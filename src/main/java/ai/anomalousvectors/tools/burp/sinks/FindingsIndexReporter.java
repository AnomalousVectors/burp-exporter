package ai.anomalousvectors.tools.burp.sinks;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.ScopeFilter;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.concurrent.LazyScheduler;
import ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotExportEngine;
import ai.anomalousvectors.tools.burp.utils.concurrent.StartupSnapshotCoordinator;
import ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotPacing;
import ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotScopeCache;
import ai.anomalousvectors.tools.burp.utils.opensearch.BatchSizeController;
import ai.anomalousvectors.tools.burp.utils.opensearch.BulkByteBudget;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.DnsDetails;
import burp.api.montoya.collaborator.HttpDetails;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.SmtpDetails;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

/**
 * Pushes Burp Scanner audit issues to the {@code findings} index when export is running and
 * {@code findings} is selected.
 *
 * <p>Initial push on Start exports the backlog in cooperative slices so Sitemap / Proxy History /
 * WebSocket startup steps can interleave on {@link StartupSnapshotCoordinator} while
 * {@link SnapshotExportEngine} still runs one heavy prepare/flush at a time. Every 30 seconds
 * exports only issues whose {@link SnapshotExportFingerprints#findingItemKey} was not yet seen this
 * run. Severity filtering uses {@link FindingsSeverityFilter}: {@code FALSE_POSITIVE} and
 * {@code null} severities never export and are reported as backlog {@code skipped_non_exportable};
 * configured tokens (for example {@code informational}) gate the rest and increment
 * {@code skipped_severity} when excluded by operator selection.</p>
 *
 * <p>Does not start a new run while the previous push is still in progress.</p>
 */
public final class FindingsIndexReporter {

    private static final int INTERVAL_SECONDS = 30;
    private static final String SCHEMA_VERSION = "1";
    private static final String REPORTING_TOOL = "Scanner";

    /**
     * Single-owner scheduler for periodic findings polling.
     *
     * <p>Startup backlog slices run through {@link StartupSnapshotCoordinator}. This scheduler is
     * created only for recurring polling and is torn down by {@link #stop()} during UI stop or
     * extension unload.</p>
     */
    private static final LazyScheduler SCHEDULER =
            new LazyScheduler("burp-exporter-findings-reporter");
    private static final PeriodicExportSeenKeys PERIODIC_EXPORT_SEEN_KEYS =
            new PeriodicExportSeenKeys();
    private static final AtomicBoolean issuesAccessFailureLogged = new AtomicBoolean();
    private static final Object STARTUP_BACKLOG_LOCK = new Object();
    private static volatile StartupBacklogState startupBacklog;
    private static volatile boolean runInProgress;
    private static volatile boolean periodicPollingRequested;
    private static volatile boolean startupSnapshotFinished;

    private FindingsIndexReporter() {}

    private static String findingsIndexName() {
        return RuntimeConfig.indexNameForKey("findings");
    }

    /**
     * Queues startup export of current Burp Scanner audit issues (for example on Start).
     *
     * <p>Safe to call from any thread. No-op when export is stopped, no sink is enabled, or
     * findings is not selected. Applies {@link FindingsSeverityFilter}, records
     * {@code skipped_non_exportable} for issues Burp will not export, and records
     * {@code skipped_severity} when operator severity selection excludes an issue.</p>
     *
     * <p>Captures the issue list once, then uses the shared adaptive
     * {@link StartupSnapshotCoordinator} item allowance so Sitemap, Proxy History, and WebSocket
     * can run between slices.</p>
     */
    public static void pushSnapshotNow() {
        try {
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            if (!RuntimeConfig.isAnySinkEnabled()) {
                return;
            }
            if (!RuntimeConfig.isDataSourceEnabled(ConfigKeys.SRC_FINDINGS)) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null) {
                return;
            }
            ExportRunToken token = RuntimeConfig.currentExportRunToken();
            // Ordered with other startup snapshots; slices re-submit so Sitemap/Proxy can interleave.
            StartupSnapshotCoordinator.submit(
                    StartupSnapshotCoordinator.Lane.FINDINGS,
                    token,
                    "Findings",
                    () -> runStartupBacklogSlice(api, token));
        } catch (RuntimeException e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logWarnPanelOnly("[SnapshotExport] Findings: push failed: " + msg);
        }
    }

    /**
     * Requests 30-second periodic polling after the startup snapshot finishes.
     *
     * <p>Does not perform an initial push; callers must call {@link #pushSnapshotNow()} once on
     * Start. Safe to call from any thread.</p>
     */
    public static void start() {
        periodicPollingRequested = true;
        startPeriodicIfReady();
    }

    private static void startPeriodicIfReady() {
        if (!periodicPollingRequested || !startupSnapshotFinished) {
            return;
        }
        ExportRunToken token = RuntimeConfig.currentExportRunToken();
        SCHEDULER.startRecurring(
                () -> {
                    if (RuntimeConfig.isExportRunActive(token)) {
                        pushNewIssuesOnly();
                    }
                },
                INTERVAL_SECONDS,
                INTERVAL_SECONDS,
                TimeUnit.SECONDS);
    }

    /**
     * Stops the periodic scheduler and clears per-session reporter state.
     *
     * <p>Safe to call from any thread. The next {@link #start()} call creates a fresh scheduler.</p>
     */
    public static void stop() {
        SCHEDULER.stop();
        issuesAccessFailureLogged.set(false);
        runInProgress = false;
        periodicPollingRequested = false;
        startupSnapshotFinished = false;
        clearStartupBacklog();
        PERIODIC_EXPORT_SEEN_KEYS.clear();
    }

    static void pushNewIssuesOnly() {
        try {
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            if (!RuntimeConfig.isAnySinkEnabled()) {
                return;
            }
            if (!RuntimeConfig.isDataSourceEnabled(ConfigKeys.SRC_FINDINGS)) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null) {
                return;
            }
            pushIssues(api, false);
        } catch (RuntimeException e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logWarnPanelOnly("[PeriodicExport] Findings: push failed: " + msg);
        }
    }

    private static void pushIssues(MontoyaApi api, boolean pushAll) {
        if (runInProgress) {
            return;
        }
        runInProgress = true;
        try {
            List<AuditIssue> issues = safeIssues(api);
            if (issues == null) {
                return;
            }
            var state = RuntimeConfig.getState();
            var severities = state.findingsSeverities();
            boolean filterBySeverity = severities != null && !severities.isEmpty();
            Set<String> selectedSeverities = filterBySeverity ? Set.copyOf(severities) : Set.of();
            if (pushAll) {
                // Legacy full-list path kept for direct tests; Start uses sliced coordinator path.
                pushAllIssuesParallel(api, issues, state, filterBySeverity, selectedSeverities);
            } else {
                pushIncrementalIssues(api, issues, state, filterBySeverity, selectedSeverities);
            }
        } finally {
            runInProgress = false;
        }
    }

    private record FindingWorkItem(AuditIssue issue, boolean burpInScope) {
    }

    /**
     * One cooperative Findings startup slice on the startup coordinator thread.
     *
     * <p>Captures the Burp issue list once, exports one shared adaptive allowance through
     * {@link SnapshotExportEngine}, then re-queues a continuation so Sitemap / Proxy History can
     * run before the next Findings slice. Marks startup finished only after the last slice.</p>
     */
    private static void runStartupBacklogSlice(MontoyaApi api, ExportRunToken token) {
        if (!RuntimeConfig.isExportRunActive(token)) {
            finishStartupBacklog(false);
            return;
        }
        StartupBacklogState state;
        List<AuditIssue> slice;
        int sliceStart;
        synchronized (STARTUP_BACKLOG_LOCK) {
            state = startupBacklog;
            if (state == null) {
                List<AuditIssue> issues = safeIssues(api);
                if (issues == null) {
                    finishStartupBacklogLocked(false);
                    return;
                }
                var config = RuntimeConfig.getState();
                var severities = config.findingsSeverities();
                boolean filterBySeverity = severities != null && !severities.isEmpty();
                // Preserve null AuditIssue slots (counted as skipped_non_exportable);
                // List.copyOf forbids nulls.
                state = new StartupBacklogState(
                        Collections.unmodifiableList(new ArrayList<>(issues)),
                        config,
                        filterBySeverity,
                        filterBySeverity ? Set.copyOf(severities) : Set.of(),
                        new SnapshotScopeCache(api),
                        SnapshotSummary.forIndexKey("findings"),
                        token);
                startupBacklog = state;
                Logger.logInfoPanelOnly("[StartupExport] Findings: exporting backlog: "
                        + state.issues.size() + " issue(s) with adaptive startup slices.");
                SnapshotPacing.resetCountersForSnapshot();
            }
            if (state.offset >= state.issues.size()) {
                finishStartupBacklogLocked(true);
                return;
            }
            int sliceTarget = StartupSnapshotCoordinator.nextSliceItemCount(
                    StartupSnapshotCoordinator.Lane.FINDINGS);
            sliceStart = state.offset;
            int end = Math.min(state.offset + sliceTarget, state.issues.size());
            slice = state.issues.subList(state.offset, end);
        }

        if (runInProgress) {
            // Another Findings push is active; re-queue so we do not drop the remainder.
            StartupSnapshotCoordinator.submit(
                    StartupSnapshotCoordinator.Lane.FINDINGS,
                    token,
                    "Findings",
                    () -> runStartupBacklogSlice(api, token));
            return;
        }
        runInProgress = true;
        SnapshotExportEngine.Result result;
        long sliceStartedNanos = System.nanoTime();
        try {
            result = exportStartupSlice(state, slice);
        } catch (RuntimeException e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logWarnPanelOnly("[SnapshotExport] Findings: push failed: " + msg);
            finishStartupBacklog(true);
            return;
        } finally {
            runInProgress = false;
        }

        boolean more;
        synchronized (STARTUP_BACKLOG_LOCK) {
            if (startupBacklog != state) {
                return;
            }
            state.offset += slice.size();
            more = state.offset < state.issues.size() && RuntimeConfig.isExportRunActive(token);
            if (!more) {
                finishStartupBacklogLocked(true);
            }
        }
        long elapsedMs = (System.nanoTime() - sliceStartedNanos) / 1_000_000L;
        StartupSnapshotCoordinator.recordSliceOutcome(
                StartupSnapshotCoordinator.Lane.FINDINGS,
                "Findings",
                sliceStart,
                slice.size(),
                result.totalChunkBytes(),
                elapsedMs,
                more);
        if (more) {
            StartupSnapshotCoordinator.submit(
                    StartupSnapshotCoordinator.Lane.FINDINGS,
                    token,
                    "Findings",
                    () -> runStartupBacklogSlice(api, token));
        }
    }

    private static SnapshotExportEngine.Result exportStartupSlice(
            StartupBacklogState state,
            List<AuditIssue> slice) {
        boolean openSearchActive = RuntimeConfig.isSearchActive();
        String indexName = findingsIndexName();
        String activeBaseUrl = RuntimeConfig.searchBaseUrl();
        int batchSize = SnapshotBatchTuning.initialTarget();
        int buildWorkers = SnapshotExportEngine.defaultBuildWorkers();

        SnapshotExportEngine.Result exportResult = SnapshotExportEngine.run(
                state.token,
                slice,
                buildWorkers,
                BulkByteBudget.currentMaxBytes(),
                batchSize,
                SnapshotBatchTuning::applyLiveBackpressure,
                SnapshotBatchTuning.chunkTargetAdjuster(),
                activeBaseUrl,
                indexName,
                "findings",
                issue -> {
                    FindingWorkItem work = toStartupWorkItem(
                            issue,
                            state.config,
                            state.scopeCache,
                            state.filterBySeverity,
                            state.selectedSeverities,
                            state.processed,
                            state.skippedNonExportable,
                            state.skippedSeverity,
                            state.skippedScope);
                    if (work == null) {
                        return null;
                    }
                    Map<String, Object> doc = buildFindingDoc(work.issue(), work.burpInScope());
                    if (doc == null) {
                        return null;
                    }
                    return ExportDocumentIdentity.prepare(indexName, "findings", doc);
                },
                (chunk, outcome, nextChunkTarget) ->
                        BulkOutcomeRecorder.record(
                                "findings", "Findings", "Bulk push", outcome, openSearchActive));
        state.addEngineResult(exportResult);
        return exportResult;
    }

    /**
     * Acquires the startup lock and completes or abandons the current backlog.
     */
    private static void finishStartupBacklog(boolean logSummary) {
        synchronized (STARTUP_BACKLOG_LOCK) {
            finishStartupBacklogLocked(logSummary);
        }
    }

    /**
     * Finalizes startup state while {@link #STARTUP_BACKLOG_LOCK} is held.
     *
     * <p>Only an active run may publish summary counters or enable periodic polling.</p>
     */
    private static void finishStartupBacklogLocked(boolean logSummary) {
        StartupBacklogState state = startupBacklog;
        startupBacklog = null;
        if (logSummary && state != null && RuntimeConfig.isExportRunActive(state.token)) {
            long durationMs = (System.nanoTime() - state.startNs) / 1_000_000L;
            boolean openSearchActive = RuntimeConfig.isSearchActive();
            boolean fileActive = RuntimeConfig.isAnyFileExportEnabled();
            ExportStats.recordSnapshotLastRun(
                    ExportStats.SNAPSHOT_FINDINGS,
                    state.attempted,
                    state.success,
                    durationMs,
                    state.finalChunkTarget,
                    state.chunks,
                    state.totalChunkBytes,
                    state.buildWallMs,
                    state.buildCpuMs,
                    state.flushMs,
                    state.fileFlushMs,
                    state.openSearchFlushMs,
                    state.buildWorkers);
            SnapshotSummary.logInfo(
                    "Findings",
                    state.baseline,
                    state.attempted,
                    durationMs,
                    state.buildWallMs,
                    state.flushMs,
                    openSearchActive,
                    fileActive);
            Logger.logInfoPanelOnly("[SnapshotExport] Findings: backlog filters: seen=" + state.issues.size()
                    + " exported=" + state.attempted
                    + " skipped_scope=" + state.skippedScope.get()
                    + " skipped_severity=" + state.skippedSeverity.get()
                    + " skipped_non_exportable=" + state.skippedNonExportable.get()
                    + " in " + durationMs + "ms.");
        }
        if (state != null && RuntimeConfig.isExportRunActive(state.token)) {
            startupSnapshotFinished = true;
            startPeriodicIfReady();
        }
    }

    private static void clearStartupBacklog() {
        synchronized (STARTUP_BACKLOG_LOCK) {
            startupBacklog = null;
        }
    }

    /**
     * Mutable aggregate owned by the serialized Findings coordinator lane.
     *
     * <p>Offset and lifecycle transitions are guarded by {@link #STARTUP_BACKLOG_LOCK}; result
     * accumulation occurs on the lane owner before the next slice is submitted.</p>
     */
    private static final class StartupBacklogState {
        private final List<AuditIssue> issues;
        private final ConfigState.State config;
        private final boolean filterBySeverity;
        private final Set<String> selectedSeverities;
        private final SnapshotScopeCache scopeCache;
        private final SnapshotSummary.Baseline baseline;
        private final ExportRunToken token;
        private final AtomicInteger processed = new AtomicInteger();
        private final AtomicInteger skippedNonExportable = new AtomicInteger();
        private final AtomicInteger skippedSeverity = new AtomicInteger();
        private final AtomicInteger skippedScope = new AtomicInteger();
        private final long startNs = System.nanoTime();
        private int offset;
        private int attempted;
        private int success;
        private int chunks;
        private long totalChunkBytes;
        private long buildWallMs;
        private long buildCpuMs;
        private long flushMs;
        private long fileFlushMs;
        private long openSearchFlushMs;
        private int finalChunkTarget;
        private int buildWorkers;

        private StartupBacklogState(
                List<AuditIssue> issues,
                ConfigState.State config,
                boolean filterBySeverity,
                Set<String> selectedSeverities,
                SnapshotScopeCache scopeCache,
                SnapshotSummary.Baseline baseline,
                ExportRunToken token) {
            this.issues = issues;
            this.config = config;
            this.filterBySeverity = filterBySeverity;
            this.selectedSeverities = selectedSeverities;
            this.scopeCache = scopeCache;
            this.baseline = baseline;
            this.token = token;
        }

        private void addEngineResult(SnapshotExportEngine.Result exportResult) {
            attempted += exportResult.attempted();
            success += exportResult.success();
            chunks += exportResult.chunks();
            totalChunkBytes += exportResult.totalChunkBytes();
            buildWallMs += exportResult.buildWallMs();
            buildCpuMs += exportResult.buildCpuMs();
            flushMs += exportResult.flushMs();
            fileFlushMs += exportResult.fileFlushMs();
            openSearchFlushMs += exportResult.openSearchFlushMs();
            finalChunkTarget = exportResult.finalChunkTarget();
            buildWorkers = exportResult.buildWorkers();
        }
    }

    private static void pushAllIssuesParallel(
            MontoyaApi api,
            List<AuditIssue> issues,
            ConfigState.State state,
            boolean filterBySeverity,
            Set<String> selectedSeverities) {
        SnapshotScopeCache scopeCache = new SnapshotScopeCache(api);
        AtomicInteger processed = new AtomicInteger();
        AtomicInteger skippedNonExportable = new AtomicInteger();
        AtomicInteger skippedSeverity = new AtomicInteger();
        AtomicInteger skippedScope = new AtomicInteger();
        SnapshotSummary.Baseline baseline = SnapshotSummary.forIndexKey("findings");
        boolean openSearchActive = RuntimeConfig.isSearchActive();
        boolean fileActive = RuntimeConfig.isAnyFileExportEnabled();
        long startNs = System.nanoTime();
        String indexName = findingsIndexName();
        String activeBaseUrl = RuntimeConfig.searchBaseUrl();
        int batchSize = SnapshotBatchTuning.initialTarget();
        int buildWorkers = SnapshotExportEngine.defaultBuildWorkers();
        Logger.logInfoPanelOnly("[StartupExport] Findings: exporting backlog: " + issues.size() + " issue(s).");
        SnapshotPacing.resetCountersForSnapshot();

        SnapshotExportEngine.Result exportResult = SnapshotExportEngine.run(
                issues,
                buildWorkers,
                BulkByteBudget.currentMaxBytes(),
                batchSize,
                SnapshotBatchTuning::applyLiveBackpressure,
                SnapshotBatchTuning.chunkTargetAdjuster(),
                activeBaseUrl,
                indexName,
                "findings",
                issue -> {
                    FindingWorkItem work = toStartupWorkItem(
                            issue,
                            state,
                            scopeCache,
                            filterBySeverity,
                            selectedSeverities,
                            processed,
                            skippedNonExportable,
                            skippedSeverity,
                            skippedScope);
                    if (work == null) {
                        return null;
                    }
                    Map<String, Object> doc = buildFindingDoc(work.issue(), work.burpInScope());
                    if (doc == null) {
                        return null;
                    }
                    return ExportDocumentIdentity.prepare(indexName, "findings", doc);
                },
                (chunk, outcome, nextChunkTarget) ->
                        BulkOutcomeRecorder.record(
                                "findings", "Findings", "Bulk push", outcome, openSearchActive));

        long durationMs = (System.nanoTime() - startNs) / 1_000_000L;
        ExportStats.recordSnapshotLastRun(
                ExportStats.SNAPSHOT_FINDINGS,
                exportResult.attempted(),
                exportResult.success(),
                durationMs,
                exportResult.finalChunkTarget(),
                exportResult.chunks(),
                exportResult.totalChunkBytes(),
                exportResult.buildWallMs(),
                exportResult.buildCpuMs(),
                exportResult.flushMs(),
                exportResult.fileFlushMs(),
                exportResult.openSearchFlushMs(),
                exportResult.buildWorkers());
        SnapshotSummary.logInfo(
                "Findings",
                baseline,
                exportResult.attempted(),
                durationMs,
                exportResult.buildWallMs(),
                exportResult.flushMs(),
                openSearchActive,
                fileActive);
        Logger.logInfoPanelOnly("[SnapshotExport] Findings: backlog filters: seen=" + issues.size()
                + " exported=" + exportResult.attempted()
                + " skipped_scope=" + skippedScope.get()
                + " skipped_severity=" + skippedSeverity.get()
                + " skipped_non_exportable=" + skippedNonExportable.get()
                + " in " + durationMs + "ms.");
    }

    private static FindingWorkItem toStartupWorkItem(
            AuditIssue issue,
            ConfigState.State state,
            SnapshotScopeCache scopeCache,
            boolean filterBySeverity,
            Set<String> selectedSeverities,
            AtomicInteger processed,
            AtomicInteger skippedNonExportable,
            AtomicInteger skippedSeverity,
            AtomicInteger skippedScope) {
        SnapshotPacing.paceItem(processed.getAndIncrement());
        if (issue == null) {
            skippedNonExportable.incrementAndGet();
            return null;
        }
        AuditIssueSeverity sev = issue.severity();
        if (FindingsSeverityFilter.isOperatorExcluded(sev)) {
            skippedNonExportable.incrementAndGet();
            return null;
        }
        if (FindingsSeverityFilter.countsTowardSkippedSeverity(sev, filterBySeverity, selectedSeverities)) {
            skippedSeverity.incrementAndGet();
            return null;
        }
        if (!FindingsSeverityFilter.shouldExport(sev, filterBySeverity, selectedSeverities)) {
            return null;
        }
        String issueUrl = issue.baseUrl() != null ? issue.baseUrl() : "";
        boolean burpInScope = scopeCache.isInScope(issueUrl);
        if (!ScopeFilter.shouldExport(state, issueUrl, burpInScope)) {
            skippedScope.incrementAndGet();
            return null;
        }
        PERIODIC_EXPORT_SEEN_KEYS.recordSeen(SnapshotExportFingerprints.findingItemKey(issue));
        return new FindingWorkItem(issue, burpInScope);
    }

    private static void pushIncrementalIssues(
            MontoyaApi api,
            List<AuditIssue> issues,
            ConfigState.State state,
            boolean filterBySeverity,
            Set<String> selectedSeverities) {
        int batchSize = BatchSizeController.getInstance().getCurrentBatchSize();
        List<PreparedExportDocument> batchDocs = new ArrayList<>(batchSize);
        long runningBatchBytes = 0;
        int checked = 0;
        int exported = 0;

        for (AuditIssue issue : issues) {
            if (!RuntimeConfig.isExportRunning()) {
                break;
            }
            AuditIssueSeverity sev = issue.severity();
            if (!FindingsSeverityFilter.shouldExport(sev, filterBySeverity, selectedSeverities)) {
                continue;
            }
            String issueUrl = issue.baseUrl() != null ? issue.baseUrl() : "";
            boolean burpInScope = safeBurpInScope(api, issueUrl);
            if (!ScopeFilter.shouldExport(state, issueUrl, burpInScope)) {
                continue;
            }
            checked++;
            String itemKey = SnapshotExportFingerprints.findingItemKey(issue);
            if (!PERIODIC_EXPORT_SEEN_KEYS.isNew(itemKey)) {
                continue;
            }
            Map<String, Object> doc = buildFindingDoc(issue, burpInScope);
            if (doc == null) {
                continue;
            }
            PreparedExportDocument prepared = ExportDocumentIdentity.prepare(findingsIndexName(), "findings", doc);
            if (!PERIODIC_EXPORT_SEEN_KEYS.claimNew(itemKey)) {
                continue;
            }
            batchDocs.add(prepared);
            runningBatchBytes += prepared.estimatedBulkBytes();
            exported++;

            if (batchDocs.size() >= batchSize || runningBatchBytes >= BulkByteBudget.currentMaxBytes()) {
                flushPreparedBatch(batchDocs);
                batchDocs.clear();
                runningBatchBytes = 0;
            }
        }
        if (RuntimeConfig.isExportRunning() && !batchDocs.isEmpty()) {
            flushPreparedBatch(batchDocs);
        }
        logPeriodicExportSummary(checked, exported);
    }

    private static void logPeriodicExportSummary(int checked, int exported) {
        if (checked <= 0) {
            return;
        }
        if (exported > 0) {
            Logger.logInfoPanelOnly("[PeriodicExport] Findings: " + exported
                    + " new issue(s); " + checked + " in-scope checked.");
            return;
        }
        Logger.logDebug("[PeriodicExport] Findings: no new issues; " + checked + " in-scope checked.");
    }

    /** Returns current Burp issues, tolerating transient lifecycle nulls. */
    private static List<AuditIssue> safeIssues(MontoyaApi api) {
        try {
            if (api == null) {
                return null;
            }
            var siteMap = api.siteMap();
            if (siteMap == null) {
                return null;
            }
            return siteMap.issues();
        } catch (Throwable t) {
            logIssuesAccessFailureOnce(t);
            return null;
        }
    }

    private static void logIssuesAccessFailureOnce(Throwable t) {
        if (!issuesAccessFailureLogged.compareAndSet(false, true)) {
            return;
        }
        String msg = t != null && t.getMessage() != null ? t.getMessage() : t != null ? t.getClass().getSimpleName() : "unknown error";
        Logger.logDebug("[SnapshotExport] Findings: siteMap().issues() unavailable; skipping export until access succeeds: "
                + msg);
    }

    private static boolean safeBurpInScope(MontoyaApi api, String url) {
        if (url == null) {
            return false;
        }
        try {
            if (api == null) {
                return false;
            }
            var scope = api.scope();
            return scope != null && scope.isInScope(url);
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static void flushPreparedBatch(List<PreparedExportDocument> batchDocs) {
        String activeBaseUrl = RuntimeConfig.searchBaseUrl();
        boolean openSearchActive = RuntimeConfig.isSearchActive();
        String indexName = findingsIndexName();
        var outcome = OpenSearchClientWrapper.pushPreparedBulk(activeBaseUrl, indexName, "findings", batchDocs);
        BulkOutcomeRecorder.record("findings", "Findings", "Bulk push", outcome, openSearchActive);
    }

    /**
     * Builds a findings document for {@code issue} with {@code burp.in_scope=false}.
     *
     * <p>Package-visible for integration tests and partial-field OpenSearch ITs.</p>
     *
     * @param issue Montoya audit issue
     * @return document map before field filtering and bulk prepare
     */
    static Map<String, Object> buildFindingDoc(AuditIssue issue) {
        return buildFindingDoc(issue, false);
    }

    private static Map<String, Object> buildFindingDoc(
            AuditIssue issue,
            boolean burpInScope) {
        Map<String, Object> doc = new LinkedHashMap<>();
        HttpService svc = issue.httpService();
        doc.put("burp", buildRootBurpDoc(burpInScope));
        doc.put("issue", buildIssueDoc(issue));
        doc.put("target", buildTargetDoc(issue, svc));

        List<HttpRequestResponse> reqResList = issue.requestResponses();
        boolean missingReqRes = reqResList == null || reqResList.isEmpty();
        List<Map<String, Object>> requestResponsesList = new ArrayList<>();
        if (!missingReqRes && reqResList != null) {
            for (HttpRequestResponse rr : reqResList) {
                if (rr == null) {
                    continue;
                }
                HttpRequest req = rr.request();
                if (req == null) {
                    continue;
                }
                HttpResponse resp = rr.hasResponse() ? rr.response() : null;
                HttpService pairService = pairHttpService(rr, svc);
                Map<String, Object> reqDoc = RequestResponseDocBuilder.buildTrafficRequestDoc(req);
                putPairRequestServiceFields(reqDoc, req, pairService);
                Map<String, Object> respDoc = resp != null
                        ? RequestResponseDocBuilder.buildTrafficResponseDoc(resp)
                        : emptyTrafficResponseDoc();
                // Scanner-attached pair-level markers (issue evidence) take precedence over the
                // per-message marker slots filled by RequestResponseDocBuilder, since for
                // scanner-produced findings the per-message markers are essentially always empty
                // and the evidence highlights live on the HttpRequestResponse pair itself.
                TrafficPairMarkers.overlayPairMarkers(reqDoc, respDoc, rr);
                Map<String, Object> pair = new LinkedHashMap<>();
                pair.put("burp", buildPairBurpDoc(rr));
                pair.put("request", reqDoc);
                pair.put("response", respDoc);
                requestResponsesList.add(pair);
            }
        }
        doc.put("requests_responses", requestResponsesList);
        doc.put("collaborator", buildCollaboratorInteractionsList(issue));

        doc.put("meta", ExportMetaFields.meta(SCHEMA_VERSION));
        return doc;
    }

    private static Map<String, Object> buildRootBurpDoc(boolean burpInScope) {
        Map<String, Object> burp = new LinkedHashMap<>();
        burp.put("is_in_scope", burpInScope);
        burp.put("reporting_tool", REPORTING_TOOL);
        return burp;
    }

    private static Map<String, Object> buildIssueDoc(AuditIssue issue) {
        Map<String, Object> issueDoc = new LinkedHashMap<>();
        issueDoc.put("name", nullToEmpty(issue.name()));
        AuditIssueSeverity severity = issue.severity();
        issueDoc.put("severity", severity != null ? severity.name() : "");
        AuditIssueConfidence confidence = issue.confidence();
        issueDoc.put("confidence", confidence != null ? confidence.name() : "");

        Map<String, Object> remediation = new LinkedHashMap<>();
        try {
            var def = issue.definition();
            if (def != null) {
                issueDoc.put("type_id", def.typeIndex());
                AuditIssueSeverity typical = def.typicalSeverity();
                issueDoc.put("typical_severity", typical != null ? typical.name() : "");
                issueDoc.put("background", nullToEmpty(def.background()));
                remediation.put("background", nullToEmpty(def.remediation()));
            } else {
                issueDoc.put("type_id", 0);
                issueDoc.put("typical_severity", "");
                issueDoc.put("background", "");
                remediation.put("background", "");
            }
        } catch (RuntimeException e) {
            issueDoc.put("type_id", 0);
            issueDoc.put("typical_severity", "");
            issueDoc.put("background", "");
            remediation.put("background", "");
        }

        issueDoc.put("description", nullToEmpty(issue.detail()));
        remediation.put("detail", nullToEmpty(issue.remediation()));
        issueDoc.put("remediation", remediation);
        return issueDoc;
    }

    private static Map<String, Object> buildTargetDoc(AuditIssue issue, HttpService svc) {
        Map<String, Object> target = new LinkedHashMap<>();
        target.put("url", nullToEmpty(issue.baseUrl()));
        target.put("host", svc != null ? svc.host() : "");
        target.put("port", svc != null ? svc.port() : 0);

        Map<String, Object> protocol = new LinkedHashMap<>();
        protocol.put("scheme", svc != null ? (svc.secure() ? "https" : "http") : "");
        target.put("protocol", protocol);
        return target;
    }

    private static void putPairRequestServiceFields(
            Map<String, Object> reqDoc, HttpRequest request, HttpService service) {
        if (reqDoc == null) {
            return;
        }
        String url = RequestResponseDocBuilder.buildBestEffortUrl(request, service, reqDoc, "Findings");
        reqDoc.put("url", HttpMessageDocSupport.urlObject(nullToEmpty(url), service));
        reqDoc.put("protocol", TrafficProtocolFields.requestProtocol(
                RequestResponseDocBuilder.safeRequestHttpVersion(request)));
    }

    private static HttpService pairHttpService(HttpRequestResponse rr, HttpService fallback) {
        try {
            HttpService service = rr.httpService();
            return service != null ? service : fallback;
        } catch (RuntimeException ignored) {
            return fallback;
        }
    }

    /** Builds the pair-level Burp metadata sub-document for one {@link HttpRequestResponse}. */
    private static Map<String, Object> buildPairBurpDoc(HttpRequestResponse rr) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("timing", BurpTimingFields.from(rr));
        Annotations ann = rr == null ? null : rr.annotations();
        if (ann == null) {
            m.put("notes", null);
            m.put("highlight", null);
            return m;
        }
        m.put("notes", ann.hasNotes() ? ann.notes() : null);
        HighlightColor hl = ann.hasHighlightColor() ? ann.highlightColor() : null;
        m.put("highlight", hl != null ? hl.name() : null);
        return m;
    }

    /**
     * Captures Burp Collaborator interactions associated with the issue, including the
     * forensic-preserving raw HTTP request/response bytes for HTTP pingbacks.
     *
     * <p>HTTP request/response bodies for collaborator pingbacks are typically small (the
     * payload Burp Suite's mock listener returns) and base64-encoding them preserves the
     * original bytes verbatim for downstream forensic analysis without requiring the
     * findings mapping to enumerate the full HTTP document shape twice. Larger or richer
     * parsed representations can be added later if specific queries require them.</p>
     */
    private static List<Map<String, Object>> buildCollaboratorInteractionsList(AuditIssue issue) {
        List<Interaction> interactions;
        try {
            interactions = issue.collaboratorInteractions();
        } catch (RuntimeException ignored) {
            return List.of();
        }
        if (interactions == null || interactions.isEmpty()) {
            return List.of();
        }
        List<Map<String, Object>> out = new ArrayList<>(interactions.size());
        for (Interaction i : interactions) {
            if (i == null) {
                continue;
            }
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("id", i.id() != null ? i.id().toString() : null);
            entry.put("type", i.type() != null ? i.type().name() : null);
            entry.put("time", i.timeStamp() != null ? i.timeStamp().toInstant().toString() : null);
            InetAddress ip = i.clientIp();
            entry.put("client_ip", ip != null ? ip.getHostAddress() : null);
            entry.put("client_port", i.clientPort());

            Map<String, Object> dns = new LinkedHashMap<>();
            Optional<DnsDetails> dnsOpt = i.dnsDetails();
            if (dnsOpt.isPresent()) {
                DnsDetails d = dnsOpt.get();
                dns.put("query_type", d.queryType() != null ? d.queryType().name() : null);
                ByteArray q = d.query();
                dns.put("query_b64", q != null ? Base64.getEncoder().encodeToString(q.getBytes()) : null);
            }
            entry.put("dns", dns);

            Map<String, Object> http = new LinkedHashMap<>();
            Optional<HttpDetails> httpOpt = i.httpDetails();
            if (httpOpt.isPresent()) {
                HttpDetails h = httpOpt.get();
                http.put("protocol", h.protocol() != null ? h.protocol().name() : null);
                HttpRequestResponse hrr = h.requestResponse();
                if (hrr != null) {
                    Map<String, Object> requestDoc = null;
                    Map<String, Object> responseDoc;
                    HttpRequest hreq = hrr.request();
                    if (hreq != null) {
                        ByteArray bytes = hreq.toByteArray();
                        http.put("request_b64", bytes != null ? Base64.getEncoder().encodeToString(bytes.getBytes()) : null);
                        requestDoc = RequestResponseDocBuilder.buildTrafficRequestDoc(hreq);
                        putPairRequestServiceFields(requestDoc, hreq, pairHttpService(hrr, null));
                    }
                    HttpResponse hresp = hrr.hasResponse() ? hrr.response() : null;
                    if (hresp != null) {
                        ByteArray bytes = hresp.toByteArray();
                        http.put("response_b64", bytes != null ? Base64.getEncoder().encodeToString(bytes.getBytes()) : null);
                        responseDoc = RequestResponseDocBuilder.buildTrafficResponseDoc(hresp);
                    } else {
                        responseDoc = emptyTrafficResponseDoc();
                    }
                    TrafficPairMarkers.overlayPairMarkers(requestDoc, responseDoc, hrr);
                    if (requestDoc != null) {
                        http.put("request", requestDoc);
                    }
                    http.put("response", responseDoc);
                }
            }
            entry.put("http", http);

            Map<String, Object> smtp = new LinkedHashMap<>();
            Optional<SmtpDetails> smtpOpt = i.smtpDetails();
            if (smtpOpt.isPresent()) {
                SmtpDetails s = smtpOpt.get();
                smtp.put("protocol", s.protocol() != null ? s.protocol().name() : null);
                smtp.put("conversation", s.conversation());
            }
            entry.put("smtp", smtp);

            Optional<String> custom = i.customData();
            entry.put("custom_data", custom.orElse(null));
            out.add(entry);
        }
        return out;
    }

    private static Map<String, Object> emptyTrafficResponseDoc() {
        Map<String, Object> response = new LinkedHashMap<>();

        Map<String, Object> status = new LinkedHashMap<>();
        status.put("code", null);
        status.put("code_class", null);
        status.put("description", null);
        response.put("status", status);

        Map<String, Object> protocol = new LinkedHashMap<>();
        protocol.put("http_version", null);
        response.put("protocol", protocol);

        response.put("headers", List.of());
        response.put("cookies", List.of());
        response.put("mime_type", HttpMessageDocSupport.responseMimeType(List.of(), null));

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("length", 0);
        body.put("offset", 0);
        body.put("b64", null);
        body.put("text", null);
        body.put("markers", List.of());
        response.put("body", body);

        return response;
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }
}
