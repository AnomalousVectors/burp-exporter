package ai.anomalousvectors.tools.burp.sinks;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.opensearch.BatchSizeController;
import ai.anomalousvectors.tools.burp.utils.opensearch.BulkByteBudget;
import ai.anomalousvectors.tools.burp.utils.ScopeFilter;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.concurrent.LazyScheduler;
import ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotExportEngine;
import ai.anomalousvectors.tools.burp.utils.concurrent.StartupSnapshotCoordinator;
import ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotPacing;
import ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotScopeCache;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Pushes Burp sitemap items to the sitemap index when export is running and
 * "Sitemap" is selected. Initial push on Start exports every site-map row returned
 * by Montoya (background); every 30 seconds exports only in-scope rows whose
 * {@link SnapshotExportFingerprints#sitemapEntryFingerprint} was not yet seen this run.
 */
public final class SitemapIndexReporter {

    private static final int INTERVAL_SECONDS = 30;
    private static final String SCHEMA_VERSION = "1";

    /**
     * Single-owner scheduler for periodic sitemap polling.
     *
     * <p>Startup backlog slices run through {@link StartupSnapshotCoordinator}. This scheduler is
     * created only for recurring polling and is torn down by {@link #stop()} during UI stop or
     * extension unload.</p>
     */
    private static final LazyScheduler SCHEDULER =
            new LazyScheduler("burp-exporter-sitemap-reporter");
    private static final PeriodicExportSeenKeys PERIODIC_EXPORT_SEEN_KEYS =
            new PeriodicExportSeenKeys();
    private static volatile boolean runInProgress;
    private static volatile boolean periodicPollingRequested;
    private static volatile boolean startupSnapshotFinished;
    private static final Object STARTUP_BACKLOG_LOCK = new Object();
    private static volatile StartupBacklogState startupBacklog;

    private SitemapIndexReporter() {}

    private static String sitemapIndexName() {
        return RuntimeConfig.indexNameForKey("sitemap");
    }

    /**
     * Schedules one startup export of all current sitemap items.
     *
     * <p>Safe to call from any thread. Work runs in cooperative background slices through
     * {@link StartupSnapshotCoordinator}, and this method returns without waiting. No-op if export
     * is not running, no sink is enabled, or Sitemap is not selected.</p>
     */
    public static void pushSnapshotNow() {
        try {
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            if (!RuntimeConfig.isAnySinkEnabled()) {
                return;
            }
            List<String> sources = RuntimeConfig.getState().dataSources();
            if (sources == null || !sources.contains(ConfigKeys.SRC_SITEMAP)) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null) {
                return;
            }
            ExportRunToken token = RuntimeConfig.currentExportRunToken();
            // Ordered with other startup snapshots so Proxy History cannot starve Sitemap.
            StartupSnapshotCoordinator.submit(
                    StartupSnapshotCoordinator.Lane.SITEMAP,
                    token,
                    "Sitemap",
                    () -> runStartupBacklogSlice(api, token));
        } catch (RuntimeException e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logWarnPanelOnly("[SnapshotExport] Sitemap: push failed: " + msg);
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
                        pushNewItemsOnly();
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
        runInProgress = false;
        periodicPollingRequested = false;
        startupSnapshotFinished = false;
        synchronized (STARTUP_BACKLOG_LOCK) {
            startupBacklog = null;
        }
        PERIODIC_EXPORT_SEEN_KEYS.clear();
    }

    static void pushNewItemsOnly() {
        try {
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            if (!RuntimeConfig.isAnySinkEnabled()) {
                return;
            }
            List<String> sources = RuntimeConfig.getState().dataSources();
            if (sources == null || !sources.contains(ConfigKeys.SRC_SITEMAP)) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null) {
                return;
            }
            pushItems(api, false);
        } catch (RuntimeException e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logWarnPanelOnly("[PeriodicExport] Sitemap: push failed: " + msg);
        }
    }

    private record SitemapWorkItem(HttpRequestResponse item, boolean burpInScope) {
    }

    private static void pushItems(MontoyaApi api, boolean pushAll) {
        if (runInProgress) {
            return;
        }
        runInProgress = true;
        try {
            List<HttpRequestResponse> items = safeSiteMapItems(api);
            if (items == null) {
                return;
            }
            if (pushAll) {
                pushAllItemsParallel(api, items);
            } else {
                pushIncrementalItems(api, items);
            }
        } finally {
            runInProgress = false;
        }
    }

    /**
     * Runs one token-scoped Sitemap startup slice.
     *
     * <p>State selection and offset changes occur under {@link #STARTUP_BACKLOG_LOCK}; document
     * preparation and delivery run outside the lock. State identity and run activity are checked
     * again before results are committed.</p>
     */
    private static void runStartupBacklogSlice(MontoyaApi api, ExportRunToken token) {
        if (!RuntimeConfig.isExportRunActive(token)) {
            return;
        }
        StartupBacklogState state;
        List<HttpRequestResponse> slice;
        int sliceStart;
        synchronized (STARTUP_BACKLOG_LOCK) {
            state = startupBacklog;
            if (state == null) {
                List<HttpRequestResponse> items = safeSiteMapItems(api);
                if (items == null) {
                    return;
                }
                state = new StartupBacklogState(
                        Collections.unmodifiableList(new ArrayList<>(items)),
                        RuntimeConfig.getState(),
                        new SnapshotScopeCache(api),
                        SnapshotSummary.forIndexKey("sitemap"),
                        token);
                startupBacklog = state;
                Logger.logInfoPanelOnly("[StartupExport] Sitemap: exporting backlog: "
                        + items.size() + " item(s) with adaptive startup slices.");
                SnapshotPacing.resetCountersForSnapshot();
            }
            if (state.offset >= state.items.size()) {
                finishStartupBacklogLocked(state);
                return;
            }
            int sliceTarget = StartupSnapshotCoordinator.nextSliceItemCount(
                    StartupSnapshotCoordinator.Lane.SITEMAP);
            sliceStart = state.offset;
            int end = Math.min(state.offset + sliceTarget, state.items.size());
            slice = state.items.subList(state.offset, end);
        }

        long sliceStartedNanos = System.nanoTime();
        SnapshotExportEngine.Result result = exportStartupSlice(state, slice);
        long elapsedMs = (System.nanoTime() - sliceStartedNanos) / 1_000_000L;
        boolean more;
        synchronized (STARTUP_BACKLOG_LOCK) {
            if (startupBacklog != state || !RuntimeConfig.isExportRunActive(token)) {
                return;
            }
            state.add(result);
            state.offset += slice.size();
            more = state.offset < state.items.size();
            if (!more) {
                finishStartupBacklogLocked(state);
            }
        }
        StartupSnapshotCoordinator.recordSliceOutcome(
                StartupSnapshotCoordinator.Lane.SITEMAP,
                "Sitemap",
                sliceStart,
                slice.size(),
                result.totalChunkBytes(),
                elapsedMs,
                more);
        if (more) {
            StartupSnapshotCoordinator.submit(
                    StartupSnapshotCoordinator.Lane.SITEMAP,
                    token,
                    "Sitemap",
                    () -> runStartupBacklogSlice(api, token));
        }
    }

    private static SnapshotExportEngine.Result exportStartupSlice(
            StartupBacklogState state,
            List<HttpRequestResponse> slice) {
        boolean openSearchActive = RuntimeConfig.isSearchActive();
        String indexName = sitemapIndexName();
        return SnapshotExportEngine.run(
                state.token,
                slice,
                SnapshotExportEngine.defaultBuildWorkers(),
                BulkByteBudget.currentMaxBytes(),
                SnapshotBatchTuning.initialTarget(),
                SnapshotBatchTuning::applyLiveBackpressure,
                SnapshotBatchTuning.chunkTargetAdjuster(),
                RuntimeConfig.searchBaseUrl(),
                indexName,
                "sitemap",
                item -> {
                    SitemapWorkItem work = toStartupWorkItem(
                            item, state.config, state.scopeCache, state.processed, state.skippedScope);
                    return work == null ? null : prepareSitemapWorkItem(indexName, work);
                },
                (chunk, outcome, nextChunkTarget) ->
                        BulkOutcomeRecorder.record(
                                "sitemap", "Sitemap", "Bulk push", outcome, openSearchActive));
    }

    /**
     * Finalizes startup state while {@link #STARTUP_BACKLOG_LOCK} is held.
     *
     * <p>Only the active run publishes summary counters and enables periodic polling.</p>
     */
    private static void finishStartupBacklogLocked(StartupBacklogState state) {
        startupBacklog = null;
        if (!RuntimeConfig.isExportRunActive(state.token)) {
            return;
        }
        long durationMs = (System.nanoTime() - state.startNs) / 1_000_000L;
        ExportStats.recordSnapshotLastRun(
                ExportStats.SNAPSHOT_SITEMAP,
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
                "Sitemap",
                state.baseline,
                state.attempted,
                durationMs,
                state.buildWallMs,
                state.flushMs,
                RuntimeConfig.isSearchActive(),
                RuntimeConfig.isAnyFileExportEnabled());
        Logger.logInfoPanelOnly("[SnapshotExport] Sitemap: backlog filters: seen="
                + state.items.size() + " exported=" + state.attempted
                + " skipped_scope=" + state.skippedScope.get()
                + " in " + durationMs + "ms.");
        startupSnapshotFinished = true;
        startPeriodicIfReady();
    }

    /**
     * Mutable aggregate owned by the serialized Sitemap coordinator lane.
     *
     * <p>References and offsets are guarded by {@link #STARTUP_BACKLOG_LOCK}; one coordinator
     * slice at a time updates the accumulated result fields.</p>
     */
    private static final class StartupBacklogState {
        private final List<HttpRequestResponse> items;
        private final ConfigState.State config;
        private final SnapshotScopeCache scopeCache;
        private final SnapshotSummary.Baseline baseline;
        private final ExportRunToken token;
        private final AtomicInteger processed = new AtomicInteger();
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
                List<HttpRequestResponse> items,
                ConfigState.State config,
                SnapshotScopeCache scopeCache,
                SnapshotSummary.Baseline baseline,
                ExportRunToken token) {
            this.items = items;
            this.config = config;
            this.scopeCache = scopeCache;
            this.baseline = baseline;
            this.token = token;
        }

        private void add(SnapshotExportEngine.Result result) {
            attempted += result.attempted();
            success += result.success();
            chunks += result.chunks();
            totalChunkBytes += result.totalChunkBytes();
            buildWallMs += result.buildWallMs();
            buildCpuMs += result.buildCpuMs();
            flushMs += result.flushMs();
            fileFlushMs += result.fileFlushMs();
            openSearchFlushMs += result.openSearchFlushMs();
            finalChunkTarget = result.finalChunkTarget();
            buildWorkers = result.buildWorkers();
        }
    }

    private static void pushAllItemsParallel(MontoyaApi api, List<HttpRequestResponse> items) {
        var state = RuntimeConfig.getState();
        SnapshotScopeCache scopeCache = new SnapshotScopeCache(api);
        AtomicInteger processed = new AtomicInteger();
        AtomicInteger skippedScope = new AtomicInteger();
        boolean openSearchActive = RuntimeConfig.isSearchActive();
        boolean fileActive = RuntimeConfig.isAnyFileExportEnabled();
        SnapshotSummary.Baseline baseline = SnapshotSummary.forIndexKey("sitemap");
        long startNs = System.nanoTime();
        String indexName = sitemapIndexName();
        String activeBaseUrl = RuntimeConfig.searchBaseUrl();
        int batchSize = SnapshotBatchTuning.initialTarget();
        Logger.logInfoPanelOnly("[StartupExport] Sitemap: exporting backlog: " + items.size() + " item(s).");
        SnapshotPacing.resetCountersForSnapshot();

        SnapshotExportEngine.Result exportResult = SnapshotExportEngine.run(
                items,
                SnapshotExportEngine.defaultBuildWorkers(),
                BulkByteBudget.currentMaxBytes(),
                batchSize,
                SnapshotBatchTuning::applyLiveBackpressure,
                SnapshotBatchTuning.chunkTargetAdjuster(),
                activeBaseUrl,
                indexName,
                "sitemap",
                item -> {
                    SitemapWorkItem work = toStartupWorkItem(
                            item, state, scopeCache, processed, skippedScope);
                    if (work == null) {
                        return null;
                    }
                    return prepareSitemapWorkItem(indexName, work);
                },
                (chunk, outcome, nextChunkTarget) ->
                        BulkOutcomeRecorder.record(
                                "sitemap", "Sitemap", "Bulk push", outcome, openSearchActive));

        long durationMs = (System.nanoTime() - startNs) / 1_000_000L;
        ExportStats.recordSnapshotLastRun(
                ExportStats.SNAPSHOT_SITEMAP,
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
                "Sitemap",
                baseline,
                exportResult.attempted(),
                durationMs,
                exportResult.buildWallMs(),
                exportResult.flushMs(),
                openSearchActive,
                fileActive);
        Logger.logInfoPanelOnly("[SnapshotExport] Sitemap: backlog filters: seen=" + items.size()
                + " exported=" + exportResult.attempted()
                + " skipped_scope=" + skippedScope.get()
                + " in " + durationMs + "ms.");
    }

    private static SitemapWorkItem toStartupWorkItem(
            HttpRequestResponse item,
            ConfigState.State state,
            SnapshotScopeCache scopeCache,
            AtomicInteger processed,
            AtomicInteger skippedScope) {
        SnapshotPacing.paceItem(processed.getAndIncrement());
        if (item == null) {
            return null;
        }
        HttpRequest request = item.request();
        if (request == null) {
            return null;
        }
        String url = RequestResponseDocBuilder.safeRequestUrl(request, "Sitemap");
        if (url == null) {
            url = "";
        }
        boolean burpInScope = scopeCache.isInScope(url);
        if (!ScopeFilter.shouldExport(state, url, burpInScope)) {
            skippedScope.incrementAndGet();
            return null;
        }
        PERIODIC_EXPORT_SEEN_KEYS.recordSeen(SnapshotExportFingerprints.sitemapEntryFingerprint(item));
        return new SitemapWorkItem(item, burpInScope);
    }

    private static PreparedExportDocument prepareSitemapWorkItem(String indexName, SitemapWorkItem work) {
        Map<String, Object> doc = buildSitemapDoc(work.item(), work.burpInScope());
        if (doc == null) {
            return null;
        }
        return ExportDocumentIdentity.prepare(indexName, "sitemap", doc);
    }

    private static void pushIncrementalItems(MontoyaApi api, List<HttpRequestResponse> items) {
        var state = RuntimeConfig.getState();
        SnapshotScopeCache scopeCache = new SnapshotScopeCache(api);
        int batchTarget = BatchSizeController.getInstance().getCurrentBatchSize();
        List<PreparedExportDocument> batchDocs = new ArrayList<>(batchTarget);
        long runningBatchBytes = 0;
        String indexName = sitemapIndexName();
        int processed = 0;
        int checked = 0;
        int exported = 0;

        for (HttpRequestResponse item : items) {
            if (!RuntimeConfig.isExportRunning()) {
                break;
            }
            SnapshotPacing.paceItem(processed);
            processed++;
            SitemapWorkItem work = toWorkItem(item, state, scopeCache);
            if (work == null) {
                continue;
            }
            checked++;
            String itemKey = SnapshotExportFingerprints.sitemapEntryFingerprint(work.item());
            if (!PERIODIC_EXPORT_SEEN_KEYS.isNew(itemKey)) {
                continue;
            }
            Map<String, Object> doc = buildSitemapDoc(work.item(), work.burpInScope());
            if (doc == null) {
                continue;
            }
            PreparedExportDocument prepared = ExportDocumentIdentity.prepare(indexName, "sitemap", doc);
            if (!PERIODIC_EXPORT_SEEN_KEYS.claimNew(itemKey)) {
                continue;
            }
            batchDocs.add(prepared);
            runningBatchBytes += prepared.estimatedBulkBytes();
            exported++;

            if (batchDocs.size() >= batchTarget || runningBatchBytes >= BulkByteBudget.currentMaxBytes()) {
                flushBatch(batchDocs);
                batchDocs.clear();
                runningBatchBytes = 0;
            }
        }
        if (RuntimeConfig.isExportRunning() && !batchDocs.isEmpty()) {
            flushBatch(batchDocs);
        }
        logPeriodicExportSummary(checked, exported);
    }

    private static void logPeriodicExportSummary(int checked, int exported) {
        if (checked <= 0) {
            return;
        }
        if (exported > 0) {
            Logger.logInfoPanelOnly("[PeriodicExport] Sitemap: " + exported
                    + " new item(s); " + checked + " in-scope checked.");
            return;
        }
        Logger.logDebug("[PeriodicExport] Sitemap: no new items; " + checked + " in-scope checked.");
    }

    private static SitemapWorkItem toWorkItem(
            HttpRequestResponse item,
            ConfigState.State state,
            SnapshotScopeCache scopeCache) {
        HttpRequest request = item.request();
        if (request == null) {
            return null;
        }
        String url = RequestResponseDocBuilder.safeRequestUrl(request, "Sitemap");
        if (url == null) {
            url = "";
        }
        boolean burpInScope = scopeCache.isInScope(url);
        if (!ScopeFilter.shouldExport(state, url, burpInScope)) {
            return null;
        }
        return new SitemapWorkItem(item, burpInScope);
    }

    /** Returns sitemap request/response items, tolerating transient Burp lifecycle nulls. */
    private static List<HttpRequestResponse> safeSiteMapItems(MontoyaApi api) {
        try {
            if (api == null) {
                return null;
            }
            var siteMap = api.siteMap();
            if (siteMap == null) {
                return null;
            }
            return siteMap.requestResponses();
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static void flushBatch(List<PreparedExportDocument> batchDocs) {
        String activeBaseUrl = RuntimeConfig.searchBaseUrl();
        boolean openSearchActive = RuntimeConfig.isSearchActive();
        var outcome = OpenSearchClientWrapper.pushPreparedBulk(activeBaseUrl, sitemapIndexName(), "sitemap", batchDocs);
        BulkOutcomeRecorder.record("sitemap", "Sitemap", "Bulk push", outcome, openSearchActive);
    }

    static Map<String, Object> buildSitemapDoc(HttpRequestResponse item) {
        return buildSitemapDoc(item, false);
    }

    private static Map<String, Object> buildSitemapDoc(
            HttpRequestResponse item,
            boolean burpInScope) {
        Map<String, Object> doc = new LinkedHashMap<>();
        HttpRequest request = item.request();
        HttpService service = item.httpService();
        HttpResponse response = item.hasResponse() ? item.response() : null;

        Map<String, Object> requestDoc = request == null ? null : RequestResponseDocBuilder.buildSitemapRequestDoc(request);
        String url = request == null
                ? ""
                : nullToEmpty(RequestResponseDocBuilder.buildBestEffortUrl(request, service, requestDoc, "Sitemap"));
        doc.put("burp", buildBurpDoc(item, burpInScope));

        if (requestDoc != null) {
            requestDoc.put("url", HttpMessageDocSupport.urlObject(url, service));
            requestDoc.put("protocol", TrafficProtocolFields.requestProtocol(
                    RequestResponseDocBuilder.safeRequestHttpVersion(request)));
        }
        doc.put("request", requestDoc);
        if (response != null) {
            Map<String, Object> responseDoc = RequestResponseDocBuilder.buildTrafficResponseDoc(response);
            TrafficPairMarkers.overlayPairMarkers(requestDoc, responseDoc, item);
            doc.put("response", responseDoc);
        } else {
            TrafficPairMarkers.overlayPairMarkers(requestDoc, null, item);
            doc.put("response", null);
        }

        doc.put("meta", ExportMetaFields.meta(SCHEMA_VERSION));

        return doc;
    }

    private static Map<String, Object> buildBurpDoc(HttpRequestResponse item, boolean burpInScope) {
        Map<String, Object> burp = new LinkedHashMap<>();
        burp.put("is_in_scope", burpInScope);
        burp.put("timing", BurpTimingFields.from(item));
        putAnnotations(burp, item.annotations());
        return burp;
    }

    private static void putAnnotations(Map<String, Object> burp, Annotations annotations) {
        if (annotations == null) {
            return;
        }
        if (annotations.hasNotes()) {
            burp.put("notes", annotations.notes());
        }
        if (annotations.hasHighlightColor()) {
            HighlightColor color = annotations.highlightColor();
            burp.put("highlight", color == null ? null : color.name());
        }
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }
}
