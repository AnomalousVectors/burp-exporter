package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

import ai.anomalousvectors.tools.burp.sinks.ExportReporterLifecycle;
import ai.anomalousvectors.tools.burp.sinks.SearchRecoveryBootstrap;
import ai.anomalousvectors.tools.burp.sinks.TrafficRouteBucket;
import ai.anomalousvectors.tools.burp.utils.ControlStatusBridge;
import ai.anomalousvectors.tools.burp.utils.ExportAdmissionController;
import ai.anomalousvectors.tools.burp.utils.ExportControlBridge;
import ai.anomalousvectors.tools.burp.utils.ExportPressureLogThrottler;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.concurrent.Workers;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;
import ai.anomalousvectors.tools.burp.utils.concurrent.ExportRunContext;
import ai.anomalousvectors.tools.burp.utils.export.BulkOutcomeBreakdown;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;
import ai.anomalousvectors.tools.burp.utils.export.SearchBodyPrefixFitter;
import ai.anomalousvectors.tools.burp.utils.search.SearchConnectionStatus;
import ai.anomalousvectors.tools.burp.utils.search.SearchConnectionTester;

/**
 * Coordinates search-database retries and bounded fallback queues for failed writes.
 *
 * <p>Single-document writes make one immediate attempt and then offer the document to a retry
 * queue. Bulk writes retry with backoff before queueing only the failed items. A dedicated drain
 * thread periodically retries queued work.</p>
 *
 * <p>Thread-safe. Public push methods may block on offered-load pacing, retry backoff, and HTTP
 * completion. Lifecycle methods coordinate the background drain through an ownership lock; Stop
 * and stale-run cancellation leave current-run accounting unchanged.</p>
 */
public final class IndexingRetryCoordinator {

    /** Document-count safety rail; byte budget from {@link ExportAdmissionController} is primary. */
    private static final int MAX_QUEUE_SIZE_PER_INDEX =
            ExportAdmissionController.RETRY_DOC_SAFETY_RAIL;
    private static final int CONSECUTIVE_FAILURES_BEFORE_CHECK = 3;
    private static final int DRAIN_INTERVAL_MS_NORMAL = 5_000;
    private static final int DRAIN_INTERVAL_MS_OUTAGE = 30_000;
    private static final int BULK_RETRY_ATTEMPTS = 3;
    private static final long BACKOFF_BASE_MS = 1_000;
    private static final int BACKOFF_MULTIPLIER = 2;
    private static final int OUTAGE_LOG_THROTTLE_MS = 30_000;
    private static final long[] AUTHORIZATION_PROBE_BACKOFF_MS = {
            5_000L, 15_000L, 30_000L, 60_000L
    };

    private static final long DRAIN_SHUTDOWN_TIMEOUT_MS = 1_000;
    /**
     * Join budget for export Stop when the background drain may still be blocked on an in-flight
     * bulk HTTP call.
     *
     * <p>Stop should return quickly after the operator clicks Stop. Interrupt the drain thread and
     * wait briefly; remaining work is either finished by the short Stop retry drain or discarded as
     * Permanent Drops. Do not wait out the full classic bulk response timeout.</p>
     */
    public static final long STOP_DRAIN_THREAD_JOIN_MS = 20_000L;

    /**
     * Maximum wall time Stop spends actively retrying the OpenSearch retry queue before discarding
     * what remains.
     *
     * <p>Kept short so Stop feels responsive. Transient failures keep retrying while export is
     * running; Stop is allowed to abandon leftovers as Permanent Drops.</p>
     */
    public static final long STOP_RETRY_DRAIN_TIMEOUT_MS = 20_000L;

    private static final ExportPressureLogThrottler RETRY_PRESSURE_LOGS =
            new ExportPressureLogThrottler("OpenSearchRetry");

    /**
     * Outcome of a Stop-time retry drain attempt.
     *
     * @param attempted documents dequeued for at least one push attempt
     * @param recovered documents successfully indexed during the drain
     * @param remaining documents still queued when the drain budget ended
     */
    public record StopDrainResult(int attempted, int recovered, int remaining) {
    }

    private final RetryQueue queue;
    private final AtomicInteger consecutiveFailures = new AtomicInteger(0);
    private final AtomicBoolean outageMode = new AtomicBoolean(false);
    private final AtomicBoolean authorizationRecoveryPaused = new AtomicBoolean(false);
    private final AtomicInteger authorizationProbeAttempts = new AtomicInteger();
    private volatile long lastOutageLogTime = 0;
    private volatile long authorizationPausedAtMs;
    private volatile long nextAuthorizationProbeAtMs;
    private volatile String authorizationFailureDetail = "";
    private volatile String healthyClusterUuid = "";
    private volatile Thread drainThread;
    private volatile String lastDrainBaseUrl = "";
    private final Object drainThreadLock = new Object();
    private final AtomicReference<DrainInFlight> drainInFlight = new AtomicReference<>();
    private volatile AuthorizationProbe authorizationProbe =
            IndexingRetryCoordinator::testConnectionWithRuntimeConfig;
    private volatile RecoveryPreparer recoveryPreparer =
            SearchRecoveryBootstrap::ensureSelectedIndexes;
    private volatile SnapshotReplayer snapshotReplayer =
            SearchRecoveryBootstrap::replaySelectedSnapshots;

    @FunctionalInterface
    interface AuthorizationProbe {
        /**
         * Tests whether current runtime credentials can reach the destination.
         *
         * @param baseUrl effective destination URL
         * @return non-null connection status
         * @throws RuntimeException if probe setup cannot produce a status
         */
        SearchConnectionStatus test(String baseUrl);
    }

    @FunctionalInterface
    interface RecoveryPreparer {
        /**
         * Revalidates selected indexes after authorization returns.
         *
         * @param baseUrl effective destination URL
         * @param identityChanged whether the reachable cluster identity differs from preflight
         * @param token export run that owns the recovery attempt
         * @return non-null recovery preparation result
         */
        SearchRecoveryBootstrap.RecoveryPreparation prepare(
                String baseUrl,
                boolean identityChanged,
                ExportRunToken token);
    }

    @FunctionalInterface
    interface SnapshotReplayer {
        /**
         * Replays selected snapshots for the owning export run.
         *
         * @param token export run that owns replay
         * @return {@code true} when replay reaches its quiescent completion boundary
         */
        boolean replay(ExportRunToken token);
    }

    private record DrainInFlight(
            String indexName,
            String indexKey,
            List<PreparedExportDocument> documents) {
    }

    /**
     * Creates a coordinator with a fresh bounded retry queue.
     *
     * <p>Production code should normally use {@link #getInstance()}. This constructor remains
     * public so focused tests can create isolated coordinators.</p>
     */
    public IndexingRetryCoordinator() {
        this.queue = new RetryQueue(MAX_QUEUE_SIZE_PER_INDEX);
    }

    /**
     * Returns the shared coordinator used by production export paths.
     *
     * @return process-wide coordinator instance
     */
    public static IndexingRetryCoordinator getInstance() {
        return Holder.INSTANCE;
    }

    private static final class Holder {
        private static final IndexingRetryCoordinator INSTANCE = new IndexingRetryCoordinator();
    }

    /**
     * Pushes a single document. One attempt only (caller may be on HTTP thread).
     *
     * <p>On failure, offers to the retry queue; if the queue is full, the document is dropped and
     * this method returns {@code false}.</p>
     *
     * @param baseUrl search-database base URL
     * @param indexName target index name
     * @param document the document to index
     * @param indexKey short index key for stats (e.g. {@code "traffic"})
     * @return {@code true} if indexed successfully, {@code false} otherwise
     */
    OpenSearchClientWrapper.SingleDocPushResult pushDocumentWithResult(
            String baseUrl,
            String indexName,
            Map<String, Object> document,
            String indexKey) {
        if (document == null) {
            return new OpenSearchClientWrapper.SingleDocPushResult(false, BulkOutcomeBreakdown.empty(), null);
        }
        return pushPreparedDocumentWithResult(
                baseUrl, ExportDocumentIdentity.prepare(indexName, indexKey, document));
    }

    /**
     * Pushes one already-prepared document and queues the same prepared entry if retry is needed.
     *
     * @param baseUrl search-database base URL
     * @param document prepared document to index
     * @return structured single-document outcome
     */
    OpenSearchClientWrapper.SingleDocPushResult pushPreparedDocumentWithResult(
            String baseUrl,
            PreparedExportDocument document) {
        if (document == null) {
            return new OpenSearchClientWrapper.SingleDocPushResult(false, BulkOutcomeBreakdown.empty(), null);
        }
        ExportRunToken operationToken = RuntimeConfig.currentExportRunToken();
        if (!RuntimeConfig.isExportRunActive(operationToken)) {
            return new OpenSearchClientWrapper.SingleDocPushResult(false, BulkOutcomeBreakdown.empty(), null);
        }
        if (!ExportRunContext.allowsRunMutation()) {
            return new OpenSearchClientWrapper.SingleDocPushResult(false, BulkOutcomeBreakdown.empty(), null);
        }
        if (!RuntimeConfig.isExportReady() || !RuntimeConfig.isSearchExportEnabled()) {
            recordCurrentPermanentDrops(
                    document.indexKey(), List.of(document), "search destination not ready");
            return new OpenSearchClientWrapper.SingleDocPushResult(false, BulkOutcomeBreakdown.empty(), null);
        }
        ensureDrainThreadStarted();
        if (isAuthorizationRecoveryPaused() && !RuntimeConfig.isSearchRecoveryReplay()) {
            offerAllAccountingDrops(document.indexName(), document.indexKey(), List.of(document));
            postAuthorizationPauseStatus();
            return new OpenSearchClientWrapper.SingleDocPushResult(
                    false,
                    BulkOutcomeBreakdown.empty(),
                    "authorization_recovery_paused");
        }
        String activeBaseUrl = resolveBaseUrlForOperation(baseUrl);

        // Always attempt once; shared cooldown in PreparedBulkSender paces capacity pressure.
        // Soft outage must not skip live pushes entirely or Start-time singles (settings) stall
        // until the drain interval while export looks failed.
        OpenSearchClientWrapper.SingleDocPushResult result =
                OpenSearchClientWrapper.doPushPreparedDocument(activeBaseUrl, document);
        if (!ExportRunContext.allowsRunMutation()
                || !RuntimeConfig.isExportRunActive(operationToken)) {
            return result;
        }
        if (result.success()) {
            consecutiveFailures.set(0);
            ExportStats.recordOpenSearchSuccess();
            return result;
        }
        if (!OpenSearchPushCancellation.shouldSuppressFailureAccounting()) {
            ExportStats.recordOpenSearchFailure();
            if (BulkRateLimitBackoff.isCoolingDown()) {
                enterSoftCapacityOutageFromBulk();
            } else {
                int fails = consecutiveFailures.incrementAndGet();
                if (maybeEnterOutageMode(activeBaseUrl, fails)) {
                    recordCurrentPermanentDrops(
                            document.indexKey(), List.of(document), "search destination auto-disabled");
                    return new OpenSearchClientWrapper.SingleDocPushResult(false, BulkOutcomeBreakdown.empty(), null);
                }
            }
        }

        if (!RuntimeConfig.isExportReady()) {
            recordCurrentPermanentDrops(
                    document.indexKey(), List.of(document), "export stopped before retry enqueue");
            return new OpenSearchClientWrapper.SingleDocPushResult(false, BulkOutcomeBreakdown.empty(), null);
        }

        boolean offered = queue.offer(document.indexName(), document);
        if (!offered) {
            recordRetryQueueDrops(document.indexKey(), List.of(document));
            RETRY_PRESSURE_LOGS.record(
                    "retry_queue_full." + document.indexKey(), 1, this::retryPressureContext);
        }
        if (authorizationRecoveryPaused.get()) {
            postAuthorizationPauseStatus();
        }
        return new OpenSearchClientWrapper.SingleDocPushResult(false, BulkOutcomeBreakdown.empty(), null);
    }

    /**
     * One-shot push for Stop/unload final documents when {@link RuntimeConfig#isExportReady()} is false.
     *
     * <p>Does not enqueue retries; callers must run before {@link #stopDrainThread()} and
     * {@link OpenSearchConnector#closeAll()}.</p>
     *
     * @param baseUrl search database base URL passed by the caller
     * @param document prepared document to index
     * @return push outcome with optional root failure detail
     */
    OpenSearchClientWrapper.SingleDocPushResult pushPreparedDocumentDuringShutdown(
            String baseUrl,
            PreparedExportDocument document) {
        if (document == null) {
            return new OpenSearchClientWrapper.SingleDocPushResult(
                    false, BulkOutcomeBreakdown.empty(), "document is null");
        }
        if (!RuntimeConfig.isSearchExportEnabled()) {
            recordCurrentPermanentDrops(
                    document.indexKey(), List.of(document), "search destination disabled during shutdown");
            return new OpenSearchClientWrapper.SingleDocPushResult(
                    false, BulkOutcomeBreakdown.empty(),
                    RuntimeConfig.searchDestinationDisplayName() + " export disabled");
        }
        String activeBaseUrl = resolveBaseUrlForOperation(baseUrl);
        if (activeBaseUrl == null || activeBaseUrl.isBlank()) {
            recordCurrentPermanentDrops(
                    document.indexKey(), List.of(document), "search URL unavailable during shutdown");
            return new OpenSearchClientWrapper.SingleDocPushResult(
                    false, BulkOutcomeBreakdown.empty(), RuntimeConfig.searchDestinationDisplayName() + " URL not configured");
        }
        OpenSearchClientWrapper.SingleDocPushResult result = OpenSearchClientWrapper.doPushPreparedDocument(
                activeBaseUrl, document);
        if (result.success()) {
            consecutiveFailures.set(0);
            ExportStats.recordOpenSearchSuccess();
        } else {
            ExportStats.recordOpenSearchFailure();
            ExportStats.recordBulkBreakdown(document.indexKey(), result.breakdown());
            recordCurrentPermanentDrops(
                    document.indexKey(), List.of(document), "shutdown push failed without retry ownership");
        }
        return result;
    }

    /**
     * Pushes one document and queues it for bounded retry when the initial attempt fails.
     *
     * <p>The call may block on pacing and HTTP completion. It returns {@code false} when the
     * document is rejected, queued, dropped, cancelled, or belongs to a stale export run.</p>
     *
     * @param baseUrl destination URL; live runtime configuration takes precedence when available
     * @param indexName full target index name
     * @param document document to prepare and send; {@code null} is treated as failed
     * @param indexKey logical index key used for accounting
     * @return {@code true} only when the initial push indexes the document
     */
    public boolean pushDocument(String baseUrl, String indexName, Map<String, Object> document, String indexKey) {
        return pushDocumentWithResult(baseUrl, indexName, document, indexKey).success();
    }

    /**
     * Pushes documents in bulk. Up to 3 attempts with exponential backoff.
     *
     * <p>On partial failure, queues only the failed items. On full failure after retries, queues
     * the whole batch if within queue capacity.</p>
     *
     * @param baseUrl search-database base URL
     * @param indexName target index name
     * @param documents documents to index
     * @param indexKey short index key for stats (e.g. {@code "traffic"})
     * @return number of documents successfully indexed
     */
    public int pushBulk(String baseUrl, String indexName, List<Map<String, Object>> documents, String indexKey) {
        if (documents == null || documents.isEmpty()) {
            return 0;
        }
        List<PreparedExportDocument> prepared = new ArrayList<>(documents.size());
        for (Map<String, Object> document : documents) {
            prepared.add(ExportDocumentIdentity.prepare(indexName, indexKey, document));
        }
        return pushPreparedBulkWithResult(baseUrl, indexName, prepared, indexKey).successCount();
    }

    /**
     * Pushes prepared documents in bulk using pre-serialized NDJSON when available.
     *
     * <p>The method may block for retries and HTTP completion. Failed documents retain their
     * prepared identity when accepted by the bounded retry queue.</p>
     *
     * @param baseUrl destination URL; live runtime configuration takes precedence when available
     * @param indexName full target index name
     * @param documents prepared documents; {@code null} or empty returns zero
     * @param indexKey logical index key used for accounting and retry routing
     * @return number of documents indexed during this call
     * @see #pushBulk
     */
    public int pushPreparedBulk(
            String baseUrl,
            String indexName,
            List<PreparedExportDocument> documents,
            String indexKey) {
        return pushPreparedBulkWithResult(baseUrl, indexName, documents, indexKey).successCount();
    }

    OpenSearchClientWrapper.BulkResult pushPreparedBulkWithResult(
            String baseUrl,
            String indexName,
            List<PreparedExportDocument> documents,
            String indexKey) {
        if (documents == null || documents.isEmpty()) {
            return new OpenSearchClientWrapper.BulkResult(BulkOutcomeBreakdown.empty(), List.of());
        }
        ExportRunToken operationToken = RuntimeConfig.currentExportRunToken();
        if (!RuntimeConfig.isExportRunActive(operationToken)) {
            return transientFailureResult(documents.size(), "stale_export_run");
        }
        if (!ExportRunContext.allowsRunMutation()) {
            return transientFailureResult(documents.size(), "stale_export_run");
        }
        if (!RuntimeConfig.isExportReady() || !RuntimeConfig.isSearchExportEnabled()) {
            recordCurrentPermanentDrops(indexKey, documents, "search destination not ready");
            return transientFailureResult(documents.size(), "search_destination_not_ready");
        }
        ensureDrainThreadStarted();
        if (isAuthorizationRecoveryPaused() && !RuntimeConfig.isSearchRecoveryReplay()) {
            offerAllAccountingDrops(indexName, indexKey, documents);
            postAuthorizationPauseStatus();
            return transientFailureResult(documents.size(), "authorization_recovery_paused");
        }
        String activeBaseUrl = resolveBaseUrlForOperation(baseUrl);

        OpenSearchClientWrapper.BulkResult lastResult =
                new OpenSearchClientWrapper.BulkResult(BulkOutcomeBreakdown.empty(), List.of());
        List<PreparedExportDocument> toQueue = new ArrayList<>();
        boolean failurePartitioned = false;
        boolean inOutage = outageMode.get();
        int maxAttempts = inOutage ? 1 : BULK_RETRY_ATTEMPTS;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            OpenSearchClientWrapper.BulkResult result = OpenSearchClientWrapper.doPushPreparedBulkWithDetails(
                    activeBaseUrl, indexName, documents);
            lastResult = result;
            if (!ExportRunContext.allowsRunMutation()
                    || !RuntimeConfig.isExportRunActive(operationToken)) {
                return result;
            }
            if (isOnlyDocumentTooLargeOutcome(documents, result)) {
                // Local size gate — not destination capacity. Permanent-drop and return without
                // Soft Outage / AIMD shrink.
                consecutiveFailures.set(0);
                if (result.successCount() > 0) {
                    ExportStats.recordOpenSearchSuccess();
                    BatchSizeController.getInstance().recordSuccess(result.successCount());
                    BulkByteBudget.recordFailure();
                }
                filterTransientFailures(
                        documents, result.failedItems, result.successCount(), indexName, indexKey);
                return result;
            }
            if (result.successCount() == documents.size()) {
                consecutiveFailures.set(0);
                ExportStats.recordOpenSearchSuccess();
                BatchSizeController.getInstance().recordSuccess(result.successCount());
                noteFullPayloadBulkSuccess(
                        indexKey, result.maxSuccessfulRequestBytes());
                return result;
            }
            if (result.successCount() > 0) {
                BatchSizeController.getInstance().recordPartialSuccess(result.successCount(), documents.size());
                BulkByteBudget.recordFailure();
                consecutiveFailures.set(0);
                ExportStats.recordOpenSearchSuccess();
                toQueue = filterTransientFailures(
                        documents, result.failedItems, result.successCount(), indexName, indexKey);
                failurePartitioned = true;
                break;
            }
            // Rate-limited whole-batch failures already set a shared cooldown. Queue immediately
            // instead of stacking more prepared attempts on top of that wait.
            if (BulkRateLimitBackoff.isCoolingDown() || attempt == maxAttempts) {
                if (!OpenSearchPushCancellation.shouldSuppressFailureAccounting()) {
                    BatchSizeController.getInstance().recordFailure(documents.size());
                    BulkByteBudget.recordFailure();
                    ExportStats.recordOpenSearchFailure();
                }
                toQueue = filterTransientFailures(
                        documents, result.failedItems, result.successCount(), indexName, indexKey);
                failurePartitioned = true;
                break;
            }
            if (!waitBackoffDelay(attempt)) {
                toQueue = new ArrayList<>(documents);
                failurePartitioned = true;
                break;
            }
        }

        if (!OpenSearchPushCancellation.shouldSuppressFailureAccounting()) {
            if (BulkRateLimitBackoff.isCoolingDown()) {
                enterSoftCapacityOutageFromBulk();
            } else {
                int fails = consecutiveFailures.incrementAndGet();
                if (maybeEnterOutageMode(activeBaseUrl, fails)) {
                    recordCurrentPermanentDrops(
                            indexKey,
                            failurePartitioned ? toQueue : documents,
                            "search destination auto-disabled");
                    return lastResult;
                }
            }
        }

        if (!RuntimeConfig.isExportReady()) {
            recordCurrentPermanentDrops(
                    indexKey,
                    failurePartitioned ? toQueue : documents,
                    "export stopped before retry enqueue");
            return lastResult;
        }

        if (!toQueue.isEmpty()) {
            if (toQueue.size() <= MAX_QUEUE_SIZE_PER_INDEX) {
                int added = queue.offerAll(indexName, toQueue);
                if (added < toQueue.size()) {
                    List<PreparedExportDocument> dropped = toQueue.subList(added, toQueue.size());
                    recordRetryQueueDrops(indexKey, dropped);
                    RETRY_PRESSURE_LOGS.record(
                            "retry_queue_full." + indexKey, dropped.size(), this::retryPressureContext);
                }
            } else {
                recordRetryQueueDrops(indexKey, toQueue);
                RETRY_PRESSURE_LOGS.record(
                        "retry_batch_too_large." + indexKey, toQueue.size(), this::retryPressureContext);
            }
        }
        if (authorizationRecoveryPaused.get()) {
            postAuthorizationPauseStatus();
        }
        return lastResult;
    }

    /**
     * Clears queued retry state and resets outage/failure tracking without touching successful stats.
     *
     * <p>Used when export is intentionally stopped or a Start attempt fails, so queued retries do
     * not continue behind a stopped UI. Discarded documents are counted as
     * {@link ExportStats#recordPermanentDrop(String, long)} and logged as WARN so Permanent Drops
     * and outstanding Failures stay honest after Stop.</p>
     */
    public void clearPendingWork() {
        Map<String, List<PreparedExportDocument>> discardedByIndex = queue.drainAll();
        DrainInFlight inFlight = drainInFlight.getAndSet(null);
        if (inFlight != null && inFlight.documents() != null && !inFlight.documents().isEmpty()) {
            discardedByIndex.computeIfAbsent(inFlight.indexName(), ignored -> new ArrayList<>())
                    .addAll(inFlight.documents());
        }
        int discarded = 0;
        StringBuilder detail = new StringBuilder();
        for (Map.Entry<String, List<PreparedExportDocument>> entry : discardedByIndex.entrySet()) {
            List<PreparedExportDocument> docs = entry.getValue();
            if (docs == null || docs.isEmpty()) {
                continue;
            }
            int count = docs.size();
            discarded += count;
            String indexKey = docs.get(0).indexKey();
            if (indexKey == null || indexKey.isBlank()) {
                indexKey = shortIndexKeyFromFullName(entry.getKey());
            }
            ExportStats.recordPermanentDrop(indexKey, count);
            ExportStats.recordPermanentDropReason(ExportStats.PERMANENT_DROP_REASON_STOP, count);
            attributeTrafficRoutePermanentDrops(indexKey, docs);
            if (detail.length() > 0) {
                detail.append(", ");
            }
            detail.append(indexKey).append('=').append(count);
        }
        consecutiveFailures.set(0);
        outageMode.set(false);
        authorizationRecoveryPaused.set(false);
        authorizationProbeAttempts.set(0);
        authorizationPausedAtMs = 0L;
        nextAuthorizationProbeAtMs = 0L;
        authorizationFailureDetail = "";
        healthyClusterUuid = "";
        RuntimeConfig.setSearchRecoveryReplay(false);
        lastOutageLogTime = 0;
        lastDrainBaseUrl = "";
        BulkRateLimitBackoff.clear();
        if (discarded > 0) {
            Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                    + " Discarded " + discarded
                    + " queued retry document(s) on Stop (not recovered; counted as Permanent Drops"
                    + (detail.length() > 0 ? ": " + detail : "")
                    + ").");
        }
    }

    /**
     * Actively retries queued documents during Stop while search connections are still open.
     *
     * <p>Call after {@link #stopDrainThread()} so this method owns the queue without racing the
     * background drain. Bypasses {@link RuntimeConfig#isExportReady()} because Stop has already
     * cleared the running flag. Honors {@code timeoutMs} as a wall-clock budget (including any
     * rate-limit cooldown waits). Remaining documents are left queued for
     * {@link #clearPendingWork()} to discard and warn about.</p>
     *
     * @param timeoutMs maximum milliseconds to spend draining; values {@code <= 0} skip pushes
     * @return drain counters; never {@code null}
     */
    public StopDrainResult drainPendingRetriesDuringShutdown(long timeoutMs) {
        int started = queue.totalSize();
        if (started == 0) {
            return new StopDrainResult(0, 0, 0);
        }
        if (!RuntimeConfig.isSearchExportEnabled()) {
            Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                    + " Search export disabled; skipping Stop retry drain ("
                    + started + " queued).");
            return new StopDrainResult(0, 0, started);
        }
        if (authorizationRecoveryPaused.get()) {
            Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                    + " Authorization recovery is still paused; skipping Stop retry drain ("
                    + started + " queued).");
            return new StopDrainResult(0, 0, started);
        }
        String baseUrl = resolveBaseUrlForOperation("");
        if (baseUrl == null || baseUrl.isBlank()) {
            Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                    + " No search URL; skipping Stop retry drain ("
                    + started + " queued).");
            return new StopDrainResult(0, 0, started);
        }
        long budgetMs = Math.max(0L, timeoutMs);
        Logger.logInfoPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                + " Stop drain: retrying " + started
                + " queued document(s) (budget " + budgetMs + " ms).");
        if (budgetMs == 0L) {
            return new StopDrainResult(0, 0, started);
        }
        long deadlineNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(budgetMs);
        int recovered = 0;
        int attempted = 0;
        while (queue.totalSize() > 0 && System.nanoTime() < deadlineNanos) {
            if (RuntimeConfig.isExportStopForceAbortRequested() || Thread.currentThread().isInterrupted()) {
                Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                        + " Stop drain interrupted by force-stop (attempted=" + attempted
                        + " recovered=" + recovered + " remaining=" + queue.totalSize() + ").");
                break;
            }
            // Cap cooldown wait so a 60s shared deadline cannot consume the Stop budget unused.
            long remainingBudgetMs = TimeUnit.NANOSECONDS.toMillis(deadlineNanos - System.nanoTime());
            if (remainingBudgetMs <= 0L) {
                break;
            }
            int batchSize = Math.max(1, BatchSizeController.getInstance().getCurrentBatchSize());
            RetryQueue.PolledBatch polled = queue.pollNextBatch(batchSize, BulkByteBudget.currentMaxBytes());
            if (polled == null) {
                break;
            }
            String indexName = polled.indexName();
            BulkRateLimitBackoff.awaitIfNeeded(
                    indexName,
                    Math.min(BulkRateLimitBackoff.STOP_DRAIN_MAX_COOLDOWN_WAIT_MS, remainingBudgetMs));
            if (System.nanoTime() >= deadlineNanos) {
                // Re-queue the polled batch so Stop cleanup can discard it as Permanent Drops.
                offerAllAccountingDrops(indexName, polled.documents().get(0).indexKey(), polled.documents());
                break;
            }
            List<PreparedExportDocument> batch = polled.documents();
            attempted += batch.size();
            String indexKey = batch.get(0).indexKey();
            noteRetryDrainPush(indexKey, indexName, batch.size());
            OpenSearchClientWrapper.BulkResult result =
                    OpenSearchClientWrapper.doPushPreparedBulkWithDetails(baseUrl, indexName, batch);
            int sent = result.successCount();
            if (sent > 0) {
                recovered += sent;
                if (sent == batch.size()) {
                    noteFullPayloadBulkSuccess(indexKey, result.maxSuccessfulRequestBytes());
                } else {
                    BulkByteBudget.recordFailure();
                }
                recordRetryRecovery(indexKey, batch, result);
                logRetryRecovery(indexKey, indexName, sent, batch.size() - sent);
                // Successes only: failures were already counted when first queued.
                ExportStats.recordRetryDrainBulkSuccess(indexKey, result.breakdown());
                ExportStats.recordExportedBytes(indexKey, estimateSuccessfulBytes(batch, sent));
                ExportStats.recordOpenSearchSuccess();
                if (sent == batch.size() && queue.size(indexName) == 0) {
                    ExportStats.clearLastError(indexKey);
                }
            }
            if (sent < batch.size()) {
                List<PreparedExportDocument> reQueue = filterTransientFailures(
                        batch, result.failedItems, result.successCount(), indexName, indexKey);
                if (sent == 0) {
                    logRetryDrainFailure(indexKey, indexName, batch.size(), reQueue.size(), result);
                }
                offerAllAccountingDrops(indexName, indexKey, reQueue);
            }
        }
        int remaining = queue.totalSize();
        Logger.logInfoPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                + " Stop drain finished: recovered=" + recovered
                + " (evidence=bulk_item_success)"
                + " remaining=" + remaining
                + (remaining > 0
                        ? " (will discard as Permanent Drops on Stop cleanup)"
                        : "")
                + ".");
        return new StopDrainResult(attempted, recovered, remaining);
    }

    /**
     * Logs a WARN when Stats still show outstanding (unrecovered) exported failures after Stop.
     *
     * <p>Complements {@link #clearPendingWork()} discard warnings: outstanding can remain even when
     * the retry queue is empty (for example documents never queued, or permanent drops already
     * counted separately).</p>
     */
    public static void warnIfOutstandingFailuresRemain() {
        long total = ExportStats.getTotalOutstandingFailureCount();
        if (total <= 0L) {
            return;
        }
        StringBuilder message = new StringBuilder(128);
        message.append(RuntimeConfig.searchDestinationLogPrefix())
                .append(" Stop finished with ")
                .append(total)
                .append(" outstanding exported failure(s)");
        List<String> parts = new ArrayList<>();
        for (String key : ExportStats.getIndexKeys()) {
            long count = ExportStats.getOutstandingFailureCount(key);
            if (count > 0L) {
                parts.add(key + "=" + count);
            }
        }
        if (!parts.isEmpty()) {
            message.append(": ").append(String.join(", ", parts));
        }
        message.append('.');
        Logger.logWarnPanelOnly(message.toString());
    }

    /**
     * Returns the total number of documents currently waiting in all retry queues.
     *
     * @return non-negative queue depth
     */
    public int getTotalQueueSize() {
        return queue.totalSize();
    }

    /**
     * Offers failed prepared documents to the retry queue after a chunked (or other) bulk path
     * already recorded the failure.
     *
     * <p>Applies the same transient/permanent partition as prepared-bulk retries. Starts the drain
     * thread when needed. Safe to call from the traffic drain worker.</p>
     *
     * @param indexName target index name
     * @param indexKey short index key for stats (e.g. {@code "traffic"})
     * @param documents documents that were attempted in the failed bulk; {@code null}/empty ignored
     * @param failedItems per-item failures when available
     * @param knownSuccessCount aggregate successes for the same attempt
     * @return number of documents accepted into the retry queue
     */
    public int enqueueFailedPreparedDocuments(
            String indexName,
            String indexKey,
            List<PreparedExportDocument> documents,
            List<OpenSearchClientWrapper.FailedItem> failedItems,
            int knownSuccessCount) {
        if (documents == null || documents.isEmpty()) {
            return 0;
        }
        if (!ExportRunContext.allowsRunMutation()) {
            return 0;
        }
        List<PreparedExportDocument> toQueue = filterTransientFailures(
                documents, failedItems, knownSuccessCount, indexName, indexKey);
        if (toQueue.isEmpty()) {
            return 0;
        }
        if (!RuntimeConfig.isSearchExportEnabled()) {
            recordCurrentPermanentDrops(indexKey, toQueue, "search destination disabled before retry enqueue");
            return 0;
        }
        // Allow enqueue while Stop is draining an in-flight chunked bulk (exportRunning already false).
        if (!RuntimeConfig.isExportReady() && !RuntimeConfig.isExportStopping()) {
            recordCurrentPermanentDrops(indexKey, toQueue, "export stopped before retry enqueue");
            return 0;
        }
        ensureDrainThreadStarted();
        int added;
        if (toQueue.size() <= MAX_QUEUE_SIZE_PER_INDEX) {
            added = queue.offerAll(indexName, toQueue);
            if (added < toQueue.size()) {
                List<PreparedExportDocument> dropped = toQueue.subList(added, toQueue.size());
                recordRetryQueueDrops(indexKey, dropped);
                RETRY_PRESSURE_LOGS.record(
                        "retry_queue_full." + indexKey, dropped.size(), this::retryPressureContext);
            }
        } else {
            recordRetryQueueDrops(indexKey, toQueue);
            RETRY_PRESSURE_LOGS.record(
                    "retry_batch_too_large." + indexKey, toQueue.size(), this::retryPressureContext);
            added = 0;
        }
        if (added > 0) {
            Logger.logInfoPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                    + " Queued " + added + " document(s) for retry"
                    + " (index=" + indexName + ").");
        }
        return added;
    }

    /**
     * Exposes drain-thread liveness for lifecycle and unload-termination tests.
     *
     * @return {@code true} when the drain thread reference is non-null and still alive
     */
    public boolean isDrainThreadAlive() {
        Thread worker = drainThread;
        return worker != null && worker.isAlive();
    }

    /**
     * Interrupts and joins the drain thread with the short unload budget.
     *
     * <p>Prefer {@link #stopDrainThread(long)} from export Stop so an in-flight bulk can finish and
     * re-queue before the synchronous Stop drain runs.</p>
     *
     * @return {@code true} when no owner remains, {@code false} when the existing owner is still alive
     */
    public boolean stopDrainThread() {
        return stopDrainThread(DRAIN_SHUTDOWN_TIMEOUT_MS);
    }

    /**
     * Interrupts and joins the drain thread so callers own the retry queue without a poll race.
     *
     * <p>Safe to call from any thread and safe to call more than once. The owner reference remains
     * installed until termination, preventing a replacement drain from competing for the queue.
     * Callers must not begin a synchronous Stop drain when this method returns {@code false}.</p>
     *
     * @param joinTimeoutMs maximum milliseconds to wait for the drain thread to exit; {@code <= 0}
     *                      interrupts without waiting
     * @return {@code true} when no owner remains, {@code false} when the existing owner is still alive
     */
    public boolean stopDrainThread(long joinTimeoutMs) {
        Thread worker;
        synchronized (drainThreadLock) {
            worker = drainThread;
        }
        Workers.awaitThreadJoin(worker, joinTimeoutMs);
        if (worker != null && worker.isAlive()) {
            return false;
        }
        synchronized (drainThreadLock) {
            if (drainThread == worker) {
                drainThread = null;
            }
        }
        return true;
    }

    private boolean maybeEnterOutageMode(String baseUrl, int consecutiveFails) {
        if (consecutiveFails != CONSECUTIVE_FAILURES_BEFORE_CHECK) {
            return false;
        }
        Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                + " Repeated push failures detected; testing destination health.");
        SearchConnectionStatus status = testConnectionWithRuntimeConfig(baseUrl);
        if (status.success()) {
            consecutiveFailures.set(0);
            return false;
        }
        SearchDestinationFailureKind kind = SearchDestinationFailureKind.classify(status);
        if (kind == SearchDestinationFailureKind.AUTH) {
            enterAuthorizationRecoveryPause(status);
            return false;
        }
        if (kind == SearchDestinationFailureKind.HARD) {
            outageMode.set(true);
            logOutageOnce();
            return handlePersistentDestinationFailure(status, kind);
        }
        if (!outageMode.getAndSet(true)) {
            ExportStats.recordSoftOutageEntry();
        }
        logOutageOnce();
        enterSoftCapacityOutage(status);
        return false;
    }

    /**
     * Keeps export enabled under gateway/transport pressure: queue + escalated backoff, no disable.
     *
     * @param status failed health probe classified as capacity pressure
     */
    private void enterSoftCapacityOutage(SearchConnectionStatus status) {
        consecutiveFailures.set(0);
        String detail = status == null || status.message() == null || status.message().isBlank()
                ? "capacity pressure"
                : status.message();
        BulkRateLimitBackoff.noteCapacityProbeFailure(detail);
        int queued = queue.totalSize();
        Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                + " Soft outage: capacity probe failed"
                + " queued=" + queued
                + " byteBudget=" + BulkByteBudget.currentMaxBytes()
                + " inFlightFlushes=" + BulkByteBudget.maxInFlightFlushes()
                + " cooldownActive=" + BulkRateLimitBackoff.isCoolingDown()
                + " pressureStreak=" + BulkRateLimitBackoff.pressureStreak()
                + " detail=" + detail.replace('\n', ' ').strip() + ".");
    }

    /**
     * Enters soft capacity outage when bulk capacity symptoms are already active without probing.
     */
    private void enterSoftCapacityOutageFromBulk() {
        if (!outageMode.getAndSet(true)) {
            ExportStats.recordSoftOutageEntry();
            Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                    + " Soft outage: entering from bulk pressure"
                    + " queued=" + queue.totalSize()
                    + " byteBudget=" + BulkByteBudget.currentMaxBytes()
                    + " inFlightFlushes=" + BulkByteBudget.maxInFlightFlushes()
                    + " cooldownActive=" + BulkRateLimitBackoff.isCoolingDown()
                    + " pressureStreak=" + BulkRateLimitBackoff.pressureStreak() + ".");
        }
        consecutiveFailures.set(0);
        logOutageOnce();
    }

    /**
     * Returns whether soft capacity outage mode is active.
     *
     * <p>When {@code true}, export stays enabled and the retry drain paces work under shared
     * capacity backoff. Surfaced on the Misc Stats {@code Soft Outage} row.</p>
     *
     * @return {@code true} while soft capacity outage is active
     */
    public boolean isSoftCapacityOutage() {
        return outageMode.get();
    }

    /**
     * Returns whether database sends are paused while authorization is re-probed.
     *
     * @return {@code true} after repeated 401/403 responses until recovery or Stop
     */
    public boolean isAuthorizationRecoveryPaused() {
        return authorizationRecoveryPaused.get();
    }

    /**
     * Returns when the current authorization pause began.
     *
     * @return epoch milliseconds, or {@code 0} when not paused
     */
    public long getAuthorizationPausedAtMs() {
        return authorizationPausedAtMs;
    }

    /**
     * Returns the latest authorization probe failure.
     *
     * @return concise failure detail; empty when not paused
     */
    public String getAuthorizationFailureDetail() {
        return authorizationFailureDetail;
    }

    /**
     * Returns when the next authorization probe may run.
     *
     * @return epoch milliseconds, or {@code 0} when not paused
     */
    public long getNextAuthorizationProbeAtMs() {
        return nextAuthorizationProbeAtMs;
    }

    /**
     * Records the healthy cluster identity observed during Start preflight.
     *
     * <p>Blank identities are ignored because Serverless and some proxies do not expose
     * {@code cluster_uuid}.</p>
     *
     * @param clusterUuid root-response cluster UUID
     */
    public void recordHealthyClusterIdentity(String clusterUuid) {
        String normalized = normalizeClusterUuid(clusterUuid);
        if (!normalized.isBlank()) {
            healthyClusterUuid = normalized;
        }
    }

    /**
     * Contributes a live chunked-bulk 401/403 to the shared authorization-failure threshold.
     *
     * <p>Prepared snapshot paths already flow through this coordinator. Traffic's chunked sender
     * calls this hook so traffic-only runs receive the same recoverable pause policy.</p>
     *
     * @param baseUrl active destination URL
     * @param httpStatus HTTP response status
     */
    public void noteHttpAuthorizationFailure(String baseUrl, int httpStatus) {
        if ((httpStatus != 401 && httpStatus != 403)
                || authorizationRecoveryPaused.get()
                || !RuntimeConfig.isExportRunning()) {
            return;
        }
        int failures = consecutiveFailures.incrementAndGet();
        maybeEnterOutageMode(resolveBaseUrlForOperation(baseUrl), failures);
    }

    /**
     * Sets soft-outage state without producing pressure side effects.
     *
     * <p>Intended for isolated tests; callers must use a non-shared coordinator or restore the
     * previous state before allowing production work.</p>
     *
     * @param active replacement soft-outage state
     */
    void setSoftCapacityOutageForTests(boolean active) {
        outageMode.set(active);
    }

    /** Clears the consecutive-failure counter for isolated recovery tests. */
    void noteReachableProbeForTests() {
        consecutiveFailures.set(0);
    }

    /**
     * Replaces authorization-recovery collaborators for isolated tests.
     *
     * <p>Each {@code null} collaborator restores its production implementation. Hooks run on the
     * retry-drain thread and must honor the supplied run token, avoid blocking indefinitely, and
     * return non-null results.</p>
     *
     * @param probe replacement credential probe, or {@code null} for production behavior
     * @param preparer replacement index preparer, or {@code null} for production behavior
     * @param replayer replacement snapshot replayer, or {@code null} for production behavior
     */
    void setAuthorizationRecoveryHooksForTests(
            AuthorizationProbe probe,
            RecoveryPreparer preparer,
            SnapshotReplayer replayer) {
        authorizationProbe = probe == null
                ? IndexingRetryCoordinator::testConnectionWithRuntimeConfig
                : probe;
        recoveryPreparer = preparer == null
                ? SearchRecoveryBootstrap::ensureSelectedIndexes
                : preparer;
        snapshotReplayer = replayer == null
                ? SearchRecoveryBootstrap::replaySelectedSnapshots
                : replayer;
    }

    /**
     * Enters authorization pause immediately and makes its first probe eligible.
     *
     * @param status failed status used for operator detail
     */
    void enterAuthorizationRecoveryPauseForTests(SearchConnectionStatus status) {
        enterAuthorizationRecoveryPause(status);
        nextAuthorizationProbeAtMs = 0L;
    }

    /**
     * Runs one eligible authorization-recovery probe synchronously.
     *
     * @param token active export run that owns resulting state mutations
     */
    void probeAuthorizationRecoveryForTests(ExportRunToken token) {
        maybeProbeAuthorizationRecovery(token);
    }

    /**
     * Records one fully successful payload bulk for shared recovery hysteresis.
     *
     * <p>Live traffic, prepared snapshots, and retry drains use this method. Single exporter,
     * logging, Stats, and health-probe requests do not, so they cannot clear Soft Outage. A partial
     * success must call {@link BulkByteBudget#recordFailure()} instead.</p>
     *
     * @param indexKey logical payload index key
     * @param bulkBytes successful NDJSON bytes
     */
    public void noteFullPayloadBulkSuccess(String indexKey, long bulkBytes) {
        boolean recoveryQualified = BulkByteBudget.recordFullPayloadSuccess(
                bulkBytes, canClearSoftOutageFromIndex(indexKey));
        if (!recoveryQualified || !outageMode.compareAndSet(true, false)) {
            return;
        }
        consecutiveFailures.set(0);
        Logger.logInfoPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                + " Soft outage cleared: full payload recovery streak="
                + OfferedLoadGovernor.RECOVERY_SUCCESS_STREAK
                + " queued=" + queue.totalSize()
                + " byteBudget=" + BulkByteBudget.currentMaxBytes()
                + " offeredBytesPerSecond=" + OfferedLoadGovernor.currentBytesPerSecond()
                + " inFlightRequests=" + OfferedLoadGovernor.currentMaxInFlight() + ".");
    }

    private void enterAuthorizationRecoveryPause(SearchConnectionStatus status) {
        long now = System.currentTimeMillis();
        authorizationFailureDetail = conciseStatusDetail(status);
        if (authorizationRecoveryPaused.compareAndSet(false, true)) {
            authorizationPausedAtMs = now;
            authorizationProbeAttempts.set(0);
            nextAuthorizationProbeAtMs = now + AUTHORIZATION_PROBE_BACKOFF_MS[0];
            outageMode.set(false);
            Logger.logErrorPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                    + " Authorization recovery paused after repeated 401/403 responses."
                    + " Database sends and snapshot production are paused; queued work is retained."
                    + " Automatic probe in " + AUTHORIZATION_PROBE_BACKOFF_MS[0] / 1_000L
                    + "s. detail=" + authorizationFailureDetail + ".");
        }
        postAuthorizationPauseStatus();
    }

    private void maybeProbeAuthorizationRecovery(ExportRunToken token) {
        if (!authorizationRecoveryPaused.get()
                || !RuntimeConfig.isExportRunActive(token)
                || System.currentTimeMillis() < nextAuthorizationProbeAtMs) {
            return;
        }
        String baseUrl = resolveBaseUrlForOperation("");
        int attempt = authorizationProbeAttempts.incrementAndGet();
        Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                + " Authorization recovery probe starting: attempt=" + attempt
                + " retainedRetryDocs=" + queue.totalSize() + ".");
        SearchConnectionStatus status = authorizationProbe.test(baseUrl);
        if (!RuntimeConfig.isExportRunActive(token) || !authorizationRecoveryPaused.get()) {
            return;
        }
        if (!status.success()) {
            authorizationFailureDetail = conciseStatusDetail(status);
            scheduleNextAuthorizationProbe(attempt);
            Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                    + " Authorization recovery probe failed: attempt=" + attempt
                    + " nextProbeInMs=" + Math.max(0L, nextAuthorizationProbeAtMs - System.currentTimeMillis())
                    + " detail=" + authorizationFailureDetail + ".");
            postAuthorizationPauseStatus();
            return;
        }

        String currentUuid = normalizeClusterUuid(status.clusterUuid());
        boolean identityChanged = !healthyClusterUuid.isBlank()
                && !currentUuid.isBlank()
                && !healthyClusterUuid.equals(currentUuid);
        SearchRecoveryBootstrap.RecoveryPreparation preparation =
                recoveryPreparer.prepare(baseUrl, identityChanged, token);
        if (!preparation.ready()) {
            authorizationFailureDetail = preparation.detail();
            scheduleNextAuthorizationProbe(attempt);
            Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                    + " Authorization returned, but index revalidation is not ready:"
                    + " detail=" + preparation.detail()
                    + " nextProbeInMs=" + Math.max(0L, nextAuthorizationProbeAtMs - System.currentTimeMillis())
                    + ".");
            postAuthorizationPauseStatus();
            return;
        }
        if (preparation.replayRequired() && !snapshotReplayer.replay(token)) {
            authorizationFailureDetail = "selected snapshot replay did not quiesce";
            scheduleNextAuthorizationProbe(attempt);
            postAuthorizationPauseStatus();
            return;
        }

        if (!currentUuid.isBlank()) {
            healthyClusterUuid = currentUuid;
        }
        long pausedMs = Math.max(0L, System.currentTimeMillis() - authorizationPausedAtMs);
        authorizationRecoveryPaused.set(false);
        authorizationProbeAttempts.set(0);
        nextAuthorizationProbeAtMs = 0L;
        authorizationFailureDetail = "";
        authorizationPausedAtMs = 0L;
        consecutiveFailures.set(0);
        outageMode.set(false);
        Logger.logInfoPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                + " Authorization recovery completed: pausedMs=" + pausedMs
                + " clusterIdentityChanged=" + identityChanged
                + " snapshotReplay=" + preparation.replayRequired()
                + " retainedRetryDocs=" + queue.totalSize() + ".");
        ControlStatusBridge.post(runningDestinationStatus());
    }

    private void scheduleNextAuthorizationProbe(int completedAttempt) {
        int delayIndex = Math.min(
                Math.max(0, completedAttempt),
                AUTHORIZATION_PROBE_BACKOFF_MS.length - 1);
        nextAuthorizationProbeAtMs =
                System.currentTimeMillis() + AUTHORIZATION_PROBE_BACKOFF_MS[delayIndex];
    }

    private void postAuthorizationPauseStatus() {
        long pausedSeconds = authorizationPausedAtMs <= 0L
                ? 0L
                : Math.max(0L, (System.currentTimeMillis() - authorizationPausedAtMs) / 1_000L);
        long retrySeconds = Math.max(
                0L,
                (nextAuthorizationProbeAtMs - System.currentTimeMillis() + 999L) / 1_000L);
        String paused = "Paused (authorization recovery"
                + "; " + pausedSeconds + "s"
                + "; retained retry=" + queue.totalSize()
                + "; traffic=" + ai.anomalousvectors.tools.burp.sinks.TrafficExportQueue.getCurrentSize()
                + "; next probe=" + retrySeconds + "s"
                + "; " + authorizationFailureDetail + ")";
        String files = RuntimeConfig.isAnyFileExportEnabled() ? "Files: Running\n" : "";
        ControlStatusBridge.post(files + RuntimeConfig.searchDestinationDisplayName() + ": " + paused);
    }

    private static String runningDestinationStatus() {
        String files = RuntimeConfig.isAnyFileExportEnabled() ? "Files: Running\n" : "";
        return files + RuntimeConfig.searchDestinationDisplayName() + ": Running";
    }

    private static String conciseStatusDetail(SearchConnectionStatus status) {
        if (status == null || status.message() == null || status.message().isBlank()) {
            return "authorization rejected";
        }
        String detail = status.message().replace('\r', ' ').replace('\n', ' ').strip();
        return detail.length() <= 180 ? detail : detail.substring(0, 177) + "...";
    }

    private static String normalizeClusterUuid(String clusterUuid) {
        return clusterUuid == null ? "" : clusterUuid.trim();
    }

    private boolean handlePersistentDestinationFailure(
            SearchConnectionStatus status,
            SearchDestinationFailureKind kind) {
        if (!RuntimeConfig.disableDatabaseDestination()) {
            return false;
        }
        clearPendingWork();
        boolean authFailure = kind == SearchDestinationFailureKind.AUTH
                || "Failed".equals(status.authenticationStatus());
        String failureKind = authFailure ? "authentication failures" : "connectivity failures";
        if (kind == SearchDestinationFailureKind.HARD && !authFailure) {
            failureKind = "configuration failures";
        }
        String detail = status.message() == null || status.message().isBlank()
                ? failureKind
                : failureKind + " (" + status.message() + ")";
        String recoveryHint = authFailure
                ? " Update credentials in Config (bearer/API key/session token may have expired), then Stop and Start."
                : " Fix the destination configuration, then Stop and Start.";
        if (RuntimeConfig.isAnyFileExportEnabled()) {
            String destination = RuntimeConfig.searchDestinationDisplayName();
            String message = destination + " export disabled after repeated " + detail
                    + ". Files export will continue." + recoveryHint;
            Logger.logErrorPanelOnly(RuntimeConfig.searchDestinationLogPrefix() + " " + message);
            ControlStatusBridge.post(message);
            return true;
        }
        String destination = RuntimeConfig.searchDestinationDisplayName();
        String message = destination + " export disabled after repeated " + detail
                + ". No destinations remain; export stopped." + recoveryHint;
        Logger.logErrorPanelOnly(RuntimeConfig.searchDestinationLogPrefix() + " " + message);
        ControlStatusBridge.post(message);
        ExportReporterLifecycle.stopAndClearPendingExportWork();
        ExportReporterLifecycle.releaseRunResourcesAsync();
        Logger.logInfoPanelOnly("[Export] Forced stop after destination auto-disable; syncing Start/Stop controls.");
        ExportControlBridge.notifyForcedStopped();
        return true;
    }

    private void logOutageOnce() {
        if (queue.totalSize() == 0) {
            return;
        }
        if (System.currentTimeMillis() - lastOutageLogTime < OUTAGE_LOG_THROTTLE_MS) {
            return;
        }
        lastOutageLogTime = System.currentTimeMillis();
        StringBuilder sb = new StringBuilder(RuntimeConfig.searchDestinationLogPrefix())
                .append(outageMode.get()
                        ? " Soft outage: queue snapshot "
                        : " Unreachable: queue snapshot ");
        for (String key : ExportStats.getIndexKeys()) {
            String indexName = indexNameFromKey(key);
            int size = queue.size(indexName);
            if (size > 0) {
                sb.append(key).append("=").append(size).append(" ");
            }
        }
        sb.append("byteBudget=").append(BulkByteBudget.currentMaxBytes())
                .append(" cooldownActive=").append(BulkRateLimitBackoff.isCoolingDown())
                .append(" pressureStreak=").append(BulkRateLimitBackoff.pressureStreak())
                .append('.');
        Logger.logWarnPanelOnly(sb.toString().replaceAll("  +", " ").strip());
    }

    private static boolean canClearSoftOutageFromIndex(String indexKey) {
        if (indexKey == null || indexKey.isBlank()) {
            return false;
        }
        return !"exporter".equals(indexKey);
    }

    /**
     * Returns index keys ordered by oldest retry age so findings/sitemap are not starved by traffic.
     *
     * <p>Under Soft Outage, {@code exporter} is drained last so payload recovery keeps HTTP slots.</p>
     */
    private List<String> fairDrainIndexKeys() {
        List<String> keys = new ArrayList<>(ExportStats.getIndexKeys());
        keys.sort(Comparator.comparingLong((String key) -> {
            String indexName = indexNameFromKey(key);
            long enqueuedAt = queue.oldestEnqueuedAtMs(indexName);
            return enqueuedAt < 0L ? Long.MAX_VALUE : enqueuedAt;
        }));
        if (outageMode.get() && keys.size() > 1) {
            List<String> exporter = new ArrayList<>();
            List<String> others = new ArrayList<>();
            for (String key : keys) {
                if ("exporter".equals(key)) {
                    exporter.add(key);
                } else {
                    others.add(key);
                }
            }
            others.addAll(exporter);
            return others;
        }
        return keys;
    }

    /**
     * Logs an INFO panel line when the retry drain recovers previously failed documents.
     *
     * <p>Recovery is claimed only after a prepared bulk returns per-item success for those
     * documents ({@code evidence=bulk_item_success}). This is not a Stats-only bookkeeping line.</p>
     *
     * @param indexKey short index key
     * @param indexName full index name
     * @param recoveredCount documents successfully re-indexed in this drain batch
     * @param stillQueuedCount documents from this batch re-queued after partial success
     */
    private static void logRetryRecovery(
            String indexKey,
            String indexName,
            int recoveredCount,
            int stillQueuedCount) {
        if (recoveredCount <= 0) {
            return;
        }
        int batchSize = recoveredCount + Math.max(0, stillQueuedCount);
        StringBuilder message = new StringBuilder(200);
        message.append(RuntimeConfig.searchDestinationLogPrefix())
                .append(" Recovered previously failed documents:")
                .append(" index=")
                .append(indexName == null || indexName.isBlank() ? indexKey : indexName)
                .append(" recovered=")
                .append(recoveredCount)
                .append(" successCount=")
                .append(recoveredCount)
                .append('/')
                .append(batchSize)
                .append(" evidence=bulk_item_success")
                .append(" countedInExported=true")
                .append(" countedInRecoveredFailures=true");
        if (stillQueuedCount > 0) {
            message.append(" stillQueued=").append(stillQueuedCount);
        }
        message.append('.');
        Logger.logInfoPanelOnly(message.toString());
    }

    /**
     * Records a retry-drain push and emits an INFO start line so operators can see progress.
     *
     * @param indexKey short index key
     * @param indexName full index name
     * @param docs documents in this push batch
     */
    private void noteRetryDrainPush(String indexKey, String indexName, int docs) {
        if (docs <= 0) {
            return;
        }
        ExportStats.recordRetryAttempt(indexKey, docs);
        Logger.logInfoPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                + " Retry drain push starting:"
                + " index=" + (indexName == null || indexName.isBlank() ? indexKey : indexName)
                + " docs=" + docs
                + " queueRemainingBeforePush=" + queue.totalSize()
                + " softOutage=" + outageMode.get()
                + " cooldownActive=" + BulkRateLimitBackoff.isCoolingDown()
                + " byteBudget=" + BulkByteBudget.currentMaxBytes()
                + " inFlightFlushes=" + BulkByteBudget.maxInFlightFlushes()
                + " pressureStreak=" + BulkRateLimitBackoff.pressureStreak() + ".");
    }

    /**
     * Logs when a retry-drain push recovers nothing and documents are re-queued.
     *
     * @param indexKey short index key
     * @param indexName full index name
     * @param attemptedDocs documents pushed in this batch
     * @param requeuedDocs documents returned to the retry queue
     * @param result bulk result; may be {@code null}
     */
    private static void logRetryDrainFailure(
            String indexKey,
            String indexName,
            int attemptedDocs,
            int requeuedDocs,
            OpenSearchClientWrapper.BulkResult result) {
        if (attemptedDocs <= 0) {
            return;
        }
        String cause = "unknown";
        if (result != null && result.failedItems != null && !result.failedItems.isEmpty()) {
            OpenSearchClientWrapper.FailedItem first = result.failedItems.get(0);
            String type = first.type() == null ? "" : first.type().trim();
            String reason = first.reason() == null ? "" : first.reason().trim();
            cause = type.isEmpty() ? reason : (reason.isEmpty() ? type : type + ": " + reason);
            if (cause.length() > 160) {
                cause = cause.substring(0, 157) + "...";
            }
        } else if (result != null && result.breakdown() != null && result.breakdown().failed() > 0) {
            cause = "bulk_item_failures=" + result.breakdown().failed();
        } else {
            cause = "transport_or_empty_success";
        }
        Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                + " Retry drain push failed:"
                + " index=" + (indexName == null || indexName.isBlank() ? indexKey : indexName)
                + " docs=" + attemptedDocs
                + " requeued=" + Math.max(0, requeuedDocs)
                + " recoveredThisPush=0"
                + " cooldownActive=" + BulkRateLimitBackoff.isCoolingDown()
                + " byteBudget=" + BulkByteBudget.currentMaxBytes()
                + " pressureStreak=" + BulkRateLimitBackoff.pressureStreak()
                + " cause=" + cause + ".");
    }

    private static String indexNameFromKey(String indexKey) {
        return RuntimeConfig.indexNameForKey(indexKey);
    }

    /**
     * Best-effort short index key when a queued document has no {@code indexKey}.
     *
     * @param fullIndexName full index name from the retry queue
     * @return matching {@link ExportStats} key, or {@code unknown}
     */
    private static String shortIndexKeyFromFullName(String fullIndexName) {
        if (fullIndexName == null || fullIndexName.isBlank()) {
            return "unknown";
        }
        for (String key : ExportStats.getIndexKeys()) {
            if (fullIndexName.equals(RuntimeConfig.indexNameForKey(key))) {
                return key;
            }
        }
        String lower = fullIndexName.toLowerCase(java.util.Locale.ROOT);
        for (String key : ExportStats.getIndexKeys()) {
            if (lower.endsWith("-" + key) || lower.endsWith("_" + key) || lower.equals(key)) {
                return key;
            }
        }
        return "unknown";
    }

    private void ensureDrainThreadStarted() {
        if (drainThread != null && drainThread.isAlive()) {
            return;
        }
        synchronized (drainThreadLock) {
            if (drainThread != null && drainThread.isAlive()) {
                return;
            }
            ExportRunToken token = RuntimeConfig.currentExportRunToken();
            drainThread = new Thread(
                    () -> ExportRunContext.call(token, () -> {
                        drainLoop(token);
                        return null;
                    }),
                    "OpenSearchRetryDrain");
            drainThread.setDaemon(true);
            drainThread.start();
        }
    }

    private void drainLoop(ExportRunToken token) {
        drainLoopUntilStopped(token);
    }

    private void drainLoopUntilStopped(ExportRunToken token) {
        while (true) {
            if (!RuntimeConfig.isExportRunActive(token)) {
                break;
            }
            // Soft capacity outage still has a reachable destination — drain at the normal cadence
            // so findings/sitemap recovery is not parked for 30s between attempts. Use the longer
            // interval only when outage mode is active and there is nothing queued yet.
            long interval = (outageMode.get() && queue.allEmpty())
                    ? DRAIN_INTERVAL_MS_OUTAGE
                    : DRAIN_INTERVAL_MS_NORMAL;
            if (!waitInterval(interval)) {
                break;
            }

            // Exit if ownership changed; Stop otherwise retains this reference until termination.
            if (drainThread != Thread.currentThread()) {
                break;
            }

            if (!RuntimeConfig.isExportRunActive(token) || !RuntimeConfig.isExportReady()) {
                break;
            }

            if (authorizationRecoveryPaused.get()) {
                maybeProbeAuthorizationRecovery(token);
                continue;
            }

            if (outageMode.get() && queue.totalSize() > 0) {
                if (System.currentTimeMillis() - lastOutageLogTime >= OUTAGE_LOG_THROTTLE_MS) {
                    lastOutageLogTime = System.currentTimeMillis();
                    Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix() + " Still unreachable. Queued: "
                            + queue.totalSize() + ". Will retry.");
                }
            }

            String baseUrl = resolveBaseUrlForOperation("");
            if (baseUrl.isBlank()) {
                continue;
            }
            maybeLogDestinationChange(baseUrl);

            for (String indexKey : fairDrainIndexKeys()) {
                String indexName = indexNameFromKey(indexKey);
                int batchSize = BatchSizeController.getInstance().getCurrentBatchSize();
                // Cap retry bulks by the live byte budget so Hosted Soft Outage recovery cannot
                // reassemble dozens of large traffic docs into a multi-MiB HTTP body.
                List<PreparedExportDocument> batch = queue.pollBatch(
                        indexName, batchSize, BulkByteBudget.currentMaxBytes());
                if (batch.isEmpty()) continue;

                noteRetryDrainPush(indexKey, indexName, batch.size());
                DrainInFlight inFlight = new DrainInFlight(indexName, indexKey, List.copyOf(batch));
                drainInFlight.set(inFlight);
                OpenSearchClientWrapper.BulkResult result =
                        OpenSearchClientWrapper.doPushPreparedBulkWithDetails(baseUrl, indexName, batch);
                if (!RuntimeConfig.isExportRunActive(token)
                        || !drainInFlight.compareAndSet(inFlight, null)) {
                    return;
                }
                noteAuthorizationFailureFromResult(baseUrl, result);
                if (authorizationRecoveryPaused.get()) {
                    offerAllAccountingDrops(indexName, indexKey, batch);
                    continue;
                }
                int sent = result.successCount();
                if (isOnlyDocumentTooLargeOutcome(batch, result)) {
                    if (sent > 0) {
                        BatchSizeController.getInstance().recordSuccess(sent);
                        BulkByteBudget.recordFailure();
                        recordRetryRecovery(indexKey, batch, result);
                        ExportStats.recordRetryDrainBulkSuccess(indexKey, result.breakdown());
                        ExportStats.recordExportedBytes(indexKey, estimateSuccessfulBytes(batch, sent));
                        ExportStats.recordOpenSearchSuccess();
                    }
                    filterTransientFailures(
                            batch, result.failedItems, result.successCount(), indexName, indexKey);
                    continue;
                }
                if (sent == batch.size()) {
                    BatchSizeController.getInstance().recordSuccess(sent);
                    noteFullPayloadBulkSuccess(indexKey, result.maxSuccessfulRequestBytes());
                    recordRetryRecovery(indexKey, batch, result);
                    logRetryRecovery(indexKey, indexName, sent, 0);
                    // Successes only: failures were already counted when first queued.
                    ExportStats.recordRetryDrainBulkSuccess(indexKey, result.breakdown());
                    ExportStats.recordExportedBytes(indexKey, estimateSuccessfulBytes(batch, sent));
                    ExportStats.recordOpenSearchSuccess();
                    if (queue.size(indexName) == 0) {
                        ExportStats.clearLastError(indexKey);
                    }
                } else if (sent > 0) {
                    BatchSizeController.getInstance().recordPartialSuccess(sent, batch.size());
                    BulkByteBudget.recordFailure();
                    recordRetryRecovery(indexKey, batch, result);
                    List<PreparedExportDocument> reQueue = filterTransientFailures(
                            batch, result.failedItems, result.successCount(), indexName, indexKey);
                    logRetryRecovery(indexKey, indexName, sent, reQueue.size());
                    // Do not recordBulkBreakdown here — that would re-count still-failed items.
                    ExportStats.recordRetryDrainBulkSuccess(indexKey, result.breakdown());
                    ExportStats.recordExportedBytes(indexKey, estimateSuccessfulBytes(batch, sent));
                    ExportStats.recordOpenSearchSuccess();
                    offerAllAccountingDrops(indexName, indexKey, reQueue);
                } else {
                    if (!OpenSearchPushCancellation.shouldSuppressFailureAccounting()) {
                        BatchSizeController.getInstance().recordFailure(batch.size());
                        BulkByteBudget.recordFailure();
                        ExportStats.recordOpenSearchFailure();
                    }
                    List<PreparedExportDocument> reQueue = filterTransientFailures(
                            batch, result.failedItems, result.successCount(), indexName, indexKey);
                    logRetryDrainFailure(indexKey, indexName, batch.size(), reQueue.size(), result);
                    offerAllAccountingDrops(indexName, indexKey, reQueue);
                }
            }
        }
    }

    /**
     * Returns the currently effective destination URL for retries.
     *
     * <p>Retry and drain paths should honor live runtime destination changes. This method
     * prefers runtime config and falls back to call-site URL when runtime has not been set.</p>
     */
    static String resolveBaseUrlForOperation(String fallbackBaseUrl) {
        String runtimeBaseUrl = RuntimeConfig.searchBaseUrl();
        if (runtimeBaseUrl != null && !runtimeBaseUrl.isBlank()) {
            return runtimeBaseUrl.trim();
        }
        if (fallbackBaseUrl == null) {
            return "";
        }
        return fallbackBaseUrl.trim();
    }

    private void noteAuthorizationFailureFromResult(
            String baseUrl,
            OpenSearchClientWrapper.BulkResult result) {
        if (result == null || result.failedItems == null || result.failedItems.isEmpty()) {
            return;
        }
        for (OpenSearchClientWrapper.FailedItem item : result.failedItems) {
            String reason = item.reason() == null ? "" : item.reason();
            if (reason.contains("status 401")) {
                noteHttpAuthorizationFailure(baseUrl, 401);
                return;
            }
            if (reason.contains("status 403")) {
                noteHttpAuthorizationFailure(baseUrl, 403);
                return;
            }
        }
    }

    private static SearchConnectionStatus testConnectionWithRuntimeConfig(String baseUrl) {
        return SearchConnectionTester.safeTestConnection(RuntimeConfig.searchDestinationKind(), baseUrl);
    }

    private void maybeLogDestinationChange(String baseUrl) {
        String previous = lastDrainBaseUrl;
        if (baseUrl.equals(previous)) {
            return;
        }
        lastDrainBaseUrl = baseUrl;
        if (previous != null && !previous.isBlank() && queue.totalSize() > 0) {
            Logger.logInfoPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                    + " Retry drain destination updated while backlog exists: "
                    + previous + " -> " + baseUrl);
        }
    }

    private String retryPressureContext() {
        return "retry_queue_total=" + queue.totalSize();
    }

    /**
     * Returns retry-queue depth for an index.
     *
     * @param indexName full index name
     * @return current non-negative document count
     */
    public int getQueueSize(String indexName) {
        return queue.size(indexName);
    }

    /**
     * Returns a non-destructive snapshot of documents currently queued for {@code indexName}.
     *
     * <p>Used by Stats traffic-source rows to attribute live Queued depth without dequeuing.</p>
     *
     * @param indexName full index name
     * @return immutable document list (never {@code null})
     */
    public List<PreparedExportDocument> snapshotQueuedDocuments(String indexName) {
        return queue.snapshotDocuments(indexName);
    }

    /**
     * Returns the enqueue timestamp (epoch ms) of the oldest queued document for the given index,
     * or {@code -1} when the queue is empty. Used by {@link ExportStats#getOldestQueuedAgeMs(String)}
     * to surface the {@code Oldest Queued Age} row on the Misc Stats panel.
     *
     * @param indexName full index name
     * @return enqueue epoch milliseconds, or {@code -1} when empty
     */
    public long getOldestQueuedEnqueuedAtMs(String indexName) {
        return queue.oldestEnqueuedAtMs(indexName);
    }

    /**
     * Returns the approximate total bytes of documents currently queued for retry on the given
     * index. Maintained incrementally on offer and dequeue; intended for low-frequency
     * observability callers (StatsPanel).
     *
     * @param indexName full index name
     * @return non-negative estimated bytes currently retained
     */
    public long getQueueBytesEstimate(String indexName) {
        return queue.bytesEstimate(indexName);
    }

    private static boolean waitBackoffDelay(int attempt) {
        long delayMs = BACKOFF_BASE_MS * (long) Math.pow(BACKOFF_MULTIPLIER, attempt - 1);
        return waitInterval(delayMs);
    }

    private static boolean waitInterval(long delayMs) {
        if (delayMs <= 0) {
            return !Thread.currentThread().isInterrupted();
        }
        long remainingNanos = TimeUnit.MILLISECONDS.toNanos(delayMs);
        long deadline = System.nanoTime() + remainingNanos;
        while (remainingNanos > 0) {
            LockSupport.parkNanos(remainingNanos);
            if (Thread.currentThread().isInterrupted()) {
                Thread.currentThread().interrupt();
                return false;
            }
            remainingNanos = deadline - System.nanoTime();
        }
        return true;
    }

    private static void recordRetryRecovery(
            String indexKey,
            List<PreparedExportDocument> batch,
            OpenSearchClientWrapper.BulkResult result) {
        if (result == null) {
            ExportStats.recordRetryRecovery(indexKey, 0);
            return;
        }
        int recovered = result.successCount();
        ExportStats.recordRetryRecovery(indexKey, recovered);
        if (!TrafficRouteBucket.INDEX_KEY.equals(indexKey) || recovered <= 0) {
            return;
        }
        RouteRecoveryAttribution attribution =
                recordTrafficRouteRecoveries(batch, result.failedItems, recovered);
        if (attribution.attributed() != recovered) {
            Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                    + " Traffic route attribution incomplete:"
                    + " recovered=" + recovered
                    + " attributed=" + attribution.attributed()
                    + " batch=" + (batch == null ? 0 : batch.size()) + ".");
        } else if (!attribution.routeSummary().isBlank()) {
            Logger.logInfoPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                    + " Traffic route Exported updated:"
                    + " " + attribution.routeSummary() + ".");
        }
    }

    /**
     * Attributes successful traffic retry items to the same source rows as their failed attempts.
     *
     * <p>Per-item failure indices identify successful request positions by exclusion. A whole-batch
     * success has no failure list and attributes every document. Ambiguous partial results are left
     * unattributed instead of guessing.</p>
     *
     * <p>Each recovered document increments both Recovered Failures and Exported (success) on the
     * matching traffic route so Stats source sub-rows stay aligned with the Traffic parent row.</p>
     *
     * @return attribution result with count and operator-facing route summary
     */
    static RouteRecoveryAttribution recordTrafficRouteRecoveries(
            List<PreparedExportDocument> batch,
            List<OpenSearchClientWrapper.FailedItem> failedItems,
            int expectedRecovered) {
        if (batch == null || batch.isEmpty() || expectedRecovered <= 0) {
            return RouteRecoveryAttribution.none();
        }
        boolean[] failed = new boolean[batch.size()];
        int validFailed = 0;
        if (failedItems != null) {
            for (OpenSearchClientWrapper.FailedItem item : failedItems) {
                int index = item.index();
                if (index >= 0 && index < failed.length && !failed[index]) {
                    failed[index] = true;
                    validFailed++;
                }
            }
        }
        if (batch.size() - validFailed != expectedRecovered) {
            return RouteRecoveryAttribution.none();
        }
        Map<String, Integer> byRouteLabel = new LinkedHashMap<>();
        int attributed = 0;
        for (int i = 0; i < batch.size(); i++) {
            if (!failed[i]) {
                TrafficRouteBucket.Route route = TrafficRouteBucket.fromDocument(batch.get(i).document());
                TrafficRouteBucket.recordOpenSearchRecovery(route, 1);
                // Also bump route Exported so Proxy History / tool-type sub-rows match parent Traffic.
                TrafficRouteBucket.recordOpenSearchSuccess(route, 1);
                byRouteLabel.merge(trafficRouteLabel(route), 1, (left, right) -> left + right);
                attributed++;
            }
        }
        return new RouteRecoveryAttribution(attributed, formatRouteCounts(byRouteLabel));
    }

    /**
     * Result of attributing retry-drain recoveries to traffic source / tool-type rows.
     *
     * @param attributed number of documents attributed to routes
     * @param routeSummary compact {@code label=count} list for logs; empty when none
     */
    record RouteRecoveryAttribution(int attributed, String routeSummary) {
        static RouteRecoveryAttribution none() {
            return new RouteRecoveryAttribution(0, "");
        }
    }

    private static String trafficRouteLabel(TrafficRouteBucket.Route route) {
        if (route == null) {
            return "unknown";
        }
        if (route.kind() == TrafficRouteBucket.Kind.SOURCE) {
            return switch (route.key()) {
                case TrafficRouteBucket.SOURCE_PROXY_HISTORY_SNAPSHOT -> "Proxy History";
                case TrafficRouteBucket.SOURCE_PROXY_WEBSOCKET -> "Proxy WebSocket";
                default -> route.key();
            };
        }
        String key = route.key() == null ? "UNKNOWN" : route.key().trim();
        if (key.isEmpty()) {
            return "unknown";
        }
        String[] parts = key.toLowerCase(Locale.ROOT).split("_");
        StringBuilder label = new StringBuilder();
        for (String part : parts) {
            if (part.isEmpty()) {
                continue;
            }
            if (label.length() > 0) {
                label.append(' ');
            }
            label.append(Character.toUpperCase(part.charAt(0)));
            if (part.length() > 1) {
                label.append(part.substring(1));
            }
        }
        return label.length() == 0 ? key : label.toString();
    }

    private static String formatRouteCounts(Map<String, Integer> byRouteLabel) {
        if (byRouteLabel == null || byRouteLabel.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Integer> entry : byRouteLabel.entrySet()) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(entry.getKey()).append('=').append(entry.getValue());
        }
        return sb.toString();
    }

    /**
     * Returns whether every unsuccessful document in {@code result} is a permanent local/server
     * size failure (no HTTP capacity signal).
     *
     * <p>Search senders no longer emit size Permanent Drops locally; this still recognizes
     * legacy or server-reported item failures of that type.</p>
     */
    static boolean isOnlyDocumentTooLargeOutcome(
            List<PreparedExportDocument> documents,
            OpenSearchClientWrapper.BulkResult result) {
        if (documents == null || documents.isEmpty() || result == null) {
            return false;
        }
        int success = result.successCount();
        if (success >= documents.size()) {
            return false;
        }
        List<OpenSearchClientWrapper.FailedItem> failedItems = result.failedItems;
        if (failedItems == null || failedItems.isEmpty()) {
            return false;
        }
        int expectedFailures = documents.size() - success;
        if (failedItems.size() < expectedFailures) {
            return false;
        }
        for (OpenSearchClientWrapper.FailedItem item : failedItems) {
            String type = item.type() == null ? "" : item.type();
            if (BulkErrorClassification.of(item.type()) != BulkErrorClassification.PERMANENT
                    || (!BulkErrorClassification.DOCUMENT_TOO_LARGE_TYPE.equalsIgnoreCase(type)
                            && !BulkErrorClassification.SEARCH_MAX_BUDGET_EXCEEDED_TYPE.equalsIgnoreCase(type))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Partitions failed bulk items into transient (re-queued) and permanent (dropped) sets.
     *
     * <p>Transient failures (cluster backpressure, 429s, timeouts, unknown types) are returned as
     * the re-queue list so the drain thread tries them again. Permanent failures (mapping and
     * parse errors - see {@link BulkErrorClassification}) are counted via
     * {@link ExportStats#recordPermanentDrop(String, long)} and otherwise discarded.</p>
     *
     * <p>When per-item detail is absent or does not exactly identify every claimed failure, the
     * whole batch is transient. Stable operation IDs make retrying all documents idempotent, while
     * guessing which aggregate successes occurred could lose data.</p>
     *
     * <p>Package-private for direct testing of the poison-pill branch.</p>
     */
    static List<PreparedExportDocument> filterTransientFailures(
            List<PreparedExportDocument> batch,
            List<OpenSearchClientWrapper.FailedItem> failedItems,
            int knownSuccessCount,
            String indexName,
            String indexKey) {
        if (batch == null || batch.isEmpty()) {
            return new ArrayList<>();
        }
        int clampedSuccess = Math.max(0, Math.min(batch.size(), knownSuccessCount));
        int expectedFailures = batch.size() - clampedSuccess;
        if (expectedFailures == 0) {
            return new ArrayList<>();
        }
        if (!hasCompleteExactFailureSet(failedItems, expectedFailures, batch.size())) {
            return new ArrayList<>(batch);
        }
        List<PreparedExportDocument> toRetry = new ArrayList<>();
        int permanentCount = 0;
        int maximumFitCount = 0;
        int mappingCount = 0;
        List<PreparedExportDocument> permanentDocs = new ArrayList<>();
        List<PreparedExportDocument> maximumFitDocs = new ArrayList<>();
        String capacityDetail = null;
        for (OpenSearchClientWrapper.FailedItem item : failedItems) {
            int idx = item.index();
            if (BulkErrorClassification.of(item.type()) == BulkErrorClassification.PERMANENT) {
                PreparedExportDocument document = batch.get(idx);
                permanentCount++;
                permanentDocs.add(document);
                if (BulkErrorClassification.SEARCH_MAX_BUDGET_EXCEEDED_TYPE.equalsIgnoreCase(
                        item.type() == null ? "" : item.type())) {
                    maximumFitCount++;
                    maximumFitDocs.add(document);
                } else {
                    mappingCount++;
                }
            } else {
                toRetry.add(batch.get(idx));
                if (capacityDetail == null
                        && BulkRateLimitBackoff.isItemCapacityPressure(item.type(), item.reason())) {
                    capacityDetail = item.type() + ": " + item.reason();
                }
            }
        }
        if (permanentCount > 0) {
            ExportStats.recordPermanentDrop(indexKey, permanentCount);
            attributeTrafficRoutePermanentDrops(indexKey, permanentDocs);
            if (maximumFitCount > 0) {
                ExportStats.recordPermanentDropReason(
                        ExportStats.PERMANENT_DROP_REASON_MAX_FIT, maximumFitCount);
                for (PreparedExportDocument document : maximumFitDocs) {
                    logMaximumFitPermanentDrop(indexName, indexKey, document);
                }
            }
            if (mappingCount > 0) {
                ExportStats.recordPermanentDropReason(
                        ExportStats.PERMANENT_DROP_REASON_MAPPING, mappingCount);
                Logger.logErrorPanelOnly(RuntimeConfig.searchDestinationLogPrefix() + " Dropped " + mappingCount
                        + " permanently rejected document(s) from retry for index " + indexName + ".");
            }
        }
        if (capacityDetail != null) {
            // HTTP 200 + per-item throttle (common on Amazon Serverless) still needs shared cooldown.
            BulkRateLimitBackoff.noteItemCapacityPressure(indexName, "Bulk item", capacityDetail);
        }
        return toRetry;
    }

    private static boolean hasCompleteExactFailureSet(
            List<OpenSearchClientWrapper.FailedItem> failedItems,
            int expectedFailures,
            int attemptedCount) {
        if (failedItems == null || failedItems.size() != expectedFailures) {
            return false;
        }
        boolean[] seen = new boolean[Math.max(0, attemptedCount)];
        for (OpenSearchClientWrapper.FailedItem item : failedItems) {
            if (item == null
                    || item.index() < 0
                    || item.index() >= attemptedCount
                    || seen[item.index()]) {
                return false;
            }
            seen[item.index()] = true;
        }
        return true;
    }

    private static void recordCurrentPermanentDrops(
            String indexKey,
            List<PreparedExportDocument> documents,
            String reason) {
        if (documents == null || documents.isEmpty()) {
            return;
        }
        List<PreparedExportDocument> nonNull = new ArrayList<>(documents.size());
        for (PreparedExportDocument document : documents) {
            if (document != null) {
                nonNull.add(document);
            }
        }
        if (nonNull.isEmpty()) {
            return;
        }
        String key = indexKey;
        if (key == null || key.isBlank()) {
            key = nonNull.get(0).indexKey();
        }
        if (key == null || key.isBlank()) {
            key = "unknown";
        }
        ExportStats.recordPermanentDrop(key, nonNull.size());
        ExportStats.recordPermanentDropReason(
                permanentDropReasonForLifecycle(reason), nonNull.size());
        attributeTrafficRoutePermanentDrops(key, nonNull);
        Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                + " Accounted " + nonNull.size()
                + " current failed document(s) as Permanent Drops: "
                + (reason == null || reason.isBlank() ? "retry unavailable" : reason) + ".");
    }

    private static void logMaximumFitPermanentDrop(
            String indexName,
            String indexKey,
            PreparedExportDocument document) {
        PreparedExportDocument fitted = SearchBodyPrefixFitter.fitToBudget(
                document, BulkByteBudget.ADAPTIVE_MAX_BYTES);
        String resolvedIndex = indexName == null || indexName.isBlank()
                ? document.indexName()
                : indexName;
        String resolvedKey = indexKey == null || indexKey.isBlank()
                ? document.indexKey()
                : indexKey;
        Logger.logErrorPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                + " Permanently rejected search document that cannot fit the absolute bulk ceiling:"
                + " index=" + (resolvedIndex == null || resolvedIndex.isBlank() ? "unknown" : resolvedIndex)
                + " indexKey=" + (resolvedKey == null || resolvedKey.isBlank() ? "unknown" : resolvedKey)
                + " operationId="
                + (document.operationId() == null || document.operationId().isBlank()
                        ? "unknown"
                        : document.operationId())
                + " requestUrl=" + SearchBodyPrefixFitter.diagnosticRequestUrl(document)
                + " originalBytes=" + document.resolvedBulkBytes()
                + " fittedBytes=" + fitted.resolvedBulkBytes()
                + " absoluteMaxBytes=" + BulkByteBudget.ADAPTIVE_MAX_BYTES
                + " reason=" + ExportStats.PERMANENT_DROP_REASON_MAX_FIT
                + " (search path only; Files copy remains unchanged).");
    }

    private static String permanentDropReasonForLifecycle(String detail) {
        String normalized = detail == null ? "" : detail.toLowerCase(Locale.ROOT);
        if (normalized.contains("stop") || normalized.contains("shutdown")) {
            return ExportStats.PERMANENT_DROP_REASON_STOP;
        }
        if (normalized.contains("destination")
                || normalized.contains("search url")
                || normalized.contains("not ready")) {
            return ExportStats.PERMANENT_DROP_REASON_DESTINATION;
        }
        return ExportStats.PERMANENT_DROP_REASON_OTHER;
    }

    private static OpenSearchClientWrapper.BulkResult transientFailureResult(
            int attemptedCount, String reason) {
        List<OpenSearchClientWrapper.FailedItem> failedItems =
                new ArrayList<>(Math.max(0, attemptedCount));
        for (int index = 0; index < attemptedCount; index++) {
            failedItems.add(new OpenSearchClientWrapper.FailedItem(
                    index, "transient_lifecycle_failure", reason));
        }
        return new OpenSearchClientWrapper.BulkResult(
                BulkOutcomeBreakdown.classified(0, attemptedCount), failedItems);
    }

    /**
     * Offers documents to the retry queue and records Retry Drops (index + traffic route) for any
     * that are rejected when the queue is full.
     */
    private void offerAllAccountingDrops(
            String indexName, String indexKey, List<PreparedExportDocument> documents) {
        if (documents == null || documents.isEmpty()) {
            return;
        }
        int added = queue.offerAll(indexName, documents);
        if (added < documents.size()) {
            List<PreparedExportDocument> dropped = documents.subList(added, documents.size());
            recordRetryQueueDrops(indexKey, dropped);
            RETRY_PRESSURE_LOGS.record(
                    "retry_queue_full." + indexKey, dropped.size(), this::retryPressureContext);
        }
    }

    /**
     * Records index-level and traffic-route Retry Drops for documents rejected from the retry queue.
     *
     * @param indexKey short index key
     * @param dropped documents that were not accepted; {@code null}/empty ignored
     */
    static void recordRetryQueueDrops(String indexKey, List<PreparedExportDocument> dropped) {
        if (dropped == null || dropped.isEmpty()) {
            return;
        }
        ExportStats.recordRetryQueueDrop(indexKey, dropped.size());
        if (!"traffic".equalsIgnoreCase(indexKey)) {
            return;
        }
        for (PreparedExportDocument doc : dropped) {
            if (doc == null) {
                continue;
            }
            TrafficRouteBucket.recordOpenSearchRetryQueueDrop(
                    TrafficRouteBucket.fromDocument(doc.document()), 1);
        }
    }

    /**
     * Attributes permanent drops to traffic display sources when {@code indexKey} is traffic.
     *
     * @param indexKey short index key
     * @param docs permanently dropped documents; {@code null}/empty ignored
     */
    static void attributeTrafficRoutePermanentDrops(String indexKey, List<PreparedExportDocument> docs) {
        if (!"traffic".equalsIgnoreCase(indexKey) || docs == null || docs.isEmpty()) {
            return;
        }
        for (PreparedExportDocument doc : docs) {
            if (doc == null) {
                continue;
            }
            TrafficRouteBucket.recordOpenSearchPermanentDrop(
                    TrafficRouteBucket.fromDocument(doc.document()), 1);
        }
    }

    private static long estimateSuccessfulBytes(List<PreparedExportDocument> batch, int successCount) {
        if (batch == null || batch.isEmpty() || successCount <= 0) {
            return 0;
        }
        long total = 0;
        for (PreparedExportDocument doc : batch) {
            total += doc.estimatedBulkBytes();
        }
        return Math.round((double) total * successCount / batch.size());
    }
}
