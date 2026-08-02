package ai.anomalousvectors.tools.burp.sinks;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import ai.anomalousvectors.tools.burp.utils.ExportAdmissionController;
import ai.anomalousvectors.tools.burp.utils.ExportPressureLogThrottler;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;
import ai.anomalousvectors.tools.burp.utils.opensearch.BatchSizeController;
import ai.anomalousvectors.tools.burp.utils.opensearch.BulkByteBudget;
import ai.anomalousvectors.tools.burp.utils.opensearch.ChunkedBulkSender;
import ai.anomalousvectors.tools.burp.utils.opensearch.IndexingRetryCoordinator;

/**
 * Bounded queue for traffic documents so the HTTP thread can enqueue and return immediately.
 *
 * <p>Documents are prepared once at {@link #offer(Map)} into {@link TrafficQueueEntry}. A
 * dedicated worker thread drains the queue and pushes via the OpenSearch Bulk API using chunked
 * request body (NDJSON written incrementally; no full batch list in memory). In-memory capacity is
 * heap-headroom byte-based ({@link ExportAdmissionController}); when memory pressure rises or the
 * destination is in Soft Outage/cooldown, documents spill to a temp-dir file queue. New live
 * traffic is rejected only when spill is actually full or low on disk, preserving the earliest
 * backlog. Batches
 * are limited by count ({@link BatchSizeController}), payload size
 * ({@link BulkByteBudget}, typically 5 MiB; Amazon starts near 1 MiB), and time (flush after
 * 100 ms). Used by live HTTP and live non-proxy WebSocket export paths.</p>
 */
public final class TrafficExportQueue {

    private static final int CAPACITY = ExportAdmissionController.MEM_DOC_SAFETY_RAIL;
    private static final long POLL_TIMEOUT_MS = 50;
    private static final long BATCH_MAX_WAIT_MS = 100;
    private static final long STARTUP_GRACE_MAX_MS = 2_000;
    private static final long STARTUP_POLL_MS = 25;
    private static final int START_DRAIN_BACKLOG_DOCS = 64;
    private static final int SPILL_REFILL_TARGET_DOCS = 256;

    private static final MeteredQueue queue = new MeteredQueue(CAPACITY);
    private static final TrafficSpillFileQueue spillQueue = new TrafficSpillFileQueue();
    private static final AtomicBoolean workerStarted = new AtomicBoolean(false);
    private static final AtomicLong workerGeneration = new AtomicLong();
    private static final AtomicLong stopThroughGeneration = new AtomicLong();
    private static final AtomicInteger activeDrainBatches = new AtomicInteger();
    private static final AtomicLong queueBytesHeld = new AtomicLong();
    private static final ExportPressureLogThrottler OVERFLOW_LOGS =
            new ExportPressureLogThrottler("TrafficExportQueue");

    /**
     * Reference to the drain worker so shutdown can interrupt and join it deterministically.
     *
     * <p>Single-owner field; swapped under a class lock in {@link #stopWorker()} and lazily
     * recreated by {@link #startWorkerIfNeeded()} on the next {@link #offer(Map)}.</p>
     */
    private static volatile Thread drainWorker;

    /**
     * When {@code true}, {@link #offer(Map)} may queue documents but does not start the drain worker.
     * Used by unit tests that assert in-memory queue depth without racing the background drainer.
     */
    private static volatile boolean drainDisabledForTests;
    private static final long WORKER_GRACEFUL_SHUTDOWN_TIMEOUT_MS = 30_000;
    private static final long WORKER_INTERRUPT_SHUTDOWN_TIMEOUT_MS = 1_000;

    private TrafficExportQueue() {}

    static {
        long recoveredDocs = spillQueue.recoveredCount();
        if (recoveredDocs > 0) {
            long recoveredBytes = spillQueue.recoveredBytes();
            ExportStats.recordTrafficSpillRecovered(recoveredDocs);
            Logger.logInfoPanelOnly("[TrafficExportQueue] Recovered " + recoveredDocs
                    + " spill docs (" + recoveredBytes + " bytes) from " + spillQueue.directoryPath());
        }
    }

    /**
     * Returns the current number of documents in the traffic export queue.
     *
     * @return number of documents currently queued (for stats and Exporter-index observability)
     */
    public static int getCurrentSize() {
        return queue.size();
    }

    /**
     * Suppresses drain-worker startup until reset. For unit tests in this package only.
     *
     * @param disabled {@code true} to keep offers on the in-memory queue without draining
     */
    static void setDrainDisabledForTests(boolean disabled) {
        drainDisabledForTests = disabled;
        if (disabled) {
            stopWorker();
        }
    }

    /**
     * Returns the approximate total bytes of documents currently held in the in-memory queue.
     *
     * <p>Maintained incrementally on offer and dequeue. Does not include spilled documents;
     * those are tracked by {@link #getCurrentSpillBytes()}.</p>
     */
    public static long getCurrentBytesEstimate() {
        return Math.max(0L, queueBytesHeld.get());
    }

    /**
     * Recomputes in-memory queue bytes by walking the queue. Package-private for unit tests that
     * verify the maintained counter matches a full iteration.
     */
    static long computeBytesEstimateByWalk() {
        if (queue.isEmpty()) {
            return 0L;
        }
        long total = 0L;
        for (TrafficQueueEntry entry : queue) {
            total += entry.prepared().estimatedBulkBytes();
        }
        return total;
    }

    private static void recordDequeuedBytes(TrafficQueueEntry entry) {
        if (entry != null) {
            queueBytesHeld.addAndGet(-entry.prepared().estimatedBulkBytes());
        }
    }

    /** Returns current spill queue depth for StatsPanel observability. */
    public static int getCurrentSpillSize() {
        return spillQueue.size();
    }

    /** Returns current spill queue bytes for StatsPanel observability. */
    public static long getCurrentSpillBytes() {
        return spillQueue.bytes();
    }

    /** Returns oldest spill age in milliseconds (0 when no spilled docs). */
    public static long getCurrentSpillOldestAgeMs() {
        return spillQueue.oldestAgeMs();
    }

    /**
     * Returns the effective Traffic Spill byte budget (disk headroom + absolute ceiling).
     *
     * @return current spill capacity in bytes, always at least one
     */
    public static long currentSpillBudgetBytes() {
        return spillQueue.effectiveBudgetBytes();
    }

    /**
     * Returns whether spill can still accept approximately one more document.
     *
     * <p>This is a non-writing capacity and disk-headroom probe; a later append may still race
     * with other producers or changing disk space.</p>
     *
     * @return {@code true} when spill is not currently at its file, byte, or disk-space limit
     */
    public static boolean isSpillAccepting() {
        return spillQueue.canAcceptBytes(1L);
    }

    /**
     * Returns Overview Traffic Spill status ({@code Ready} / {@code In use} / {@code Full}).
     *
     * @return current operator-facing spill state
     */
    public static ExportAdmissionController.SpillStatus currentSpillStatus() {
        return ExportAdmissionController.currentSpillStatus();
    }

    /** Returns startup-recovered spill document count. */
    public static long getRecoveredSpillCount() {
        return spillQueue.recoveredCount();
    }

    /** Returns startup-recovered spill byte count. */
    public static long getRecoveredSpillBytes() {
        return spillQueue.recoveredBytes();
    }

    /** Returns currently active drain batches. */
    public static int getActiveDrainBatches() {
        return activeDrainBatches.get();
    }

    /** Returns spill directory path for diagnostics. */
    public static String getSpillDirectoryPath() {
        return spillQueue.directoryPath();
    }

    /**
     * Waits until queued traffic work has drained or the timeout elapses.
     *
     * <p>Idle means the in-memory queue and spill queue are empty and no drain batch is currently
     * applying file or OpenSearch accounting. Callers must not invoke this on the EDT.</p>
     *
     * @param timeoutMs maximum time to wait in milliseconds
     * @return {@code true} if traffic export became idle before the timeout
     */
    public static boolean awaitIdle(long timeoutMs) {
        long deadlineNs = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(Math.max(0L, timeoutMs));
        while (true) {
            if (isIdle()) {
                return true;
            }
            if (System.nanoTime() >= deadlineNs) {
                return false;
            }
            try {
                TimeUnit.MILLISECONDS.sleep(STARTUP_POLL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
    }

    /**
     * Offers a traffic document to the queue. Non-blocking.
     *
     * <p>When memory pressure rises the document is spilled. When spill rejects it (Full / low
     * disk), the new document is rejected so the earliest backlog stays contiguous. Starts the
     * drain worker on first use. Thread-safe.</p>
     *
     * @param document the document to enqueue; {@code null} is ignored
     */
    public static void offer(Map<String, Object> document) {
        offerAccepted(document);
    }

    /**
     * Offers a traffic document when export sinks are active.
     *
     * @param document document to enqueue; {@code null} is ignored
     * @return {@code true} when the document was queued or spilled; {@code false} when it was dropped
     */
    public static boolean offerAccepted(Map<String, Object> document) {
        if (document == null) {
            return false;
        }
        if (!isDocumentCurrentlyEnabled(document)) {
            return false;
        }
        if (!spillQueue.canAcceptBytes(1L)
                && !ExportAdmissionController.memAccepts(queueBytesHeld.get(), 1L)) {
            ExportAdmissionController.noteSpillFullReject();
            ExportStats.recordTrafficQueueDrop(1);
            ExportStats.recordTrafficSpillDrop(1);
            ExportStats.recordTrafficDropReason("spill_full_reject_new", 1);
            OVERFLOW_LOGS.record("spill_full_reject_new", 1, TrafficExportQueue::overflowContext);
            return false;
        }
        TrafficQueueEntry entry = TrafficQueueEntry.from(document);
        if (entry == null) {
            return false;
        }
        long docBytes = entry.prepared() != null ? entry.prepared().estimatedBulkBytes() : 1L;
        long held = queueBytesHeld.get();
        boolean preferSpill = ExportAdmissionController.shouldForceLiveTrafficToSpill()
                || ExportAdmissionController.shouldPreferSpill(held, docBytes);
        if (!preferSpill
                && queue.offerWithinBudget(entry)) {
            startWorkerIfNeeded();
            return true;
        }
        TrafficSpillFileQueue.OfferResult spillResult = spillQueue.offerDetailed(entry);
        if (spillResult == TrafficSpillFileQueue.OfferResult.QUEUED) {
            ExportStats.recordTrafficSpillEnqueued(1);
            OVERFLOW_LOGS.record("spill_queued", 1, TrafficExportQueue::overflowContext);
            startWorkerIfNeeded();
            return true;
        }
        // Spill Full / low disk: reject the new document; never drop-oldest.
        ExportAdmissionController.noteSpillFullReject();
        ExportStats.recordTrafficQueueDrop(1);
        ExportStats.recordTrafficSpillDrop(1);
        String dropReason = spillResult == TrafficSpillFileQueue.OfferResult.REJECTED_LOW_DISK
                ? "spill_low_disk_reject_new"
                : "spill_full_reject_new";
        ExportStats.recordTrafficDropReason(dropReason, 1);
        OVERFLOW_LOGS.record(dropReason, 1, TrafficExportQueue::overflowContext);
        return false;
    }

    static boolean offerPreparedForTests(PreparedExportDocument document) {
        TrafficQueueEntry entry = TrafficQueueEntry.fromPrepared(document);
        if (entry == null) {
            return false;
        }
        if (queue.offerWithinBudget(entry)) {
            startWorkerIfNeeded();
            return true;
        }
        return false;
    }

    /**
     * Clears in-memory and spilled traffic backlog.
     *
     * <p>Used when export is intentionally stopped or a Start attempt fails, so queued traffic
     * does not resume behind a stopped UI.</p>
     */
    public static void clearPendingWork() {
        queue.clear();
        spillQueue.clear();
    }

    /**
     * Removes queued traffic whose route is no longer enabled by the current traffic gate.
     *
     * <p>Used for live config deselection. Stop still calls {@link #clearPendingWork()} because
     * all queued traffic is stale after the run ends.</p>
     *
     * @param gate current runtime traffic gate
     * @return number of queued or spilled documents removed
     */
    public static int purgeDisabledTraffic(RuntimeConfig.TrafficExportGate gate) {
        if (gate == null || !gate.anyTrafficExportEnabled()) {
            int purged = queue.size() + spillQueue.size();
            clearPendingWork();
            return purged;
        }
        AtomicInteger purged = new AtomicInteger();
        queue.removeIf(entry -> {
            boolean remove = !TrafficRouteBucket.isRouteEnabled(
                    TrafficRouteBucket.fromDocument(entry.document()), gate);
            if (remove) {
                purged.incrementAndGet();
            }
            return remove;
        });
        purged.addAndGet(spillQueue.removeIf(
                doc -> !TrafficRouteBucket.isRouteEnabled(TrafficRouteBucket.fromDocument(doc), gate)));
        return purged.get();
    }

    private static void startWorkerIfNeeded() {
        if (drainDisabledForTests) {
            return;
        }
        if (workerStarted.compareAndSet(false, true)) {
            long generation = workerGeneration.incrementAndGet();
            Thread t = new Thread(() -> TrafficExportQueue.drainLoop(generation), "burp-exporter-traffic-export");
            t.setDaemon(true);
            synchronized (TrafficExportQueue.class) {
                drainWorker = t;
            }
            t.start();
        }
    }

    /**
     * Asks the drain worker to stop after the current batch, then joins it.
     *
     * <p>Safe to call from any thread and safe to call more than once. Resets the start flag so
     * the next {@link #offer(Map)} lazily starts a fresh worker. The normal path does not
     * interrupt the worker: if a bulk request is already in flight, it is allowed to complete.
     * If the worker does not stop within the graceful window, interrupt is used as a bounded
     * fallback so extension unload cannot hang indefinitely.</p>
     */
    public static void stopWorker() {
        stopWorker(WORKER_GRACEFUL_SHUTDOWN_TIMEOUT_MS + WORKER_INTERRUPT_SHUTDOWN_TIMEOUT_MS);
    }

    /**
     * Stops the drain worker within one shared wall-clock budget.
     *
     * <p>Most of the budget is graceful; up to the final second is reserved for interrupt and join
     * cleanup. A non-positive budget requests interruption without waiting. Safe to call from any
     * thread and more than once.</p>
     *
     * @param timeoutMs total graceful-plus-interrupt budget in milliseconds
     */
    public static void stopWorker(long timeoutMs) {
        long budgetMs = Math.max(0L, timeoutMs);
        long deadlineNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(budgetMs);
        long generationToStop = workerGeneration.get();
        stopThroughGeneration.updateAndGet(current -> Math.max(current, generationToStop));
        Thread worker;
        synchronized (TrafficExportQueue.class) {
            worker = drainWorker;
        }
        if (worker != null && worker != Thread.currentThread()) {
            long interruptReserveMs = Math.min(WORKER_INTERRUPT_SHUTDOWN_TIMEOUT_MS, budgetMs);
            long gracefulMs = Math.max(0L, budgetMs - interruptReserveMs);
            awaitWorker(worker, gracefulMs, false);
            if (worker.isAlive()) {
                Logger.logWarnPanelOnly("[TrafficExportQueue] Stop timed out waiting for current batch; interrupting worker.");
                long remainingNanos = deadlineNanos - System.nanoTime();
                long remainingMs = remainingNanos <= 0L
                        ? 0L
                        : TimeUnit.NANOSECONDS.toMillis(remainingNanos);
                awaitWorker(worker, remainingMs, true);
            }
        }
        if (worker != null && worker.isAlive()) {
            return;
        }
        boolean currentOwner = false;
        synchronized (TrafficExportQueue.class) {
            if (drainWorker == worker) {
                drainWorker = null;
                currentOwner = true;
            }
        }
        if (currentOwner) {
            workerStarted.set(false);
        }
    }

    private static void drainLoop(long generation) {
        try {
            if (!awaitInitialWarmup(generation)) {
                return;
            }
            BatchSizeController batchController = BatchSizeController.getInstance();
            while (true) {
                if (isStopRequested(generation)) {
                    break;
                }
                RuntimeConfig.TrafficExportGate trafficGate = RuntimeConfig.trafficExportGate();
                boolean openSearchEnabled = RuntimeConfig.isSearchTrafficEnabled();
                String baseUrl = openSearchEnabled ? RuntimeConfig.searchBaseUrl() : "";
                if (!RuntimeConfig.isExportReady() || !trafficGate.anyTrafficExportEnabled()) {
                    try {
                        TimeUnit.MILLISECONDS.sleep(POLL_TIMEOUT_MS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                    continue;
                }
                if (IndexingRetryCoordinator.getInstance().isAuthorizationRecoveryPaused()) {
                    try {
                        TimeUnit.MILLISECONDS.sleep(POLL_TIMEOUT_MS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                    continue;
                }
                if (baseUrl == null || baseUrl.isBlank()) {
                    if (!RuntimeConfig.isAnyFileExportEnabled()) {
                        try {
                            TimeUnit.MILLISECONDS.sleep(POLL_TIMEOUT_MS);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                        continue;
                    }
                    int maxBatch = batchController.getCurrentBatchSize();
                    long maxBytes = BulkByteBudget.currentMaxBytes();
                    refillFromSpill(Math.max(SPILL_REFILL_TARGET_DOCS, maxBatch));
                    activeDrainBatches.incrementAndGet();
                    try {
                        FileOnlyDrainResult result = drainToFileOnly(maxBatch, maxBytes);
                        if (result.attemptedCount == 0) {
                            continue;
                        }
                        batchController.recordSuccess(result.attemptedCount);
                    } finally {
                        activeDrainBatches.decrementAndGet();
                    }
                    continue;
                }

                int maxBatch = batchController.getCurrentBatchSize();
                long maxBytes = BulkByteBudget.currentMaxBytes();
                refillFromSpill(Math.max(SPILL_REFILL_TARGET_DOCS, maxBatch));
                long startNs = System.nanoTime();
                activeDrainBatches.incrementAndGet();
                try {
                    ChunkedBulkSender.Result result = ChunkedBulkSender.push(
                            baseUrl, TrafficRouteBucket.trafficIndexName(), TrafficRouteBucket.INDEX_KEY,
                            queue, maxBatch, maxBytes, BATCH_MAX_WAIT_MS);
                    long durationMs = (System.nanoTime() - startNs) / 1_000_000;

                    if (result.attemptedCount == 0) {
                        continue;
                    }
                    applyBulkOutcome(result, durationMs, maxBatch);
                    if (result.isFullSuccess()) {
                        batchController.recordSuccess(result.attemptedCount);
                        IndexingRetryCoordinator.getInstance().noteFullPayloadBulkSuccess(
                                TrafficRouteBucket.INDEX_KEY,
                                result.successBytes > 0
                                        ? result.successBytes
                                        : result.attemptedBytes);
                    } else {
                        batchController.recordFailure(result.attemptedCount);
                        BulkByteBudget.recordFailure();
                    }
                } finally {
                    activeDrainBatches.decrementAndGet();
                }
            }
        } finally {
            boolean currentOwner = false;
            synchronized (TrafficExportQueue.class) {
                if (drainWorker == Thread.currentThread()) {
                    drainWorker = null;
                    currentOwner = true;
                }
            }
            if (currentOwner) {
                workerStarted.set(false);
                if (!queue.isEmpty() && RuntimeConfig.isExportReady() && !drainDisabledForTests) {
                    startWorkerIfNeeded();
                }
            }
        }
    }

    private static boolean isStopRequested(long generation) {
        return generation <= stopThroughGeneration.get();
    }

    private static boolean isIdle() {
        return queue.isEmpty() && spillQueue.size() == 0 && activeDrainBatches.get() == 0;
    }

    private static void awaitWorker(Thread worker, long timeoutMs, boolean interrupt) {
        if (interrupt) {
            worker.interrupt();
        }
        if (timeoutMs <= 0L) {
            return;
        }
        try {
            worker.join(timeoutMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Applies index-level and per-route accounting for a streaming bulk push outcome.
     *
     * <p>Package-private for unit-test access; production callers invoke it from
     * {@link #drainLoop()} once per completed bulk. Delegates index-level counters and the
     * panel-warn/last-error on partial failure to
     * {@link BulkOutcomeRecorder#record(String, String, String, int, int, boolean)}, then
     * layers per-tool-type and per-source counts derived from {@link ChunkedBulkSender.Result}.
     * {@link BulkOutcomeRecorder} already clamps {@code sent} to {@code [0, attempted]}; the
     * per-route failure maps only apply when the clamped success count is below the attempted
     * total.</p>
     */
    static void applyBulkOutcome(ChunkedBulkSender.Result result, long durationMs, int targetBatch) {
        BulkOutcomeRecorder.RecordResult recorded = BulkOutcomeRecorder.recordDetailed(
                TrafficRouteBucket.INDEX_KEY, "Traffic", "Bulk push",
                result.attemptedCount, result.successCount, true, result.breakdown);
        ExportStats.recordLastLiveBulkDurationMs(TrafficRouteBucket.INDEX_KEY, durationMs);
        BulkByteBudget.recordBulkLatency(durationMs);
        ExportStats.recordLastLiveBulkShape(targetBatch, result.attemptedCount);
        ExportStats.recordExportedBytes(TrafficRouteBucket.INDEX_KEY, result.successBytes);
        result.trafficToolTypeSuccessCounts.forEach(
                (toolTypeKey, count) -> ExportStats.recordTrafficToolTypeSuccess(toolTypeKey, count.longValue()));
        result.trafficSourceSuccessCounts.forEach(
                (sourceKey, count) -> ExportStats.recordTrafficSourceSuccess(sourceKey, count.longValue()));
        if (!recorded.failuresSuppressed() && recorded.sent() < result.attemptedCount) {
            result.trafficToolTypeFailureCounts.forEach(
                    (toolTypeKey, count) -> ExportStats.recordTrafficToolTypeFailure(toolTypeKey, count.longValue()));
            result.trafficSourceFailureCounts.forEach(
                    (sourceKey, count) -> ExportStats.recordTrafficSourceFailure(sourceKey, count.longValue()));
        }
    }

    /**
     * Moves a bounded number of spilled docs back to memory queue before sending.
     *
     * <p>Drains only while memory queue has room and admission allows refill. Paused under Soft
     * Outage cooldown. Once cooldown expires, bounded refill resumes so spill-only backlog can
     * provide a governor-paced recovery canary. Stops on first enqueue failure.</p>
     *
     * @param targetDocs desired minimum queued docs before bulk send
     */
    private static void refillFromSpill(int targetDocs) {
        if (!ExportAdmissionController.shouldRefillFromSpill()) {
            return;
        }
        while (queue.size() < targetDocs) {
            if (!ExportAdmissionController.shouldRefillFromSpill()) {
                return;
            }
            TrafficQueueEntry entry = spillQueue.pollEntry();
            if (entry == null) {
                return;
            }
            if (!isDocumentCurrentlyEnabled(entry.document())) {
                continue;
            }
            if (!queue.offerWithinBudget(entry)) {
                TrafficSpillFileQueue.OfferResult spillResult = spillQueue.offerDetailed(entry);
                if (spillResult != TrafficSpillFileQueue.OfferResult.QUEUED) {
                    ExportStats.recordTrafficQueueDrop(1);
                    ExportStats.recordTrafficSpillDrop(1);
                    String dropReason = spillResult == TrafficSpillFileQueue.OfferResult.REJECTED_LOW_DISK
                            ? "spill_requeue_low_disk_drop"
                            : "spill_requeue_failed_drop";
                    ExportStats.recordTrafficDropReason(dropReason, 1);
                    OVERFLOW_LOGS.record(dropReason, 1, TrafficExportQueue::overflowContext);
                }
                return;
            }
            ExportStats.recordTrafficSpillDequeued(1);
        }
    }

    private static String overflowContext() {
        return "queue_depth=" + queue.size()
                + ", queue_bytes=" + getCurrentBytesEstimate()
                + ", mem_budget=" + ExportAdmissionController.memBudgetBytes()
                + ", spill_depth=" + spillQueue.size()
                + ", spill_bytes=" + spillQueue.bytes()
                + ", spill_budget=" + spillQueue.effectiveBudgetBytes()
                + ", oldest_spill_age_ms=" + spillQueue.oldestAgeMs();
    }

    private static FileOnlyDrainResult drainToFileOnly(int maxBatch, long maxBytes) {
        int attempted = 0;
        long exportedBytes = 0;
        List<PreparedExportDocument> batch = new ArrayList<>(Math.max(1, maxBatch));
        while (attempted < maxBatch && exportedBytes < maxBytes) {
            TrafficQueueEntry entry;
            try {
                entry = attempted == 0
                        ? queue.poll(POLL_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                        : queue.poll();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            if (entry == null) {
                break;
            }
            if (!isDocumentCurrentlyEnabled(entry.document())) {
                continue;
            }
            PreparedExportDocument prepared = entry.prepared();
            long docBytes = prepared.estimatedBulkBytes();
            if (attempted > 0 && exportedBytes + docBytes > maxBytes) {
                if (!queue.offerWithinBudget(entry)) {
                    spillRequeuedEntry(entry);
                }
                break;
            }
            batch.add(prepared);
            attempted++;
            exportedBytes += docBytes;
        }
        FileExportService.emitPreparedChunk(batch);
        return new FileOnlyDrainResult(attempted, exportedBytes);
    }

    static boolean isDocumentCurrentlyEnabled(Map<String, Object> document) {
        RuntimeConfig.TrafficExportGate gate = RuntimeConfig.trafficExportGate();
        return RuntimeConfig.isExportRunning()
                && gate.anyTrafficExportEnabled()
                && TrafficRouteBucket.isRouteEnabled(TrafficRouteBucket.fromDocument(document), gate);
    }

    /**
     * Applies startup grace before first drain while allowing immediate drain under backlog.
     *
     * <p>This keeps the extension responsive at startup when there is little traffic, but avoids
     * fixed-delay throughput penalties during initial backlog loads (for example proxy-history
     * or scanner bursts).</p>
     *
     * @return {@code true} when the worker should continue, {@code false} if interrupted
     */
    private static boolean awaitInitialWarmup(long generation) {
        long deadline = System.currentTimeMillis() + STARTUP_GRACE_MAX_MS;
        while (System.currentTimeMillis() < deadline) {
            if (isStopRequested(generation)) {
                return false;
            }
            if (!RuntimeConfig.isExportReady()) {
                return true;
            }
            if (queue.size() >= START_DRAIN_BACKLOG_DOCS) {
                return true;
            }
            try {
                long remaining = Math.max(1, deadline - System.currentTimeMillis());
                TimeUnit.MILLISECONDS.sleep(Math.min(STARTUP_POLL_MS, remaining));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return true;
    }

    private static void spillRequeuedEntry(TrafficQueueEntry entry) {
        TrafficSpillFileQueue.OfferResult spillResult = spillQueue.offerDetailed(entry);
        if (spillResult == TrafficSpillFileQueue.OfferResult.QUEUED) {
            ExportStats.recordTrafficSpillEnqueued(1);
            return;
        }
        ExportAdmissionController.noteSpillFullReject();
        ExportStats.recordTrafficQueueDrop(1);
        ExportStats.recordTrafficSpillDrop(1);
        String reason = spillResult == TrafficSpillFileQueue.OfferResult.REJECTED_LOW_DISK
                ? "spill_low_disk_reject_requeue"
                : "spill_full_reject_requeue";
        ExportStats.recordTrafficDropReason(reason, 1);
        OVERFLOW_LOGS.record(reason, 1, TrafficExportQueue::overflowContext);
    }

    private record FileOnlyDrainResult(int attemptedCount, long exportedBytes) { }

    /**
     * In-memory traffic queue that maintains {@link #queueBytesHeld} on offer, poll, clear, and
     * remove so {@link ChunkedBulkSender} drains stay O(1) for byte observability.
     */
    private static final class MeteredQueue extends LinkedBlockingQueue<TrafficQueueEntry> {

        private MeteredQueue(int capacity) {
            super(capacity);
        }

        @Override
        public boolean offer(TrafficQueueEntry entry) {
            return offerWithinBudget(entry);
        }

        private boolean offerWithinBudget(TrafficQueueEntry entry) {
            long bytes = entryBytes(entry);
            if (!reserveWithinBudget(bytes)) {
                return false;
            }
            if (super.offer(entry)) {
                return true;
            }
            queueBytesHeld.addAndGet(-bytes);
            return false;
        }

        @Override
        public TrafficQueueEntry poll() {
            TrafficQueueEntry entry = super.poll();
            recordDequeuedBytes(entry);
            return entry;
        }

        @Override
        public TrafficQueueEntry poll(long timeout, TimeUnit unit) throws InterruptedException {
            TrafficQueueEntry entry = super.poll(timeout, unit);
            recordDequeuedBytes(entry);
            return entry;
        }

        @Override
        public void clear() {
            List<TrafficQueueEntry> drained = new ArrayList<>();
            super.drainTo(drained);
            for (TrafficQueueEntry entry : drained) {
                recordDequeuedBytes(entry);
            }
        }

        @Override
        public boolean removeIf(java.util.function.Predicate<? super TrafficQueueEntry> filter) {
            return super.removeIf(entry -> {
                boolean remove = filter.test(entry);
                if (remove) {
                    recordDequeuedBytes(entry);
                }
                return remove;
            });
        }

        private static boolean reserveWithinBudget(long bytes) {
            while (true) {
                long held = queueBytesHeld.get();
                if (!ExportAdmissionController.memAccepts(held, bytes)) {
                    return false;
                }
                if (queueBytesHeld.compareAndSet(held, held + bytes)) {
                    return true;
                }
            }
        }

        private static long entryBytes(TrafficQueueEntry entry) {
            return entry == null || entry.prepared() == null
                    ? 0L
                    : Math.max(0L, entry.prepared().estimatedBulkBytes());
        }
    }
}
