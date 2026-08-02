package ai.anomalousvectors.tools.burp.utils.concurrent;

import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.LongAdder;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.IntUnaryOperator;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;
import ai.anomalousvectors.tools.burp.utils.export.BulkOutcomeBreakdown;
import ai.anomalousvectors.tools.burp.utils.export.BulkPushOutcome;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;
import ai.anomalousvectors.tools.burp.utils.opensearch.BulkByteBudget;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClientWrapper;

/**
 * Parallel snapshot build and prepare with overlapping bulk flushes.
 *
 * <p>Only one engine run executes at a time so Findings, Sitemap, Proxy History, and WebSocket
 * historic startups cannot materialize multiple prepared-document queues in parallel. Startup
 * reporters also submit through {@link StartupSnapshotCoordinator} so ConfigPanel order
 * (Findings → Sitemap → Proxy History → WebSocket) is preserved under that gate. Build workers fill
 * a count- and byte-bounded queue; the assembly thread chunks prepared documents by the live byte
 * budget and overlaps chunk flushes with continued queue draining. Adaptive {@link BulkByteBudget}
 * starts at one in-flight flush and may raise concurrency after a healthy success streak.</p>
 */
public final class SnapshotExportEngine {

    private static final int MAX_BUILD_WORKERS = 4;
    private static final int MAX_IN_FLIGHT_FLUSHES = 3;
    private static final int MIN_QUEUE_CAPACITY = 64;
    private static final int MAX_QUEUE_CAPACITY = 512;
    /** Caps resolved NDJSON waiting in the prepared queue; one larger document reserves it alone. */
    static final long MAX_BUILD_AHEAD_BYTES = 64L * 1024L * 1024L;
    /** Quantizes byte reservations so the limiter can use integer semaphore permits. */
    private static final long BUILD_AHEAD_PERMIT_BYTES = 64L * 1024L;
    private static final int MAX_BUILD_AHEAD_PERMITS =
            Math.toIntExact(MAX_BUILD_AHEAD_BYTES / BUILD_AHEAD_PERMIT_BYTES);
    private static final Object POISON = new Object();
    private static final long QUEUE_POLL_MS = 100L;
    /** Serializes heavy startup snapshot runs across reporters. */
    private static final Semaphore ENGINE_GATE = new Semaphore(1, true);
    private static final ConcurrentHashMap<Long, RunCancellation> ACTIVE_RUNS = new ConcurrentHashMap<>();

    private record QueuedPreparedDocument(PreparedExportDocument document, int reservedPermits) {}

    /** Minimum completed flush-slot wait logged at INFO. */
    static final long SLOW_FLUSH_SLOT_WAIT_LOG_MS = 1_000L;
    /** Delay before warning that a live flush is still awaiting its transport-owned outcome. */
    static final long FLUSH_SLOT_WATCHDOG_LOG_MS = 120_000L;

    private SnapshotExportEngine() {}

    private static final class RunCancellation {
        private final AtomicBoolean cancelled = new AtomicBoolean();
        private final AtomicInteger activeFlushTasks = new AtomicInteger();
        private final Thread owner;
        private volatile ChunkFlushCoordinator flushCoordinator;

        private RunCancellation(Thread owner) {
            this.owner = owner;
        }

        private void cancel() {
            cancelled.set(true);
            ChunkFlushCoordinator coordinator = flushCoordinator;
            if (coordinator != null) {
                coordinator.cancelAll();
            }
            owner.interrupt();
        }

        private void flushStarted() {
            activeFlushTasks.incrementAndGet();
        }

        private void flushFinished() {
            if (activeFlushTasks.decrementAndGet() == 0) {
                synchronized (this) {
                    notifyAll();
                }
            }
        }

        private void awaitFlushTasks(long timeoutMs) {
            long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(Math.max(0L, timeoutMs));
            synchronized (this) {
                while (activeFlushTasks.get() > 0) {
                    long remaining = deadline - System.nanoTime();
                    if (remaining <= 0L) {
                        return;
                    }
                    try {
                        TimeUnit.NANOSECONDS.timedWait(this, remaining);
                    } catch (InterruptedException e) {
                        Thread.interrupted();
                    }
                }
            }
        }
    }

    /**
     * Cancels any active snapshot engine work owned by {@code token}.
     *
     * <p>Safe to call from any thread. Cancellation is cooperative: builders and outstanding
     * flush futures are interrupted or cancelled, but this method does not wait for their
     * termination.</p>
     *
     * @param token run being stopped or aborted
     */
    public static void cancelRun(ExportRunToken token) {
        if (token == null || !token.isValid()) {
            return;
        }
        RunCancellation cancellation = ACTIVE_RUNS.get(token.generation());
        if (cancellation != null) {
            cancellation.cancel();
        }
    }

    /**
     * Returns the default snapshot document-builder count.
     *
     * @return {@code max(1, min(4, processors - 2))}
     */
    public static int defaultBuildWorkers() {
        int processors = Runtime.getRuntime().availableProcessors();
        return Math.max(1, Math.min(MAX_BUILD_WORKERS, processors - 2));
    }

    /**
     * Returns the bounded prepared-document queue capacity for one snapshot run.
     *
     * <p>Sized for a few in-flight chunks plus worker slack. A separate byte reservation limits the
     * aggregate prepared data waiting in this queue.</p>
     *
     * @param buildWorkers requested build worker count
     * @param initialChunkTarget initial chunk target for the snapshot run
     * @return queue capacity in prepared documents
     */
    public static int queueCapacity(int buildWorkers, int initialChunkTarget) {
        int workers = Math.max(1, buildWorkers);
        int chunkTarget = Math.max(1, initialChunkTarget);
        int inFlight = Math.max(1, Math.min(MAX_IN_FLIGHT_FLUSHES, BulkByteBudget.maxInFlightFlushes()));
        long desired = Math.max(
                (long) MIN_QUEUE_CAPACITY,
                Math.max((long) workers * 32L, (long) chunkTarget * inFlight));
        return (int) Math.min(MAX_QUEUE_CAPACITY, desired);
    }

    /**
     * Returns the byte capacity of the prepared-document build-ahead reservation.
     *
     * @return reservation capacity in bytes
     */
    public static long maxBuildAheadBytes() {
        return MAX_BUILD_AHEAD_BYTES;
    }

    /**
     * Returns the permit capacity of the prepared-document build-ahead reservation.
     *
     * @return reservation capacity in quantized permits
     */
    public static int maxBuildAheadPermits() {
        return MAX_BUILD_AHEAD_PERMITS;
    }

    static int buildAheadReservationPermits(long documentBytes) {
        long positiveBytes = Math.max(1L, documentBytes);
        long permits = 1L + ((positiveBytes - 1L) / BUILD_AHEAD_PERMIT_BYTES);
        return (int) Math.min(MAX_BUILD_AHEAD_PERMITS, permits);
    }

    static long buildAheadReservationBytes(int permits) {
        return Math.max(0L, permits) * BUILD_AHEAD_PERMIT_BYTES;
    }

    @FunctionalInterface
    public interface ItemPreparer<T> {
        /**
         * Builds and prepares one snapshot item.
         *
         * <p>The engine invokes this callback on a snapshot build worker. Implementations must
         * support concurrent calls when more than one build worker is configured. A runtime
         * exception skips the item and increments the preparation-failure count.</p>
         *
         * @param item source item assigned to the worker; may be {@code null} when the input list
         *             contains null
         * @return prepared document, or {@code null} to skip
         */
        PreparedExportDocument prepare(T item);
    }

    /**
     * Observes flushed chunks for route statistics and chunk-target tuning.
     *
     * <p>The engine invokes callbacks in chunk submission order on an internal engine thread;
     * callers must not assume the EDT or the original calling thread. Callbacks are suppressed
     * after cancellation or run-token invalidation.</p>
     */
    @FunctionalInterface
    public interface ChunkObserver {
        /**
         * Observes one completed chunk.
         *
         * @param chunk immutable-by-convention prepared chunk; the observer must not mutate it
         * @param outcome combined sink outcome for the chunk
         * @param nextChunkTarget document-count target selected for the next chunk
         */
        void onChunkFlushed(List<PreparedExportDocument> chunk, BulkPushOutcome outcome, int nextChunkTarget);
    }

    /**
     * Result counters and timings from one parallel snapshot export.
     *
     * @param attempted documents offered to the sinks
     * @param success documents accepted by the enabled sinks
     * @param preparationFailures items skipped because preparation threw
     * @param chunks completed chunk flushes
     * @param totalChunkBytes resolved NDJSON bytes across completed chunks
     * @param buildWallMs wall-clock span from worker start until all workers finish
     * @param buildCpuMs aggregate worker build CPU time (sum across workers; may exceed {@code buildWallMs})
     * @param flushMs sum of per-chunk flush wall durations
     * @param fileFlushMs sum of per-chunk file sink durations when recorded
     * @param openSearchFlushMs sum of per-chunk OpenSearch durations when recorded
     * @param finalChunkTarget final adaptive document-count target
     * @param buildWorkers builder threads used by the run
     */
    public record Result(
            int attempted,
            int success,
            int preparationFailures,
            int chunks,
            long totalChunkBytes,
            long buildWallMs,
            long buildCpuMs,
            long flushMs,
            long fileFlushMs,
            long openSearchFlushMs,
            int finalChunkTarget,
            int buildWorkers) {

        /**
         * Creates a result when per-destination flush timings are unavailable.
         *
         * @param attempted documents offered to the sinks
         * @param success documents accepted by the enabled sinks
         * @param preparationFailures items skipped because preparation threw
         * @param chunks completed chunk flushes
         * @param totalChunkBytes resolved NDJSON bytes across completed chunks
         * @param buildWallMs wall-clock builder span
         * @param buildCpuMs aggregate builder CPU time
         * @param flushMs aggregate chunk-flush wall time
         * @param finalChunkTarget final adaptive document-count target
         * @param buildWorkers builder threads used by the run
         */
        public Result(
                int attempted,
                int success,
                int preparationFailures,
                int chunks,
                long totalChunkBytes,
                long buildWallMs,
                long buildCpuMs,
                long flushMs,
                int finalChunkTarget,
                int buildWorkers) {
            this(
                    attempted,
                    success,
                    preparationFailures,
                    chunks,
                    totalChunkBytes,
                    buildWallMs,
                    buildCpuMs,
                    flushMs,
                    -1L,
                    -1L,
                    finalChunkTarget,
                    buildWorkers);
        }
    }

    /**
     * Runs a parallel snapshot export on the calling thread (assembly + flush coordination); build
     * uses background worker threads.
     *
     * <p>Acquires a process-wide gate so concurrent startup reporters cannot pile prepared documents
     * onto the heap faster than one destination can drain. The caller must not mutate
     * {@code items} until this method returns. Runtime exceptions from the preparer are counted and
     * skipped; sink and observer behavior follows the token-scoped overload.</p>
     *
     * @param items source snapshot; {@code null} or empty returns an empty result
     * @param buildWorkers requested builder count; values below one use one worker
     * @param bulkMaxBytes caller byte ceiling for non-adaptive destinations
     * @param initialChunkTarget initial document-count target
     * @param applyBackpressure optional per-chunk target adjustment before sending
     * @param adjustChunkTarget optional post-flush target adjustment
     * @param baseUrl search destination base URL
     * @param indexName destination index name
     * @param indexKey exporter index key used for accounting and logs
     * @param preparer concurrent item-to-document callback; {@code null} causes each item to be
     *                 counted as a preparation failure
     * @param chunkObserver optional ordered chunk-completion callback
     * @param <T> source item type
     * @return final counters and timing values; cancellation may return a partial result
     */
    public static <T> Result run(
            List<T> items,
            int buildWorkers,
            long bulkMaxBytes,
            int initialChunkTarget,
            IntUnaryOperator applyBackpressure,
            ChunkTargetAdjuster adjustChunkTarget,
            String baseUrl,
            String indexName,
            String indexKey,
            ItemPreparer<T> preparer,
            ChunkObserver chunkObserver) {
        return run(
                RuntimeConfig.currentExportRunToken(),
                items,
                buildWorkers,
                bulkMaxBytes,
                initialChunkTarget,
                applyBackpressure,
                adjustChunkTarget,
                baseUrl,
                indexName,
                indexKey,
                preparer,
                chunkObserver);
    }

    /**
     * Runs a token-scoped parallel snapshot export.
     *
     * <p>Cancellation or token invalidation interrupts builders, cancels outstanding flush futures,
     * and suppresses all late observer and adaptive-controller callbacks. Waiting for the global
     * engine gate and all assembly work occurs on the calling thread. If the caller is interrupted,
     * the interrupt flag is restored and an empty or partial result is returned.</p>
     *
     * @param token run token captured by the startup reporter
     * @param items source snapshot; {@code null} or empty returns an empty result
     * @param buildWorkers requested builder count; values below one use one worker
     * @param bulkMaxBytes caller byte ceiling for non-adaptive destinations
     * @param initialChunkTarget initial document-count target
     * @param applyBackpressure optional per-chunk target adjustment before sending
     * @param adjustChunkTarget optional post-flush target adjustment
     * @param baseUrl search destination base URL
     * @param indexName destination index name
     * @param indexKey exporter index key used for accounting and logs
     * @param preparer concurrent item-to-document callback; {@code null} causes each item to be
     *                 counted as a preparation failure
     * @param chunkObserver optional ordered chunk-completion callback
     * @param <T> source item type
     * @return final counters and timing values; an inactive token returns an empty result and
     *         cancellation may return a partial result
     */
    public static <T> Result run(
            ExportRunToken token,
            List<T> items,
            int buildWorkers,
            long bulkMaxBytes,
            int initialChunkTarget,
            IntUnaryOperator applyBackpressure,
            ChunkTargetAdjuster adjustChunkTarget,
            String baseUrl,
            String indexName,
            String indexKey,
            ItemPreparer<T> preparer,
            ChunkObserver chunkObserver) {
        if (items == null || items.isEmpty()) {
            return new Result(0, 0, 0, 0, 0L, 0L, 0L, 0L, initialChunkTarget, Math.max(1, buildWorkers));
        }
        if (!RuntimeConfig.isExportRunActive(token)) {
            return new Result(0, 0, 0, 0, 0L, 0L, 0L, 0L, initialChunkTarget, Math.max(1, buildWorkers));
        }
        RunCancellation cancellation = new RunCancellation(Thread.currentThread());
        ACTIVE_RUNS.put(token.generation(), cancellation);
        boolean acquired = false;
        try {
            ENGINE_GATE.acquire();
            acquired = true;
            if (!isLive(token, cancellation)) {
                return new Result(0, 0, 0, 0, 0L, 0L, 0L, 0L, initialChunkTarget, Math.max(1, buildWorkers));
            }
            return runExclusive(
                    token,
                    cancellation,
                    items,
                    buildWorkers,
                    bulkMaxBytes,
                    initialChunkTarget,
                    applyBackpressure,
                    adjustChunkTarget,
                    baseUrl,
                    indexName,
                    indexKey,
                    preparer,
                    chunkObserver);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Result(0, 0, 0, 0, 0L, 0L, 0L, 0L, initialChunkTarget, Math.max(1, buildWorkers));
        } finally {
            if (acquired) {
                ENGINE_GATE.release();
            }
            if (cancellation.cancelled.get()) {
                cancellation.awaitFlushTasks(RuntimeConfig.EXPORT_STOP_UX_WALL_CLOCK_MS);
            }
            ACTIVE_RUNS.remove(token.generation(), cancellation);
            if (cancellation.cancelled.get()) {
                Thread.interrupted();
            }
        }
    }

    private static <T> Result runExclusive(
            ExportRunToken token,
            RunCancellation cancellation,
            List<T> items,
            int buildWorkers,
            long bulkMaxBytes,
            int initialChunkTarget,
            IntUnaryOperator applyBackpressure,
            ChunkTargetAdjuster adjustChunkTarget,
            String baseUrl,
            String indexName,
            String indexKey,
            ItemPreparer<T> preparer,
            ChunkObserver chunkObserver) {
        int workers = Math.max(1, buildWorkers);
        BlockingQueue<Object> queue = new ArrayBlockingQueue<>(queueCapacity(workers, initialChunkTarget));
        Semaphore buildAheadPermits = new Semaphore(MAX_BUILD_AHEAD_PERMITS, true);
        LongAdder buildNanos = new LongAdder();
        LongAdder preparationFailures = new LongAdder();
        long buildWallStartNs = System.nanoTime();
        boolean buildWallEnded = false;
        long buildWallMs = 0L;
        ExecutorService buildPool = Executors.newFixedThreadPool(workers, r -> {
            Thread thread = new Thread(r, "burp-exporter-snapshot-build");
            thread.setDaemon(true);
            return thread;
        });

        for (int worker = 0; worker < workers; worker++) {
            final int workerIndex = worker;
            buildPool.execute(() -> drainWorkerItems(
                    token,
                    cancellation,
                    items,
                    workerIndex,
                    workers,
                    preparer,
                    buildNanos,
                    preparationFailures,
                    queue,
                    buildAheadPermits));
        }

        ChunkFlushCoordinator flushCoordinator = new ChunkFlushCoordinator(
                token,
                cancellation,
                baseUrl,
                indexName,
                indexKey,
                applyBackpressure,
                adjustChunkTarget,
                chunkObserver,
                initialChunkTarget);
        cancellation.flushCoordinator = flushCoordinator;

        int processed = 0;
        int poisonsReceived = 0;
        long estBytes = 0L;
        List<PreparedExportDocument> chunk = new ArrayList<>(initialChunkTarget);

        try {
            while (true) {
                if (!isLive(token, cancellation)) {
                    chunk.clear();
                    flushCoordinator.cancelAll();
                    break;
                }
                if (poisonsReceived >= workers && chunk.isEmpty() && queue.isEmpty()) {
                    break;
                }
                Object taken;
                try {
                    taken = queue.poll(QUEUE_POLL_MS, TimeUnit.MILLISECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
                if (taken == null) {
                    if (poisonsReceived >= workers && !chunk.isEmpty() && queue.isEmpty()
                            && isLive(token, cancellation)) {
                        flushCoordinator.submit(chunk);
                        chunk = new ArrayList<>(flushCoordinator.chunkTarget());
                        estBytes = 0L;
                    }
                    continue;
                }
                if (taken == POISON) {
                    poisonsReceived++;
                    if (!buildWallEnded && poisonsReceived >= workers) {
                        buildWallMs = (System.nanoTime() - buildWallStartNs) / 1_000_000L;
                        buildWallEnded = true;
                    }
                    continue;
                }
                QueuedPreparedDocument queued = (QueuedPreparedDocument) taken;
                ExportStats.releaseSnapshotBuildAhead(
                        queued.reservedPermits(), buildAheadReservationBytes(queued.reservedPermits()));
                buildAheadPermits.release(queued.reservedPermits());
                PreparedExportDocument prepared = queued.document();
                if (!isLive(token, cancellation)) {
                    break;
                }
                SnapshotPacing.paceItem(processed);
                processed++;
                long maxBytes = effectiveBulkMaxBytes(bulkMaxBytes);
                long docBytes = prepared.resolvedBulkBytes();
                // Oversized singles stay in the chunk for full dual-sink file emit. The search
                // sender fits a derived copy and refuses HTTP if the live-budget postcondition
                // still cannot be met.
                boolean countCapReached = chunk.size() >= flushCoordinator.chunkTarget();
                boolean wouldExceedBytes = !chunk.isEmpty() && (estBytes + docBytes) > maxBytes;
                boolean oversizedSingle = docBytes > maxBytes;
                if (wouldExceedBytes || countCapReached || (oversizedSingle && !chunk.isEmpty())) {
                    flushCoordinator.submit(chunk);
                    chunk = new ArrayList<>(flushCoordinator.chunkTarget());
                    estBytes = 0L;
                }
                chunk.add(prepared);
                estBytes += docBytes;
            }
            if (!chunk.isEmpty() && isLive(token, cancellation)) {
                flushCoordinator.submit(chunk);
            }
            if (isLive(token, cancellation)) {
                flushCoordinator.awaitAll();
            } else {
                flushCoordinator.cancelAll();
            }
        } finally {
            buildPool.shutdownNow();
            try {
                buildPool.awaitTermination(Workers.DEFAULT_SHUTDOWN_TIMEOUT_MS, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            ExportStats.clearSnapshotBuildAheadReservations();
            if (!buildWallEnded) {
                buildWallMs = (System.nanoTime() - buildWallStartNs) / 1_000_000L;
            }
        }

        long buildCpuMs = buildNanos.sum() / 1_000_000L;
        int failedPreparations = preparationFailures.intValue();
        if (failedPreparations > 0 && RuntimeConfig.isExportRunActive(token)) {
            Logger.logWarnPanelOnly("[SnapshotExport] "
                    + (indexKey == null || indexKey.isBlank() ? "Snapshot" : indexKey)
                    + ": skipped " + failedPreparations
                    + " item(s) whose document preparation failed; remaining items continued.");
        }
        return new Result(
                flushCoordinator.attempted(),
                flushCoordinator.success(),
                failedPreparations,
                flushCoordinator.chunks(),
                flushCoordinator.totalChunkBytes(),
                buildWallMs,
                buildCpuMs,
                flushCoordinator.flushMs(),
                flushCoordinator.fileFlushMs(),
                flushCoordinator.openSearchFlushMs(),
                flushCoordinator.chunkTarget(),
                workers);
    }

    /**
     * Resolves the per-chunk byte ceiling for assembly.
     *
     * <p>Adaptive destinations always use the live {@link BulkByteBudget} so Soft Outage shrinks
     * apply to new chunks immediately. Non-adaptive paths may honor a tighter caller cap (tests).
     * </p>
     */
    private static long effectiveBulkMaxBytes(long callerMaxBytes) {
        long live = Math.max(1L, BulkByteBudget.currentMaxBytes());
        if (!BulkByteBudget.isAdaptiveDestination() && callerMaxBytes > 0L) {
            return Math.min(live, callerMaxBytes);
        }
        return live;
    }

    private static long sumResolvedBulkBytes(List<PreparedExportDocument> documents) {
        if (documents == null || documents.isEmpty()) {
            return 0L;
        }
        long total = 0L;
        for (PreparedExportDocument document : documents) {
            if (document != null) {
                total += document.resolvedBulkBytes();
            }
        }
        return total;
    }

    private static boolean isLive(ExportRunToken token, RunCancellation cancellation) {
        return cancellation != null
                && !cancellation.cancelled.get()
                && RuntimeConfig.isExportRunActive(token)
                && !Thread.currentThread().isInterrupted();
    }

    private static <T> void drainWorkerItems(
            ExportRunToken token,
            RunCancellation cancellation,
            List<T> items,
            int workerIndex,
            int workers,
            ItemPreparer<T> preparer,
            LongAdder buildNanos,
            LongAdder preparationFailures,
            BlockingQueue<Object> queue,
            Semaphore buildAheadPermits) {
        try {
            for (int index = workerIndex; index < items.size(); index += workers) {
                if (!isLive(token, cancellation)) {
                    break;
                }
                long buildStartNs = System.nanoTime();
                PreparedExportDocument prepared;
                try {
                    prepared = preparer.prepare(items.get(index));
                } catch (RuntimeException e) {
                    preparationFailures.increment();
                    Logger.logDebug("[SnapshotExport] Item preparation failed for "
                            + (items.get(index) == null ? "null" : items.get(index).getClass().getSimpleName())
                            + ": " + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
                    continue;
                } finally {
                    buildNanos.add(System.nanoTime() - buildStartNs);
                }
                if (prepared != null && isLive(token, cancellation)) {
                    int reservedPermits = buildAheadReservationPermits(prepared.resolvedBulkBytes());
                    boolean reserved = false;
                    boolean queued = false;
                    try {
                        while (isLive(token, cancellation) && !reserved) {
                            reserved = buildAheadPermits.tryAcquire(
                                    reservedPermits, QUEUE_POLL_MS, TimeUnit.MILLISECONDS);
                        }
                        if (reserved) {
                            ExportStats.reserveSnapshotBuildAhead(
                                    reservedPermits, buildAheadReservationBytes(reservedPermits));
                        }
                        // Timed offers let Stop/token invalidation terminate builders behind a full
                        // queue. A document larger than the byte envelope reserves it exclusively.
                        while (reserved
                                && isLive(token, cancellation)
                                && !(queued = queue.offer(
                                        new QueuedPreparedDocument(prepared, reservedPermits),
                                        QUEUE_POLL_MS,
                                        TimeUnit.MILLISECONDS))) {
                            // Retry while this run remains live.
                        }
                    } finally {
                        if (reserved && !queued) {
                            ExportStats.releaseSnapshotBuildAhead(
                                    reservedPermits, buildAheadReservationBytes(reservedPermits));
                            buildAheadPermits.release(reservedPermits);
                        }
                    }
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            while (!cancellation.cancelled.get()) {
                try {
                    if (queue.offer(POISON, QUEUE_POLL_MS, TimeUnit.MILLISECONDS)) {
                        break;
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
    }

    private static FlushOutcome flushChunkSync(
            ExportRunToken token,
            RunCancellation cancellation,
            String baseUrl,
            String indexName,
            String indexKey,
            List<PreparedExportDocument> snapshot,
            IntUnaryOperator applyBackpressure,
            ChunkTargetAdjuster adjustChunkTarget,
            int chunkTarget) {
        if (!isLive(token, cancellation)) {
            return null;
        }
        int adjustedTarget = applyBackpressure == null ? chunkTarget : applyBackpressure.applyAsInt(chunkTarget);
        if (!isLive(token, cancellation)) {
            return null;
        }
        int attemptedChunk = snapshot.size();
        long chunkBytes = sumResolvedBulkBytes(snapshot);
        long flushStartNs = System.nanoTime();
        BulkPushOutcome outcome = ExportRunContext.call(
                token,
                () -> OpenSearchClientWrapper.pushPreparedBulk(baseUrl, indexName, indexKey, snapshot));
        long chunkFlushMs = (System.nanoTime() - flushStartNs) / 1_000_000L;
        if (!isLive(token, cancellation)) {
            return null;
        }
        long fileFlushMs = outcome.fileFlushMs();
        long openSearchFlushMs = outcome.openSearchFlushMs();
        if (fileFlushMs < 0L && openSearchFlushMs < 0L) {
            openSearchFlushMs = chunkFlushMs;
        }
        int sent = outcome.successCount();
        int nextTarget = adjustChunkTarget == null
                ? adjustedTarget
                : adjustChunkTarget.adjust(adjustedTarget, attemptedChunk, sent, chunkBytes);
        return new FlushOutcome(
                attemptedChunk, sent, chunkBytes, chunkFlushMs, fileFlushMs, openSearchFlushMs, nextTarget, snapshot, outcome);
    }

    /**
     * Adjusts the document-count target after a chunk flush.
     *
     * <p>Flushes may complete concurrently, so implementations must be thread-safe. A runtime
     * exception is treated as a failed flush by the asynchronous coordinator.</p>
     */
    @FunctionalInterface
    public interface ChunkTargetAdjuster {
        /**
         * @param currentTarget active doc-count target before the flush
         * @param attemptedChunk documents in the flushed chunk
         * @param succeededChunk documents accepted by sinks
         * @param chunkBytes estimated prepared NDJSON bytes in the flushed chunk
         * @return next doc-count target
         */
        int adjust(int currentTarget, int attemptedChunk, int succeededChunk, long chunkBytes);
    }

    private record FlushOutcome(
            int attempted,
            int success,
            long chunkBytes,
            long flushMs,
            long fileFlushMs,
            long openSearchFlushMs,
            int nextChunkTarget,
            List<PreparedExportDocument> snapshot,
            BulkPushOutcome bulkOutcome) {
    }

    private static final class ChunkFlushCoordinator {
        private final ExportRunToken token;
        private final RunCancellation cancellation;
        private final String baseUrl;
        private final String indexName;
        private final String indexKey;
        private final IntUnaryOperator applyBackpressure;
        private final ChunkTargetAdjuster adjustChunkTarget;
        private final ChunkObserver chunkObserver;
        private final List<CompletableFuture<FlushOutcome>> inFlight = new CopyOnWriteArrayList<>();
        private final TreeMap<Integer, FlushOutcome> completed = new TreeMap<>();
        private int assignSequence;
        private int emitSequence;
        private int chunkTarget;
        private int attempted;
        private int success;
        private int chunks;
        private long totalChunkBytes;
        private long flushMs;
        private long fileFlushMs;
        private long openSearchFlushMs;

        ChunkFlushCoordinator(
                ExportRunToken token,
                RunCancellation cancellation,
                String baseUrl,
                String indexName,
                String indexKey,
                IntUnaryOperator applyBackpressure,
                ChunkTargetAdjuster adjustChunkTarget,
                ChunkObserver chunkObserver,
                int initialChunkTarget) {
            this.token = token;
            this.cancellation = cancellation;
            this.baseUrl = baseUrl;
            this.indexName = indexName;
            this.indexKey = indexKey;
            this.applyBackpressure = applyBackpressure;
            this.adjustChunkTarget = adjustChunkTarget;
            this.chunkObserver = chunkObserver;
            this.chunkTarget = initialChunkTarget;
        }

        int chunkTarget() {
            return chunkTarget;
        }

        int attempted() {
            return attempted;
        }

        int success() {
            return success;
        }

        int chunks() {
            return chunks;
        }

        long totalChunkBytes() {
            return totalChunkBytes;
        }

        long flushMs() {
            return flushMs;
        }

        long fileFlushMs() {
            return fileFlushMs;
        }

        long openSearchFlushMs() {
            return openSearchFlushMs;
        }

        /**
         * Hands a completed chunk to the async flusher.
         *
         * <p>The caller must not mutate {@code snapshot} after this call. {@link #run} satisfies
         * that by allocating a fresh chunk list for subsequent documents, which avoids an extra
         * per-chunk defensive copy on large WebSocket/history snapshots.</p>
         */
        void submit(List<PreparedExportDocument> snapshot) {
            if (snapshot.isEmpty() || !isLive(token, cancellation)) {
                return;
            }
            while (isLive(token, cancellation)
                    && inFlight.size() >= BulkByteBudget.maxInFlightFlushes()) {
                awaitOldest();
            }
            if (!isLive(token, cancellation)) {
                return;
            }
            int currentTarget = chunkTarget;
            int sequence = assignSequence++;
            CompletableFuture<FlushOutcome> future = CompletableFuture.supplyAsync(
                    () -> {
                        cancellation.flushStarted();
                        try {
                            return flushChunkSync(
                                    token,
                                    cancellation,
                                    baseUrl,
                                    indexName,
                                    indexKey,
                                    snapshot,
                                    applyBackpressure,
                                    adjustChunkTarget,
                                    currentTarget);
                        } finally {
                            cancellation.flushFinished();
                        }
                    },
                    SnapshotFlushExecutor.flushExecutor());
            future = future.exceptionally(error -> isLive(token, cancellation)
                    ? failureFlushOutcome(snapshot, currentTarget, error)
                    : null);
            inFlight.add(future);
            future.whenComplete((outcome, error) -> {
                if (outcome != null && isLive(token, cancellation)) {
                    synchronized (completed) {
                        completed.put(sequence, outcome);
                    }
                    drainCompleted();
                }
            });
        }

        void awaitAll() {
            while (!inFlight.isEmpty() && isLive(token, cancellation)) {
                awaitOldest();
            }
            if (isLive(token, cancellation)) {
                drainCompleted();
            } else {
                cancelAll();
            }
        }

        void cancelAll() {
            cancellation.cancelled.set(true);
            for (CompletableFuture<FlushOutcome> future : inFlight) {
                future.cancel(true);
            }
            synchronized (completed) {
                completed.clear();
            }
        }

        private void awaitOldest() {
            int inFlightBeforeWait = inFlight.size();
            long startedNanos = System.nanoTime();
            CompletableFuture<FlushOutcome> oldest = inFlight.remove(0);
            try {
                // The HTTP transport owns its response timeout and retry hand-off. Waiting for the
                // same future preserves one authoritative outcome instead of abandoning a live
                // request that may still index or enqueue its own retry.
                oldest.get(FLUSH_SLOT_WATCHDOG_LOG_MS, TimeUnit.MILLISECONDS);
            } catch (TimeoutException timeout) {
                long waitedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedNanos);
                if (isLive(token, cancellation)) {
                    ExportStats.recordFlushSlotWaitMs(waitedMs);
                    Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                            + " Snapshot flush slot watchdog: index=" + indexName
                            + " waitedMs=" + waitedMs
                            + " limitMs=" + FLUSH_SLOT_WATCHDOG_LOG_MS
                            + " inFlightBeforeWait=" + inFlightBeforeWait
                            + " maxInFlightFlushes=" + BulkByteBudget.maxInFlightFlushes()
                            + " action=await_transport_outcome.");
                }
                try {
                    oldest.get();
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                } catch (Exception error) {
                    // Failure outcomes are already merged via exceptionally; ignore join noise.
                }
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            } catch (Exception error) {
                // Failure outcomes are already merged via exceptionally; ignore join noise.
            }
            long waitedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedNanos);
            if (!isLive(token, cancellation)) {
                return;
            }
            ExportStats.recordFlushSlotWaitMs(waitedMs);
            if (waitedMs >= SLOW_FLUSH_SLOT_WAIT_LOG_MS) {
                Logger.logInfoPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                        + " Snapshot flush slot wait: index=" + indexName
                        + " waitedMs=" + waitedMs
                        + " inFlightBeforeWait=" + inFlightBeforeWait
                        + " maxInFlightFlushes=" + BulkByteBudget.maxInFlightFlushes() + ".");
            }
        }

        private void drainCompleted() {
            synchronized (completed) {
                while (isLive(token, cancellation) && completed.containsKey(emitSequence)) {
                    FlushOutcome outcome = completed.remove(emitSequence++);
                    merge(outcome);
                    if (chunkObserver != null) {
                        chunkObserver.onChunkFlushed(outcome.snapshot(), outcome.bulkOutcome(), outcome.nextChunkTarget());
                    }
                    chunkTarget = outcome.nextChunkTarget();
                }
            }
        }

        private void merge(FlushOutcome outcome) {
            attempted += outcome.attempted();
            success += outcome.success();
            totalChunkBytes += outcome.chunkBytes();
            flushMs += outcome.flushMs();
            ExportStats.recordSnapshotChunkFlushMs(outcome.flushMs());
            if (outcome.fileFlushMs() >= 0L) {
                fileFlushMs += outcome.fileFlushMs();
            }
            if (outcome.openSearchFlushMs() >= 0L) {
                openSearchFlushMs += outcome.openSearchFlushMs();
            }
            chunks++;
        }

        private FlushOutcome failureFlushOutcome(
                List<PreparedExportDocument> snapshot,
                int adjustedTarget,
                Throwable error) {
            if (!isLive(token, cancellation)) {
                return null;
            }
            int attemptedChunk = snapshot.size();
            long chunkBytes = sumResolvedBulkBytes(snapshot);
            String message = error == null
                    ? "unknown"
                    : (error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage());
            Logger.logWarnPanelOnly("[SnapshotExport] Chunk flush failed for "
                    + indexName + ": " + message
                    + " action=bulk_sender_owns_retry.");
            // The bulk/retry layer is the sole enqueue owner. The async wrapper reports the failed
            // chunk but must not duplicate the sender's normal retry hand-off.
            BulkPushOutcome bulkOutcome = new BulkPushOutcome(
                    attemptedChunk,
                    0,
                    BulkOutcomeBreakdown.classified(0, attemptedChunk));
            return new FlushOutcome(
                    attemptedChunk,
                    0,
                    chunkBytes,
                    0L,
                    -1L,
                    -1L,
                    adjustedTarget,
                    snapshot,
                    bulkOutcome);
        }
    }
}
