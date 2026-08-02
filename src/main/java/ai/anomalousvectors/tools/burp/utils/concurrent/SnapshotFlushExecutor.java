package ai.anomalousvectors.tools.burp.utils.concurrent;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Daemon pools for snapshot bulk I/O.
 *
 * <p>{@link #flushExecutor()} runs whole-chunk flushes (multi-flight). {@link #dualSinkExecutor()}
 * runs parallel file + OpenSearch work inside one flush. They must stay separate: nesting
 * dual-sink tasks on the flush pool deadlocks when a flush thread blocks on {@code get()}.</p>
 *
 * <p>The shared daemon pools live for the extension process. Accessors are safe from any thread;
 * callers may submit work but must not shut down the returned executors.</p>
 */
public final class SnapshotFlushExecutor {

    /** Sized for adaptive headroom in-flight flushes (up to 3) plus one spare. */
    private static final ThreadPoolExecutor FLUSH_EXECUTOR = newFixedPool(4, "burp-exporter-snapshot-flush-");
    private static final ThreadPoolExecutor DUAL_SINK_EXECUTOR =
            newFixedPool(2, "burp-exporter-snapshot-dual-sink-");

    private SnapshotFlushExecutor() {}

    /**
     * Returns the shared pool for overlapping snapshot chunk flushes.
     *
     * @return process-wide snapshot flush executor; callers must not shut it down
     */
    public static ExecutorService flushExecutor() {
        return FLUSH_EXECUTOR;
    }

    /**
     * Returns the shared pool for parallel file and OpenSearch work within one bulk push.
     *
     * @return process-wide dual-sink executor; callers must not shut it down
     */
    public static ExecutorService dualSinkExecutor() {
        return DUAL_SINK_EXECUTOR;
    }

    /**
     * Returns point-in-time pressure metrics for both snapshot flush pools.
     *
     * @return non-atomic pressure snapshot suitable for operational statistics
     */
    public static Snapshot stats() {
        return new Snapshot(poolStats(FLUSH_EXECUTOR), poolStats(DUAL_SINK_EXECUTOR));
    }

    private static PoolStats poolStats(ThreadPoolExecutor executor) {
        return new PoolStats(
                executor.getPoolSize(),
                executor.getActiveCount(),
                executor.getQueue().size(),
                executor.getTaskCount(),
                executor.getCompletedTaskCount());
    }

    private static ThreadPoolExecutor newFixedPool(int threads, String namePrefix) {
        return new ThreadPoolExecutor(
                threads,
                threads,
                0L,
                TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(),
                new ThreadFactory() {
                    private int seq;

                    @Override
                    public Thread newThread(Runnable runnable) {
                        Thread thread = new Thread(runnable, namePrefix + (++seq));
                        thread.setDaemon(true);
                        return thread;
                    }
                });
    }

    /**
     * Snapshot flush-pool pressure at one instant.
     *
     * @param flush pool that runs whole snapshot chunk flushes
     * @param dualSink pool that runs file and OpenSearch work inside one flush
     */
    public record Snapshot(PoolStats flush, PoolStats dualSink) {
    }

    /**
     * Thread-pool pressure values exposed in exporter stats.
     *
     * @param poolSize current worker count
     * @param activeCount workers currently executing tasks
     * @param queueSize tasks waiting in the executor queue
     * @param taskCount total tasks ever scheduled, per {@link ThreadPoolExecutor#getTaskCount()}
     * @param completedTaskCount tasks completed, per {@link ThreadPoolExecutor#getCompletedTaskCount()}
     */
    public record PoolStats(
            int poolSize,
            int activeCount,
            int queueSize,
            long taskCount,
            long completedTaskCount) {
    }
}
