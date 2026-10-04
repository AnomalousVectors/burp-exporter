package ai.anomalousvectors.tools.burp.utils.concurrent;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;

/**
 * Run-scoped daemon pools for snapshot bulk I/O.
 *
 * <p>{@link #supplyFlushAsync(ExportRunToken, Supplier)} runs whole-chunk flushes
 * (multi-flight). {@link #supplyDualSinkAsync(ExportRunToken, Supplier)} runs parallel file and
 * OpenSearch work inside one flush. They must stay separate: nesting dual-sink tasks on the flush
 * pool deadlocks when a flush thread blocks on {@code get()}.</p>
 *
 * <p>Pool creation and submission are serialized with shutdown. A stopped or stale run cannot
 * recreate either pool, while a later explicit Start may activate a new token and create fresh
 * workers lazily on its first submission.</p>
 */
public final class SnapshotFlushExecutor {

    private static final Object LOCK = new Object();
    private static final PoolStats EMPTY_POOL_STATS = new PoolStats(0, 0, 0, 0L, 0L);
    private static ThreadPoolExecutor flushExecutor;
    private static ThreadPoolExecutor dualSinkExecutor;
    private static ExportRunToken activeRun;

    private SnapshotFlushExecutor() {}

    /**
     * Activates snapshot I/O ownership for one explicit export run.
     *
     * <p>This method does not create threads. Repeating it for the same token is harmless. A stale
     * token is rejected and cannot replace the active owner.</p>
     *
     * @param token active export-run token
     * @return {@code true} when the token owns snapshot I/O after the call
     */
    public static boolean beginRun(ExportRunToken token) {
        if (!RuntimeConfig.isExportRunActive(token)) {
            return false;
        }
        ThreadPoolExecutor retiredFlush = null;
        ThreadPoolExecutor retiredDualSink = null;
        synchronized (LOCK) {
            if (!RuntimeConfig.isExportRunActive(token)) {
                return false;
            }
            if (token.equals(activeRun)) {
                return true;
            }
            if (activeRun == null || !RuntimeConfig.isExportRunActive(activeRun)) {
                retiredFlush = flushExecutor;
                retiredDualSink = dualSinkExecutor;
                flushExecutor = null;
                dualSinkExecutor = null;
                activeRun = token;
            } else {
                return false;
            }
        }
        shutdownExecutors(retiredFlush, retiredDualSink, 0L);
        return true;
    }

    /**
     * Submits a whole snapshot-chunk flush for the owning run.
     *
     * @param token run that owns the work
     * @param work asynchronous flush operation
     * @param <T> result type
     * @return future for the submitted operation
     * @throws RejectedExecutionException when the token is stale or its workers were stopped
     */
    public static <T> CompletableFuture<T> supplyFlushAsync(ExportRunToken token, Supplier<T> work) {
        synchronized (LOCK) {
            requireActiveRunLocked(token);
            if (flushExecutor == null) {
                flushExecutor = newFixedPool(4, "burp-exporter-snapshot-flush-");
            }
            return CompletableFuture.supplyAsync(work, flushExecutor);
        }
    }

    /**
     * Submits one side of a parallel file and OpenSearch push for the owning run.
     *
     * @param token run that owns the work
     * @param work asynchronous sink operation
     * @param <T> result type
     * @return future for the submitted operation
     * @throws RejectedExecutionException when the token is stale or its workers were stopped
     */
    public static <T> CompletableFuture<T> supplyDualSinkAsync(ExportRunToken token, Supplier<T> work) {
        synchronized (LOCK) {
            requireActiveRunLocked(token);
            if (dualSinkExecutor == null) {
                dualSinkExecutor = newFixedPool(2, "burp-exporter-snapshot-dual-sink-");
            }
            return CompletableFuture.supplyAsync(work, dualSinkExecutor);
        }
    }

    /**
     * Stops both pool families when {@code token} still owns them.
     *
     * <p>Queued work is cancelled, running work is interrupted, and both executor references are
     * detached before this method waits. The total wait across both pools is bounded by
     * {@code timeoutMs}. Repeated calls are harmless.</p>
     *
     * @param token run whose workers should stop
     * @param timeoutMs total termination budget in milliseconds
     * @return {@code true} when both retired executors terminated within the budget
     */
    public static boolean shutdownRun(ExportRunToken token, long timeoutMs) {
        ThreadPoolExecutor retiredFlush;
        ThreadPoolExecutor retiredDualSink;
        synchronized (LOCK) {
            if (activeRun == null || token == null || !token.equals(activeRun)) {
                return true;
            }
            activeRun = null;
            retiredFlush = flushExecutor;
            retiredDualSink = dualSinkExecutor;
            flushExecutor = null;
            dualSinkExecutor = null;
        }
        return shutdownExecutors(retiredFlush, retiredDualSink, timeoutMs);
    }

    /**
     * Returns point-in-time pressure metrics for both snapshot flush pools.
     *
     * <p>Reading statistics never creates a stopped pool.</p>
     *
     * @return non-atomic pressure snapshot suitable for operational statistics
     */
    public static Snapshot stats() {
        synchronized (LOCK) {
            return new Snapshot(poolStats(flushExecutor), poolStats(dualSinkExecutor));
        }
    }

    /** Stops and forgets all pool state for deterministic test teardown. */
    static void resetForTests() {
        ThreadPoolExecutor retiredFlush;
        ThreadPoolExecutor retiredDualSink;
        synchronized (LOCK) {
            activeRun = null;
            retiredFlush = flushExecutor;
            retiredDualSink = dualSinkExecutor;
            flushExecutor = null;
            dualSinkExecutor = null;
        }
        shutdownExecutors(
                retiredFlush,
                retiredDualSink,
                Workers.DEFAULT_SHUTDOWN_TIMEOUT_MS);
    }

    private static void requireActiveRunLocked(ExportRunToken token) {
        if (token == null
                || !token.equals(activeRun)
                || !RuntimeConfig.isExportRunActive(token)) {
            throw new RejectedExecutionException("Snapshot workers are not active for this export run.");
        }
    }

    private static PoolStats poolStats(ThreadPoolExecutor executor) {
        if (executor == null) {
            return EMPTY_POOL_STATS;
        }
        return new PoolStats(
                executor.getPoolSize(),
                executor.getActiveCount(),
                executor.getQueue().size(),
                executor.getTaskCount(),
                executor.getCompletedTaskCount());
    }

    private static boolean shutdownExecutors(
            ThreadPoolExecutor first,
            ThreadPoolExecutor second,
            long timeoutMs) {
        long deadline = System.nanoTime()
                + TimeUnit.MILLISECONDS.toNanos(Math.max(0L, timeoutMs));
        if (first != null) {
            first.shutdownNow();
        }
        if (second != null) {
            second.shutdownNow();
        }
        boolean firstTerminated = awaitTermination(first, deadline);
        boolean secondTerminated = awaitTermination(second, deadline);
        return firstTerminated && secondTerminated;
    }

    private static boolean awaitTermination(ThreadPoolExecutor executor, long deadline) {
        if (executor == null) {
            return true;
        }
        long remaining = deadline - System.nanoTime();
        if (remaining <= 0L) {
            return executor.isTerminated();
        }
        try {
            return executor.awaitTermination(remaining, TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
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
