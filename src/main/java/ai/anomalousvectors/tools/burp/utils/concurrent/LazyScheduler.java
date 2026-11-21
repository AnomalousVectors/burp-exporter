package ai.anomalousvectors.tools.burp.utils.concurrent;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Lazily-started single-thread daemon {@link ScheduledExecutorService} owned by one class.
 *
 * <p>Centralizes the "{@code volatile} field + {@code synchronized} ensure-started + {@link Workers}
 * shutdown" pattern shared by reporters and the orphan-flush path. Each
 * owner declares a {@code static final LazyScheduler} whose executor is created on first
 * {@link #getOrStart()} call and torn down by {@link #stop()} during UI stop or extension unload;
 * a subsequent {@link #getOrStart()} transparently recreates a fresh executor, preserving the
 * existing lazy-restart contract.</p>
 *
 * <p>Instances are thread-safe: start and stop serialize on the instance monitor, the backing
 * reference is {@code volatile} so {@link #peek()} and {@link #isStarted()} observe the most
 * recent write without locking, and {@link #stop()} delegates to {@link Workers} so shutdown
 * semantics match every other extension-owned worker.</p>
 *
 * <p>This helper does not clear reporter-specific state such as pushed-key sets or once-logged
 * flags; owners remain responsible for resetting their own session state in their own
 * {@code stop()} method after calling {@link #stop()}.</p>
 */
public final class LazyScheduler {

    private final String threadName;
    private final long shutdownTimeoutMs;
    private volatile ScheduledExecutorService executor;
    private volatile boolean recurringStarted;

    /**
     * Creates a new holder with the
     * {@link Workers#DEFAULT_SHUTDOWN_TIMEOUT_MS default shutdown budget}.
     *
     * <p>Preferred for owners that want the standard lazy-start/deterministic-stop behavior
     * without specifying a custom teardown window.</p>
     *
     * @param threadName daemon thread name assigned to the scheduler's single worker thread
     */
    public LazyScheduler(String threadName) {
        this(threadName, Workers.DEFAULT_SHUTDOWN_TIMEOUT_MS);
    }

    /**
     * Creates a new holder configured with the daemon thread name and shutdown budget to use.
     *
     * @param threadName daemon thread name assigned to the scheduler's single worker thread
     * @param shutdownTimeoutMs maximum milliseconds {@link #stop()} waits for termination before
     *                          returning; forwarded to {@link Workers#awaitExecutorShutdown}
     */
    public LazyScheduler(String threadName, long shutdownTimeoutMs) {
        this.threadName = threadName;
        this.shutdownTimeoutMs = shutdownTimeoutMs;
    }

    /**
     * Returns the backing scheduler, creating the daemon executor on first call.
     *
     * <p>Synchronized so the executor and its daemon thread are instantiated at most once per
     * lazy-start cycle even under concurrent callers. Callers may schedule or submit work against
     * the returned reference directly.</p>
     *
     * @return the active scheduler owned by this holder
     */
    public synchronized ScheduledExecutorService getOrStart() {
        ScheduledExecutorService current = executor;
        if (current != null) {
            return current;
        }
        ScheduledExecutorService fresh = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, threadName);
            t.setDaemon(true);
            return t;
        });
        executor = fresh;
        return fresh;
    }

    /**
     * Schedules a recurring task on the backing scheduler if one has not been registered yet.
     *
     * <p>Folds the "{@code volatile} check + {@code synchronized} double-check +
     * {@code getOrStart().scheduleAtFixedRate(...)}" idiom that every recurring reporter
     * previously inlined. Safe to call from any thread and safe to call more than once: on the
     * second and subsequent calls the method returns {@code false} without adding another fixed
     * rate task, so callers can treat it as idempotent.</p>
     *
     * <p>The recurring registration is tracked separately from executor creation, so callers can
     * submit one-shot startup work through {@link #getOrStart()} and register a recurring task
     * after that work completes.</p>
     *
     * @param task recurring work; scheduled via {@link ScheduledExecutorService#scheduleAtFixedRate}
     * @param initialDelay delay before the first run, expressed in {@code unit}
     * @param period fixed-rate period between successive runs, expressed in {@code unit}
     * @param unit time unit for {@code initialDelay} and {@code period}
     * @return {@code true} when this call registered the task; {@code false} when a recurring
     *         task was already registered and the call was a no-op
     */
    public boolean startRecurring(Runnable task, long initialDelay, long period, TimeUnit unit) {
        if (recurringStarted) {
            return false;
        }
        synchronized (this) {
            if (recurringStarted) {
                return false;
            }
            getOrStart().scheduleAtFixedRate(task, initialDelay, period, unit);
            recurringStarted = true;
            return true;
        }
    }

    /**
     * Returns {@code true} when an executor is currently held.
     *
     * <p>Intended for lifecycle checks that care whether a scheduler thread exists. Recurring
     * task registration is tracked separately by {@link #startRecurring(Runnable, long, long,
     * TimeUnit)}. The check is lock-free because {@link #executor} is {@code volatile}.</p>
     *
     * @return {@code true} when {@link #getOrStart()} has been called since the last
     *         {@link #stop()}, otherwise {@code false}
     */
    public boolean isStarted() {
        return executor != null;
    }

    /**
     * Returns the current scheduler or {@code null} when not started.
     *
     * <p>Primarily intended for tests and for owners like {@code ExporterIndexStatsReporter}
     * that need to compare executor identity across recreation.</p>
     *
     * @return the active scheduler, or {@code null} when the holder has not been started
     *         (or has been stopped)
     */
    public ScheduledExecutorService peek() {
        return executor;
    }

    /**
     * Null-swaps the backing reference under the holder's lock and hands the old executor to
     * {@link Workers#awaitExecutorShutdown}.
     *
     * <p>Safe to call from any thread and safe to call more than once. A subsequent
     * {@link #getOrStart()} creates a fresh executor. The termination wait is bounded by the
     * configured timeout. If that wait is interrupted, the current thread's interrupt flag is
     * restored before returning.</p>
     */
    public void stop() {
        ScheduledExecutorService current;
        synchronized (this) {
            current = executor;
            executor = null;
            recurringStarted = false;
        }
        Workers.awaitExecutorShutdown(current, shutdownTimeoutMs);
    }
}
