package ai.anomalousvectors.tools.burp.utils.concurrent;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

/**
 * Unit tests for {@link LazyScheduler}: initial state, lazy start, idempotent stop,
 * lazy restart after stop, and daemon thread configuration.
 *
 * <p>These exercise the shared contract every {@code *IndexReporter} and
 * {@code TrafficHttpHandlerSupport} rely on so the holder can be refactored with
 * confidence even when the caller-facing reporter tests cover it only indirectly.</p>
 */
class LazySchedulerTest {

    private LazyScheduler holder;

    @AfterEach
    public void tearDown() {
        if (holder != null) {
            holder.stop();
            holder = null;
        }
    }

    @Test
    void initialState_isUnstarted() {
        holder = new LazyScheduler("lazy-scheduler-initial", 1_000L);

        assertThat(holder.isStarted()).isFalse();
        assertThat(holder.peek()).isNull();
    }

    @Test
    void getOrStart_returnsSameExecutor_onRepeatedCalls() {
        holder = new LazyScheduler("lazy-scheduler-reuse", 1_000L);

        ScheduledExecutorService first = holder.getOrStart();
        ScheduledExecutorService second = holder.getOrStart();

        assertThat(first).isNotNull();
        assertThat(second).isSameAs(first);
        assertThat(holder.isStarted()).isTrue();
        assertThat(holder.peek()).isSameAs(first);
    }

    @Test
    void getOrStart_createsDaemonThread_withConfiguredName() throws Exception {
        String threadName = "lazy-scheduler-daemon-" + System.nanoTime();
        holder = new LazyScheduler(threadName, 1_000L);

        AtomicReference<Thread> observed = new AtomicReference<>();
        CountDownLatch ran = new CountDownLatch(1);
        holder.getOrStart().execute(() -> {
            observed.set(Thread.currentThread());
            ran.countDown();
        });

        assertThat(ran.await(2, TimeUnit.SECONDS)).isTrue();
        Thread workerThread = observed.get();
        assertThat(workerThread).isNotNull();
        assertThat(workerThread.isDaemon()).isTrue();
        assertThat(workerThread.getName()).isEqualTo(threadName);
    }

    @Test
    void stop_onUnstarted_isNoOp() {
        holder = new LazyScheduler("lazy-scheduler-stop-unstarted", 1_000L);

        holder.stop();

        assertThat(holder.isStarted()).isFalse();
        assertThat(holder.peek()).isNull();
    }

    @Test
    void stop_afterStart_shutsDownExecutor_andClearsReference() throws Exception {
        holder = new LazyScheduler("lazy-scheduler-stop", 1_000L);
        ScheduledExecutorService started = holder.getOrStart();

        holder.stop();

        assertThat(holder.isStarted()).isFalse();
        assertThat(holder.peek()).isNull();
        assertThat(started.isShutdown()).isTrue();
        assertThat(started.awaitTermination(2, TimeUnit.SECONDS)).isTrue();
    }

    @Test
    void stop_isIdempotent() {
        holder = new LazyScheduler("lazy-scheduler-idempotent", 1_000L);
        holder.getOrStart();

        holder.stop();
        holder.stop();

        assertThat(holder.isStarted()).isFalse();
        assertThat(holder.peek()).isNull();
    }

    @Test
    void getOrStart_afterStop_createsFreshExecutor() {
        holder = new LazyScheduler("lazy-scheduler-restart", 1_000L);
        ScheduledExecutorService first = holder.getOrStart();
        holder.stop();

        ScheduledExecutorService second = holder.getOrStart();

        assertThat(second).isNotNull();
        assertThat(second).isNotSameAs(first);
        assertThat(first.isShutdown()).isTrue();
        assertThat(second.isShutdown()).isFalse();
        assertThat(holder.isStarted()).isTrue();
    }

    @Test
    void singleArgConstructor_usesDefaultShutdownTimeout() throws Exception {
        holder = new LazyScheduler("lazy-scheduler-default-timeout");
        ScheduledExecutorService started = holder.getOrStart();

        holder.stop();

        assertThat(holder.isStarted()).isFalse();
        assertThat(started.isShutdown()).isTrue();
        assertThat(started.awaitTermination(2, TimeUnit.SECONDS)).isTrue();
    }

    @Test
    void startRecurring_onUnstarted_startsExecutor_andRunsTask() throws Exception {
        holder = new LazyScheduler("lazy-scheduler-recurring-start");
        AtomicInteger runs = new AtomicInteger();
        CountDownLatch ran = new CountDownLatch(1);

        boolean started = holder.startRecurring(() -> {
            runs.incrementAndGet();
            ran.countDown();
        }, 0L, 50L, TimeUnit.MILLISECONDS);

        assertThat(started).isTrue();
        assertThat(holder.isStarted()).isTrue();
        assertThat(ran.await(2, TimeUnit.SECONDS)).isTrue();
        assertThat(runs.get()).isGreaterThanOrEqualTo(1);
    }

    @Test
    void startRecurring_whenRecurringAlreadyRegistered_isNoOp() {
        holder = new LazyScheduler("lazy-scheduler-recurring-idempotent");
        AtomicInteger registrations = new AtomicInteger();
        Runnable task = registrations::incrementAndGet;

        boolean first = holder.startRecurring(task, 10_000L, 10_000L, TimeUnit.MILLISECONDS);
        boolean second = holder.startRecurring(task, 10_000L, 10_000L, TimeUnit.MILLISECONDS);
        boolean third = holder.startRecurring(task, 10_000L, 10_000L, TimeUnit.MILLISECONDS);

        assertThat(first).isTrue();
        assertThat(second).isFalse();
        assertThat(third).isFalse();
        assertThat(holder.isStarted()).isTrue();
    }

    @Test
    void startRecurring_afterOneShotExecutorStart_registersRecurringTask() {
        holder = new LazyScheduler("lazy-scheduler-recurring-after-oneshot");
        ScheduledExecutorService existing = holder.getOrStart();

        boolean registered = holder.startRecurring(() -> {}, 10_000L, 10_000L, TimeUnit.MILLISECONDS);

        assertThat(registered).isTrue();
        assertThat(holder.peek()).isSameAs(existing);
    }

    @Test
    void startRecurring_afterStop_createsFreshExecutor() {
        holder = new LazyScheduler("lazy-scheduler-recurring-restart");
        Runnable noop = () -> {};

        assertThat(holder.startRecurring(noop, 10_000L, 10_000L, TimeUnit.MILLISECONDS)).isTrue();
        ScheduledExecutorService first = holder.peek();

        holder.stop();

        assertThat(holder.startRecurring(noop, 10_000L, 10_000L, TimeUnit.MILLISECONDS)).isTrue();
        ScheduledExecutorService second = holder.peek();

        assertThat(first).isNotNull();
        assertThat(second).isNotNull();
        assertThat(second).isNotSameAs(first);
        assertThat(first.isShutdown()).isTrue();
        assertThat(second.isShutdown()).isFalse();
    }

    @Test
    void runScopedRegistrationCannotRecreateSchedulerFromInvalidatedRun() {
        holder = new LazyScheduler("lazy-scheduler-stale-registration");
        try {
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.setExportRunning(true);
            var oldToken = RuntimeConfig.currentExportRunToken();
            assertThat(holder.startRecurringForRun(
                    oldToken, () -> {}, 1, 1, TimeUnit.DAYS)).isTrue();
            RuntimeConfig.setExportRunning(false);
            holder.stop();
            RuntimeConfig.setExportRunning(true);

            assertThat(holder.startRecurringForRun(
                    oldToken, () -> {}, 1, 1, TimeUnit.DAYS)).isFalse();
            assertThat(holder.isStarted()).isFalse();
            assertThat(holder.startRecurringForRun(RuntimeConfig.currentExportRunToken(),
                    () -> {}, 1, 1, TimeUnit.DAYS)).isTrue();
        } finally {
            RuntimeConfig.setExportRunning(false);
        }
    }

    @Test
    void runScopedTaskReceivesOriginatingContext() throws Exception {
        holder = new LazyScheduler("lazy-scheduler-run-context");
        try {
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.setExportRunning(true);
            var token = RuntimeConfig.currentExportRunToken();
            AtomicReference<RuntimeConfig.ExportRunToken> observed = new AtomicReference<>();
            CountDownLatch ran = new CountDownLatch(1);
            assertThat(holder.startRecurringForRun(token, () -> {
                observed.set(ExportRunContext.currentToken());
                ran.countDown();
            }, 0, 1, TimeUnit.DAYS)).isTrue();
            assertThat(ran.await(2, TimeUnit.SECONDS)).isTrue();
            assertThat(observed.get()).isEqualTo(token);
        } finally {
            RuntimeConfig.setExportRunning(false);
        }
    }
}
