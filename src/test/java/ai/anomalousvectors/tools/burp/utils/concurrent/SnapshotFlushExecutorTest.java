package ai.anomalousvectors.tools.burp.utils.concurrent;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.LockSupport;
import java.util.stream.IntStream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.sinks.ExportReporterLifecycle;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;

/** Regression tests for snapshot flush pool separation and lifecycle ownership. */
class SnapshotFlushExecutorTest {

    private ExportRunToken token;

    @BeforeEach
    void startRun() {
        RuntimeConfig.setExportRunning(true);
        token = RuntimeConfig.currentExportRunToken();
        assertThat(SnapshotFlushExecutor.beginRun(token)).isTrue();
    }

    @AfterEach
    void stopRun() {
        ExportReporterLifecycle.resetForTests();
    }

    @Test
    void nestedDualSinkOnSeparatePool_completesWithoutDeadlock() throws Exception {
        AtomicInteger dualSinkTasksCompleted = new AtomicInteger();

        Runnable dualSinkStyleWork = () -> {
            CompletableFuture<Void> file = supplyDualSink(() -> dualSinkTasksCompleted.incrementAndGet());
            CompletableFuture<Void> openSearch = supplyDualSink(() -> dualSinkTasksCompleted.incrementAndGet());
            CompletableFuture.allOf(file, openSearch).join();
        };

        CompletableFuture<Void> flushOne = supplyFlush(dualSinkStyleWork);
        CompletableFuture<Void> flushTwo = supplyFlush(dualSinkStyleWork);

        CompletableFuture.allOf(flushOne, flushTwo).get(10, TimeUnit.SECONDS);
        assertThat(dualSinkTasksCompleted.get()).isEqualTo(4);
    }

    @Test
    void flushPool_runsThreeAdaptiveFlushesWithOneControlTaskOfHeadroom() throws Exception {
        CountDownLatch started = new CountDownLatch(4);
        CountDownLatch release = new CountDownLatch(1);
        List<CompletableFuture<Void>> tasks = IntStream.range(0, 4)
                .mapToObj(ignored -> supplyFlush(() -> {
                    started.countDown();
                    await(release);
                }))
                .toList();
        try {
            assertThat(started.await(10, TimeUnit.SECONDS)).isTrue();
        } finally {
            release.countDown();
        }

        CompletableFuture.allOf(tasks.toArray(CompletableFuture[]::new))
                .get(10, TimeUnit.SECONDS);
    }

    @Test
    void stats_reportsFlushAndDualSinkPoolPressureWithoutCreatingWorkers() {
        SnapshotFlushExecutor.Snapshot before = SnapshotFlushExecutor.stats();
        assertThat(before.flush().poolSize()).isZero();
        assertThat(before.dualSink().poolSize()).isZero();

        supplyFlush(() -> {}).join();
        supplyDualSink(() -> {}).join();
        SnapshotFlushExecutor.Snapshot after = SnapshotFlushExecutor.stats();

        assertThat(after.flush().poolSize()).isPositive();
        assertThat(after.dualSink().poolSize()).isPositive();
    }

    @Test
    void stopStartUnloadReload_retiresAllSevenOldWorkersAndCreatesUsableReplacements() throws Exception {
        ConcurrentLinkedQueue<Thread> firstRunThreads = new ConcurrentLinkedQueue<>();
        CountDownLatch coordinatorStarted = new CountDownLatch(1);
        CountDownLatch flushStarted = new CountDownLatch(4);
        CountDownLatch dualSinkStarted = new CountDownLatch(2);
        CountDownLatch holdPoolTasks = new CountDownLatch(1);

        StartupSnapshotCoordinator.beginRun(token);
        StartupSnapshotCoordinator.submit(
                StartupSnapshotCoordinator.Lane.FINDINGS,
                token,
                "lifecycle",
                () -> {
                    firstRunThreads.add(Thread.currentThread());
                    coordinatorStarted.countDown();
                    while (RuntimeConfig.isExportRunActive(token)) {
                        LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(5L));
                    }
                });
        IntStream.range(0, 4).forEach(ignored -> SnapshotFlushExecutor.supplyFlushAsync(token, () -> {
            firstRunThreads.add(Thread.currentThread());
            flushStarted.countDown();
            await(holdPoolTasks);
            return null;
        }));
        IntStream.range(0, 2).forEach(ignored -> SnapshotFlushExecutor.supplyDualSinkAsync(token, () -> {
            firstRunThreads.add(Thread.currentThread());
            dualSinkStarted.countDown();
            await(holdPoolTasks);
            return null;
        }));
        StartupSnapshotCoordinator.activateRun(token);

        assertThat(coordinatorStarted.await(5, TimeUnit.SECONDS)).isTrue();
        assertThat(flushStarted.await(5, TimeUnit.SECONDS)).isTrue();
        assertThat(dualSinkStarted.await(5, TimeUnit.SECONDS)).isTrue();
        assertThat(firstRunThreads).hasSize(7);

        ExportReporterLifecycle.stopAndClearPendingExportWork();

        awaitThreadsStopped(firstRunThreads);
        assertThat(firstRunThreads).allMatch(thread -> !thread.isAlive());
        assertThat(SnapshotFlushExecutor.stats().flush().poolSize()).isZero();
        assertThat(SnapshotFlushExecutor.stats().dualSink().poolSize()).isZero();

        RuntimeConfig.setExportRunning(true);
        ExportRunToken secondToken = RuntimeConfig.currentExportRunToken();
        assertThat(SnapshotFlushExecutor.beginRun(secondToken)).isTrue();
        StartupSnapshotCoordinator.beginRun(secondToken);
        ConcurrentLinkedQueue<Thread> secondRunThreads = runOneTaskPerPool(secondToken);
        assertThat(secondRunThreads).noneMatch(firstRunThreads::contains);

        ExportReporterLifecycle.stopAndClearSessionState();
        awaitThreadsStopped(secondRunThreads);
        assertThat(secondRunThreads).allMatch(thread -> !thread.isAlive());

        RuntimeConfig.setExportRunning(true);
        ExportRunToken reloadToken = RuntimeConfig.currentExportRunToken();
        assertThat(SnapshotFlushExecutor.beginRun(reloadToken)).isTrue();
        StartupSnapshotCoordinator.beginRun(reloadToken);
        ConcurrentLinkedQueue<Thread> reloadThreads = runOneTaskPerPool(reloadToken);
        assertThat(reloadThreads).hasSize(3).noneMatch(firstRunThreads::contains);
    }

    private static ConcurrentLinkedQueue<Thread> runOneTaskPerPool(ExportRunToken runToken) throws Exception {
        ConcurrentLinkedQueue<Thread> threads = new ConcurrentLinkedQueue<>();
        CountDownLatch coordinatorCompleted = new CountDownLatch(1);
        StartupSnapshotCoordinator.submit(
                StartupSnapshotCoordinator.Lane.SITEMAP,
                runToken,
                "replacement",
                () -> {
                    threads.add(Thread.currentThread());
                    coordinatorCompleted.countDown();
                });
        StartupSnapshotCoordinator.activateRun(runToken);
        CompletableFuture<Void> flush = SnapshotFlushExecutor.supplyFlushAsync(runToken, () -> {
            threads.add(Thread.currentThread());
            return null;
        });
        CompletableFuture<Void> dualSink = SnapshotFlushExecutor.supplyDualSinkAsync(runToken, () -> {
            threads.add(Thread.currentThread());
            return null;
        });

        assertThat(coordinatorCompleted.await(5, TimeUnit.SECONDS)).isTrue();
        CompletableFuture.allOf(flush, dualSink).get(5, TimeUnit.SECONDS);
        return threads;
    }

    private static void awaitThreadsStopped(Iterable<Thread> threads) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5L);
        for (Thread thread : threads) {
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0L) {
                return;
            }
            thread.join(Math.max(1L, TimeUnit.NANOSECONDS.toMillis(remaining)));
        }
    }

    private CompletableFuture<Void> supplyFlush(Runnable work) {
        return SnapshotFlushExecutor.supplyFlushAsync(token, () -> {
            work.run();
            return null;
        });
    }

    private CompletableFuture<Void> supplyDualSink(Runnable work) {
        return SnapshotFlushExecutor.supplyDualSinkAsync(token, () -> {
            work.run();
            return null;
        });
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
