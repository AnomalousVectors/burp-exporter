package ai.anomalousvectors.tools.burp.utils.concurrent;

import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Unit tests for {@link Workers}: null-safety, zero-timeout short-circuit, normal shutdown,
 * and interrupt-and-join behavior for raw thread owners.
 */
class WorkersTest {

    @Test
    void awaitExecutorShutdown_nullExecutor_isNoOp() {
        assertThatCode(() -> Workers.awaitExecutorShutdown(null, 1_000L)).doesNotThrowAnyException();
    }

    @Test
    void awaitExecutorShutdown_zeroTimeout_callsShutdownNow_andReturnsImmediately() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Workers.awaitExecutorShutdown(executor, 0L);

            assertThat(executor.isShutdown()).isTrue();
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void awaitExecutorShutdown_normalShutdown_terminatesExecutor() throws Exception {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Workers.awaitExecutorShutdown(executor, 1_000L);

            assertThat(executor.isShutdown()).isTrue();
            assertThat(executor.awaitTermination(2, TimeUnit.SECONDS)).isTrue();
        } finally {
            executor.shutdownNow();
            assertThat(executor.awaitTermination(2, TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test
    void awaitThreadJoin_nullWorker_isNoOp() {
        assertThatCode(() -> Workers.awaitThreadJoin(null, 1_000L)).doesNotThrowAnyException();
    }

    @Test
    void awaitThreadJoin_interruptsAndJoinsWorker() throws Exception {
        CountDownLatch running = new CountDownLatch(1);
        CountDownLatch interrupted = new CountDownLatch(1);
        Thread worker = new Thread(() -> {
            running.countDown();
            try {
                java.util.concurrent.TimeUnit.MILLISECONDS.sleep(60_000L);
            } catch (InterruptedException e) {
                interrupted.countDown();
            }
        }, "workers-test-worker");
        worker.setDaemon(true);
        try {
            worker.start();
            assertThat(running.await(2, TimeUnit.SECONDS)).isTrue();

            Workers.awaitThreadJoin(worker, 2_000L);

            assertThat(interrupted.await(2, TimeUnit.SECONDS)).isTrue();
            assertThat(worker.isAlive()).isFalse();
        } finally {
            worker.interrupt();
            worker.join(2_000L);
            assertThat(worker.isAlive()).isFalse();
        }
    }

    @Test
    void awaitThreadJoin_zeroTimeout_interruptsWithoutJoining() throws Exception {
        CountDownLatch running = new CountDownLatch(1);
        CountDownLatch interrupted = new CountDownLatch(1);
        Thread worker = new Thread(() -> {
            running.countDown();
            try {
                java.util.concurrent.TimeUnit.MILLISECONDS.sleep(60_000L);
            } catch (InterruptedException e) {
                interrupted.countDown();
            }
        }, "workers-test-worker-nowait");
        worker.setDaemon(true);
        try {
            worker.start();
            assertThat(running.await(2, TimeUnit.SECONDS)).isTrue();

            // timeoutMs=0 requests interrupt without joining; the worker processes the interrupt
            // asynchronously, so we verify via a latch rather than the thread's interrupt flag
            // (which the worker clears when it catches InterruptedException).
            Workers.awaitThreadJoin(worker, 0L);

            assertThat(interrupted.await(2, TimeUnit.SECONDS)).isTrue();
            worker.join(2_000L);
            assertThat(worker.isAlive()).isFalse();
        } finally {
            worker.interrupt();
            worker.join(2_000L);
            assertThat(worker.isAlive()).isFalse();
        }
    }
}
