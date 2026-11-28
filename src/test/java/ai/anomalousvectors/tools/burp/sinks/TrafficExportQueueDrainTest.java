package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import ai.anomalousvectors.tools.burp.testutils.Reflect;
import ai.anomalousvectors.tools.burp.utils.DiskSpaceGuard;
import ai.anomalousvectors.tools.burp.utils.ExportAdmissionController;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

/** Verifies the distinction between an idle traffic worker and a batch still being delivered. */
class TrafficExportQueueDrainTest {

    @TempDir
    Path directory;

    @BeforeEach
    @AfterEach
    void reset() {
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStarting(false);
        RuntimeConfig.setExportStopping(false);
        TrafficExportQueue.stopWorker();
        TrafficExportQueue.clearPendingWork();
        FileExportService.resetForTests();
        ExportAdmissionController.resetForTests();
        ExportStats.resetForTests();
        DiskSpaceGuard.resetForTests();
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void emptyWorker_isIdleForFilesAndDatabase(boolean database) throws Exception {
        configure(database);
        Reflect.callStatic(TrafficExportQueue.class, "startWorkerIfNeeded");
        Thread worker = Reflect.getStatic(TrafficExportQueue.class, "drainWorker", Thread.class);
        awaitEmptyQueueWait(worker);

        assertThat(TrafficExportQueue.getActiveDrainBatches()).isZero();
        assertThat(TrafficExportQueue.awaitPendingWorkDrained(0L)).isTrue();
        assertThat(TrafficExportQueue.awaitIdle(0L)).isTrue();
        RuntimeConfig.beginExportStop();
        RuntimeConfig.setExportStopping(true);
        assertThat(TrafficExportQueue.awaitPendingWorkDrained(0L)).isTrue();
        TrafficExportQueue.stopWorker(1_000L);
        assertThat(worker.isAlive()).isFalse();
    }

    @Test
    void idleWorker_wakesForWorkAndKeepsDequeuedWriteActiveDuringStop() throws Exception {
        configure(false);
        CountDownLatch writing = new CountDownLatch(1);
        CountDownLatch releaseWrite = new CountDownLatch(1);
        DiskSpaceGuard.setUsableSpaceOverride(path -> {
            if (Thread.currentThread().getName().equals("burp-exporter-traffic-export")) {
                writing.countDown();
                try {
                    if (!releaseWrite.await(5, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("Timed out waiting to release the test write");
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("Interrupted test write", e);
                }
            }
            return Long.MAX_VALUE;
        });
        try {
            Reflect.callStatic(TrafficExportQueue.class, "startWorkerIfNeeded");
            Thread worker = Reflect.getStatic(TrafficExportQueue.class, "drainWorker", Thread.class);
            awaitEmptyQueueWait(worker);
            assertThat(TrafficExportQueue.offerAccepted(Map.of(
                    "burp", Map.of("reporting_tool", "Proxy"),
                    "request", Map.of("url", "https://example.test/drain")))).isTrue();
            assertThat(writing.await(2, TimeUnit.SECONDS)).isTrue();

            assertThat(TrafficExportQueue.getCurrentSize()).isZero();
            assertThat(TrafficExportQueue.getActiveDrainBatches()).isEqualTo(1);
            assertThat(TrafficExportQueue.awaitIdle(0L)).isFalse();
            RuntimeConfig.beginExportStop();
            RuntimeConfig.setExportStopping(true);
            assertThat(TrafficExportQueue.awaitPendingWorkDrained(0L)).isFalse();

            releaseWrite.countDown();
            assertThat(TrafficExportQueue.awaitPendingWorkDrained(2_000L)).isTrue();
            assertThat(FileExportStats.getWrittenCount("traffic")).isEqualTo(1L);
            assertThat(TrafficExportQueue.getActiveDrainBatches()).isZero();
        } finally {
            releaseWrite.countDown();
        }
    }

    private void configure(boolean database) {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"), "all", List.of(),
                new ConfigState.Sinks(!database, directory.toString(), false, !database,
                        database, database ? "https://opensearch.url:9200" : "", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB, List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES, null));
        RuntimeConfig.setExportRunning(true);
    }

    private static void awaitEmptyQueueWait(Thread worker) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < deadline) {
            if (worker.getState() == Thread.State.TIMED_WAITING
                    && Arrays.stream(worker.getStackTrace()).anyMatch(frame ->
                            frame.getClassName().endsWith("TrafficExportQueue$MeteredQueue"))) {
                return;
            }
            TimeUnit.MILLISECONDS.sleep(5L);
        }
        throw new AssertionError("Traffic worker did not reach its empty-queue wait");
    }
}
