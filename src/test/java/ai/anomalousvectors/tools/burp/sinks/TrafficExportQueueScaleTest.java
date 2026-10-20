package ai.anomalousvectors.tools.burp.sinks;

import static ai.anomalousvectors.tools.burp.testutils.SnapshotExportEngineTestSupport.preparedTrafficDoc;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportAdmissionController;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

/** Synthetic load tests for {@link TrafficExportQueue} depth and byte accounting. */
class TrafficExportQueueScaleTest {

    @BeforeEach
    @AfterEach
    void resetMetricsAndAdmission() {
        ExportStats.resetForTests();
        ExportAdmissionController.resetForTests();
    }

    @Test
    void enqueue_manyPreparedEntries_tracksDepthAndBytes() throws Exception {
        ExportStats.resetForTests();
        try {
            TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
                int offers = 5_000;
                long bytesPerDoc = 4_096L;
                ExportAdmissionController.setMemBudgetOverrideForTests(offers * bytesPerDoc * 2L);
                String indexName = IndexNaming.indexNameForShortName("traffic");
                for (int i = 0; i < offers; i++) {
                    assertThat(TrafficExportQueue.offerPreparedForTests(
                                    preparedTrafficDoc(indexName, i, bytesPerDoc)))
                            .isTrue();
                }

                assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(offers);
                assertThat(TrafficExportQueue.getCurrentBytesEstimate()).isEqualTo(offers * bytesPerDoc);

                ExportStats.observeExportPressureSamples(
                        TrafficExportQueue.getCurrentSize(),
                        TrafficExportQueue.getCurrentBytesEstimate(),
                        0,
                        0L,
                        0,
                        0L);
                assertThat(ExportStats.getPeakTrafficQueueDocs()).isEqualTo(offers);
                assertThat(ExportStats.getPeakTrafficQueueBytes()).isEqualTo(offers * bytesPerDoc);
            });
        } finally {
            ExportAdmissionController.resetForTests();
        }
    }

    @Test
    void enqueue_concurrentPreparedEntries_reservesHardByteBudgetAtomically() throws Exception {
        ExportStats.resetForTests();
        try {
            TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
                String indexName = IndexNaming.indexNameForShortName("traffic");
                PreparedExportDocument first = preparedTrafficDoc(indexName, 1, 4_096L);
                PreparedExportDocument second = preparedTrafficDoc(indexName, 2, 4_096L);
                ExportAdmissionController.setMemBudgetOverrideForTests(5_000L);
                AtomicInteger accepted = new AtomicInteger();
                runProducers(
                        () -> offer(first, accepted),
                        () -> offer(second, accepted));

                assertThat(accepted.get()).isEqualTo(1);
                assertThat(TrafficExportQueue.getCurrentBytesEstimate()).isEqualTo(4_096L);
                assertThat(TrafficExportQueue.computeBytesEstimateByWalk()).isEqualTo(4_096L);
                TrafficExportQueue.clearPendingWork();
                assertThat(TrafficExportQueue.getCurrentBytesEstimate()).isZero();
                assertThat(TrafficExportQueue.computeBytesEstimateByWalk()).isZero();
            });
        } finally {
            ExportAdmissionController.resetForTests();
        }
    }

    @Test
    void producerFailure_reachesJUnit_andRetiresTheBlockedPeer() {
        CountDownLatch peerStarted = new CountDownLatch(1);
        CountDownLatch releasePeer = new CountDownLatch(1);
        AtomicBoolean peerInterrupted = new AtomicBoolean();
        IllegalStateException failure = new IllegalStateException("synthetic producer failure");
        try {
            assertThatThrownBy(() -> runProducers(
                    () -> {
                        assertThat(peerStarted.await(2, TimeUnit.SECONDS)).isTrue();
                        throw failure;
                    },
                    () -> {
                        peerStarted.countDown();
                        try {
                            releasePeer.await();
                        } catch (InterruptedException interrupted) {
                            peerInterrupted.set(true);
                            Thread.currentThread().interrupt();
                        }
                    }))
                    .isInstanceOf(ExecutionException.class).hasCause(failure);
            assertThat(peerInterrupted).isTrue();
        } finally {
            releasePeer.countDown();
        }
    }

    /** Futures expose worker failures; termination precedes queue/global fixture cleanup. */
    private static void runProducers(
            TrafficExportQueueTestSupport.ThrowingRunnable firstAction,
            TrafficExportQueueTestSupport.ThrowingRunnable secondAction) throws Exception {
        ExecutorService producers = Executors.newFixedThreadPool(2);
        CountDownLatch start = new CountDownLatch(1);
        try {
            Future<?> first = producers.submit(() -> {
                start.await();
                firstAction.run();
                return null;
            });
            Future<?> second = producers.submit(() -> {
                start.await();
                secondAction.run();
                return null;
            });
            start.countDown();
            first.get(2, TimeUnit.SECONDS);
            second.get(2, TimeUnit.SECONDS);
        } finally {
            start.countDown();
            producers.shutdownNow();
            assertThat(producers.awaitTermination(2, TimeUnit.SECONDS))
                    .as("Both producer owners must retire before shared state is reset").isTrue();
        }
    }

    private static void offer(PreparedExportDocument document, AtomicInteger accepted) {
        if (TrafficExportQueue.offerPreparedForTests(document)) {
            accepted.incrementAndGet();
        }
    }
}
