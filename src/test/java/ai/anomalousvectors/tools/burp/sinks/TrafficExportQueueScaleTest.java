package ai.anomalousvectors.tools.burp.sinks;

import static ai.anomalousvectors.tools.burp.testutils.SnapshotExportEngineTestSupport.preparedTrafficDoc;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportAdmissionController;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

/** Synthetic load tests for {@link TrafficExportQueue} depth and byte accounting. */
class TrafficExportQueueScaleTest {

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
                CountDownLatch start = new CountDownLatch(1);
                AtomicInteger accepted = new AtomicInteger();
                Thread firstProducer = new Thread(() -> offerAfterLatch(first, start, accepted));
                Thread secondProducer = new Thread(() -> offerAfterLatch(second, start, accepted));

                firstProducer.start();
                secondProducer.start();
                start.countDown();
                firstProducer.join();
                secondProducer.join();

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

    private static void offerAfterLatch(
            PreparedExportDocument document,
            CountDownLatch start,
            AtomicInteger accepted) {
        try {
            start.await();
            if (TrafficExportQueue.offerPreparedForTests(document)) {
                accepted.incrementAndGet();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
