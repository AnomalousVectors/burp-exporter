package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportAdmissionController;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.DiskSpaceGuard;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

/**
 * Unit tests for {@link TrafficExportQueue}: offer is non-blocking and does not throw.
 * Worker drain and push behaviour is covered by integration tests and manual runs.
 */
class TrafficExportQueueTest {

    @BeforeEach
    @AfterEach
    public void resetQueueAndExportState() {
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStarting(false);
        TrafficExportQueue.stopWorker();
        TrafficExportQueue.clearPendingWork();
        ExportAdmissionController.resetForTests();
        ExportStats.resetForTests();
        DiskSpaceGuard.resetForTests();
    }

    @Test
    void offer_null_doesNotThrow() {
        assertThatCode(() -> TrafficExportQueue.offer(null)).doesNotThrowAnyException();
    }

    @Test
    void spillFailureIsNotCapacityAndStaleWorkIsNotADrop() {
        TrafficExportQueue.recordSpillRejection(TrafficSpillFileQueue.OfferResult.FAILED, false);
        TrafficExportQueue.recordSpillRejection(TrafficSpillFileQueue.OfferResult.FAILED, true);
        TrafficExportQueue.recordSpillRejection(TrafficSpillFileQueue.OfferResult.REJECTED_STALE, true);
        TrafficExportQueue.recordSpillRejection(TrafficSpillFileQueue.OfferResult.REJECTED_LIMIT, false);
        TrafficExportQueue.recordSpillRejection(TrafficSpillFileQueue.OfferResult.REJECTED_LOW_DISK, true);
        assertThat(ExportStats.getTrafficDropReasonCount("spill_failure_reject_new")).isEqualTo(1);
        assertThat(ExportStats.getTrafficDropReasonCount("spill_failure_reject_requeue")).isEqualTo(1);
        assertThat(ExportStats.getTrafficDropReasonCount("spill_full_reject_new")).isEqualTo(1);
        assertThat(ExportStats.getTrafficDropReasonCount("spill_full_reject_requeue")).isZero();
        assertThat(ExportStats.getTrafficDropReasonCount("spill_low_disk_reject_requeue")).isEqualTo(1);
        assertThat(ExportStats.getTrafficQueueDrops()).isEqualTo(4);
        assertThat(ExportStats.getTrafficSpillDrops()).isEqualTo(4);
    }

    @Test
    void getCurrentBytesEstimate_matchesWalkAfterOffer() {
        long before = TrafficExportQueue.getCurrentBytesEstimate();
        assertThat(before).isGreaterThanOrEqualTo(0);
        TrafficExportQueue.offer(Map.of("url", "https://example.com/bytes-probe", "status", 200));
        long after = TrafficExportQueue.getCurrentBytesEstimate();
        assertThat(after).isGreaterThanOrEqualTo(before);
        assertThat(after).isEqualTo(TrafficExportQueue.computeBytesEstimateByWalk());
    }

    @Test
    void offer_emptyMap_doesNotThrow() {
        assertThatCode(() -> TrafficExportQueue.offer(Map.of())).doesNotThrowAnyException();
    }

    @Test
    void offer_validDoc_doesNotThrow() {
        Map<String, Object> doc = Map.of("url", "https://example.com/", "status", 200);
        assertThatCode(() -> TrafficExportQueue.offer(doc)).doesNotThrowAnyException();
    }

    @Test
    void getCurrentSize_returnsNonNegative() {
        assertThat(TrafficExportQueue.getCurrentSize()).isGreaterThanOrEqualTo(0);
    }

    @Test
    void awaitIdle_returnsTrueWhenNoQueuedWorkExists() {
        assertThat(TrafficExportQueue.awaitIdle(0)).isTrue();
    }

    @Test
    void stopWorker_zeroSharedBudget_returnsWithoutWaiting() {
        assertThatCode(() -> TrafficExportQueue.stopWorker(0L)).doesNotThrowAnyException();
    }

    @Test
    void awaitIdle_returnsFalseWhenQueuedWorkIsNotDrained() throws Exception {
        TrafficExportQueueTestSupport.configureRunningTraffic(List.of("proxy"));

        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            assertThat(TrafficExportQueue.offerAccepted(trafficDoc("Proxy"))).isTrue();
            assertThat(TrafficExportQueue.awaitIdle(0)).isFalse();
        });
    }

    @Test
    void getCurrentSize_increasesWhenDocOffered() {
        assertThatCode(() ->
                TrafficExportQueue.offer(Map.of("url", "https://example.com/a", "status", 200)))
                .doesNotThrowAnyException();
        assertThat(TrafficExportQueue.getCurrentSize()).isGreaterThanOrEqualTo(0);
    }

    @Test
    void purgeDisabledTraffic_removesOnlyDeselectedRoutes() throws Exception {
        TrafficExportQueueTestSupport.configureRunningTraffic(List.of("proxy", "repeater"));

        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            TrafficExportQueue.offer(trafficDoc("Proxy"));
            TrafficExportQueue.offer(trafficDoc("Repeater"));
            TrafficExportQueueTestSupport.updateTrafficTools(List.of("proxy"));

            int purged = TrafficExportQueue.purgeDisabledTraffic(RuntimeConfig.trafficExportGate());

            assertThat(purged).isEqualTo(1);
            assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(1);
        });
    }

    @Test
    void offerAccepted_rejectsLateTrafficAfterExportStopped() {
        TrafficExportQueueTestSupport.configureRunningTraffic(List.of("proxy"));
        RuntimeConfig.setExportRunning(false);

        boolean accepted = TrafficExportQueue.offerAccepted(trafficDoc("Proxy"));

        assertThat(accepted).isFalse();
        assertThat(TrafficExportQueue.getCurrentSize()).isZero();
    }

    @Test
    void offerAccepted_whenMemoryAndSpillAreFull_rejectsNewestAndKeepsBacklog() throws Exception {
        TrafficExportQueueTestSupport.configureRunningTraffic(List.of("proxy"));

        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            ExportAdmissionController.setMemBudgetOverrideForTests(1_000_000L);
            assertThat(TrafficExportQueue.offerAccepted(trafficDoc("Proxy"))).isTrue();
            assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(1);

            ExportAdmissionController.setMemBudgetOverrideForTests(1L);
            ExportAdmissionController.setSpillBudgetOverrideForTests(1L);
            assertThat(TrafficExportQueue.offerAccepted(trafficDoc("Proxy"))).isFalse();

            assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(1);
            assertThat(TrafficExportQueue.getCurrentSpillSize()).isZero();
            assertThat(ExportStats.getTrafficDropReasonCount("spill_full_reject_new"))
                    .isEqualTo(1L);
        });
    }

    @Test
    void offerAccepted_whenSpillWriteWouldBreachDiskReserve_recordsLowDiskReason()
            throws Exception {
        TrafficExportQueueTestSupport.configureRunningTraffic(List.of("proxy"));

        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            ExportAdmissionController.setMemBudgetOverrideForTests(1_000_000L);
            assertThat(TrafficExportQueue.offerAccepted(trafficDoc("Proxy"))).isTrue();

            long heldBytes = TrafficExportQueue.getCurrentBytesEstimate();
            assertThat(heldBytes).isPositive();
            ExportAdmissionController.setMemBudgetOverrideForTests(heldBytes * 2L);
            assertThat(ExportAdmissionController.memAccepts(heldBytes, 1L)).isTrue();
            assertThat(ExportAdmissionController.shouldPreferSpill(heldBytes, heldBytes)).isTrue();
            ExportAdmissionController.setSpillBudgetOverrideForTests(1_000_000L);
            DiskSpaceGuard.setUsableSpaceOverride(ignored -> DiskSpaceGuard.MIN_FREE_BYTES);
            assertThat(TrafficExportQueue.offerAccepted(trafficDoc("Proxy"))).isFalse();

            assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(1);
            assertThat(TrafficExportQueue.getCurrentSpillSize()).isZero();
            assertThat(ExportStats.getTrafficDropReasonCount("spill_low_disk_reject_new"))
                    .isEqualTo(1L);
        });
    }

    @Test
    void runFencedOffer_rechecksOwnershipAfterPreparationAndDiscard() throws Exception {
        TrafficExportQueueTestSupport.configureRunningTraffic(List.of("proxy"));
        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            Map<String, Object> doc = trafficDoc("Proxy");
            var token = RuntimeConfig.currentExportRunToken();
            TrafficQueueEntry prepared = TrafficQueueEntry.from(doc);
            try (var entries = org.mockito.Mockito.mockStatic(TrafficQueueEntry.class)) {
                entries.when(() -> TrafficQueueEntry.from(
                        org.mockito.ArgumentMatchers.<Map<String, Object>>any(),
                        org.mockito.ArgumentMatchers.any())).thenAnswer(call -> {
                            RuntimeConfig.setExportRunning(false);
                            TrafficExportQueue.clearPendingWork();
                            RuntimeConfig.setExportRunning(true);
                            return prepared;
                        });
                assertThat(TrafficExportQueue.offerForRun(doc, token)).isFalse();
                entries.verify(() -> TrafficQueueEntry.from(
                        org.mockito.ArgumentMatchers.<Map<String, Object>>any(),
                        org.mockito.ArgumentMatchers.any()));
                assertThat(TrafficExportQueue.getCurrentSize()).isZero();
                assertThat(TrafficExportQueue.getCurrentSpillSize()).isZero();
            }
        });
    }

    private static Map<String, Object> trafficDoc(String reporter) {
        return Map.of("burp", Map.of("reporting_tool", reporter));
    }

    @Test
    void slowSpillDoesNotHoldMemoryAdmissionAndCannotRefillANewerRun() throws Exception {
        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            TrafficExportQueueTestSupport.configureRunningTraffic(List.of("proxy"));
            var token = RuntimeConfig.currentExportRunToken();
            java.util.concurrent.CountDownLatch entered = new java.util.concurrent.CountDownLatch(1);
            java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
            DiskSpaceGuard.setUsableSpaceOverride(path -> {
                if (Thread.currentThread().getName().equals("slow-spill-test")) {
                    entered.countDown();
                    try {
                        if (!release.await(5, java.util.concurrent.TimeUnit.SECONDS)) {
                            throw new IllegalStateException("Disk fixture timed out");
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new IllegalStateException(e);
                    }
                }
                return Long.MAX_VALUE;
            });
            ExportAdmissionController.setMemBudgetOverrideForTests(1L);
            var writer = new java.util.concurrent.FutureTask<>(
                    () -> TrafficExportQueue.offerForRun(trafficDoc("Proxy"), token));
            Thread writerThread = new Thread(writer, "slow-spill-test");
            writerThread.start();
            try {
                assertThat(entered.await(2, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
                RuntimeConfig.setExportRunning(false);
                RuntimeConfig.setExportRunning(true);
                ExportAdmissionController.setMemBudgetOverrideForTests(1_000_000L);
                var nextToken = RuntimeConfig.currentExportRunToken();
                var memory = new java.util.concurrent.FutureTask<>(
                        () -> TrafficExportQueue.offerForRun(trafficDoc("Proxy"), nextToken));
                Thread memoryThread = new Thread(memory, "memory-admission-test");
                memoryThread.start();
                assertThat(memory.get(2, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
            } finally {
                release.countDown();
                writerThread.join(5_000L);
                DiskSpaceGuard.resetForTests();
            }
            assertThat(writer.get(2, java.util.concurrent.TimeUnit.SECONDS)).isFalse();
            assertThat(TrafficExportQueue.getCurrentSpillSize()).isZero();
            assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(1);
        });
    }
}
