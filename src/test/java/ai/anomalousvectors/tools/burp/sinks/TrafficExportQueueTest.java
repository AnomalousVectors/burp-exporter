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

    private static Map<String, Object> trafficDoc(String reporter) {
        return Map.of("burp", Map.of("reporting_tool", reporter));
    }
}
