package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportAdmissionController;

/** Focused Soft Outage recovery state-machine tests. */
class IndexingRetryCoordinatorCapacityRecoveryTest {

    @Test
    void reachableProbeAloneDoesNotClearSoftOutage() {
        resetSharedState();
        IndexingRetryCoordinator coordinator = IndexingRetryCoordinator.getInstance();
        try {
            coordinator.setSoftCapacityOutageForTests(true);

            coordinator.noteReachableProbeForTests();

            assertThat(coordinator.isSoftCapacityOutage()).isTrue();
        } finally {
            resetSharedState();
        }
    }

    @Test
    void admissionPreservesLiveTrafficInSpillWhileOutagePersists() {
        resetSharedState();
        IndexingRetryCoordinator coordinator = IndexingRetryCoordinator.getInstance();
        BulkRateLimitBackoff.clearCooldownDeadline();
        coordinator.setSoftCapacityOutageForTests(true);
        try {
            assertThat(BulkRateLimitBackoff.isCoolingDown()).isFalse();
            assertThat(ExportAdmissionController.shouldAdmitLiveTraffic()).isTrue();
            assertThat(ExportAdmissionController.shouldForceLiveTrafficToSpill()).isTrue();
            assertThat(ExportAdmissionController.shouldBackpressureSnapshots()).isTrue();
        } finally {
            resetSharedState();
        }
    }

    @Test
    void eightSpacedPayloadBulksClearButExporterBulksCannot() {
        resetSharedState();
        AtomicLong now = new AtomicLong();
        OfferedLoadGovernor governor = OfferedLoadGovernor.createForTests(
                now::get,
                now::addAndGet,
                () -> false,
                () -> 0L);
        OfferedLoadGovernor.setSharedForTests(governor);
        BulkRateLimitBackoff.clear();
        IndexingRetryCoordinator coordinator = IndexingRetryCoordinator.getInstance();
        try {
            coordinator.setSoftCapacityOutageForTests(true);

            for (int i = 0; i < OfferedLoadGovernor.RECOVERY_SUCCESS_STREAK * 2; i++) {
                now.addAndGet(OfferedLoadGovernor.MIN_SUCCESS_SPACING_NANOS);
                coordinator.noteFullPayloadBulkSuccess("exporter", 1024L);
            }
            assertThat(coordinator.isSoftCapacityOutage()).isTrue();

            for (int i = 1; i < OfferedLoadGovernor.RECOVERY_SUCCESS_STREAK; i++) {
                now.addAndGet(OfferedLoadGovernor.MIN_SUCCESS_SPACING_NANOS);
                coordinator.noteFullPayloadBulkSuccess("traffic", 1024L);
                assertThat(coordinator.isSoftCapacityOutage()).isTrue();
            }
            now.addAndGet(OfferedLoadGovernor.MIN_SUCCESS_SPACING_NANOS);
            coordinator.noteFullPayloadBulkSuccess("traffic", 1024L);

            assertThat(coordinator.isSoftCapacityOutage()).isFalse();
        } finally {
            resetSharedState();
        }
    }

    private static void resetSharedState() {
        IndexingRetryCoordinator coordinator = IndexingRetryCoordinator.getInstance();
        coordinator.stopDrainThread();
        coordinator.clearPendingWork();
        coordinator.setSoftCapacityOutageForTests(false);
        ExportAdmissionController.resetForTests();
        OfferedLoadGovernor.restoreProductionForTests();
        BulkRateLimitBackoff.clear();
    }
}
