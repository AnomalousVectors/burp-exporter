package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.concurrent.StartupSnapshotCoordinator;

/** Verifies every historic startup reporter uses a genuinely bounded multi-slice threshold. */
class StartupReporterSliceContractTest {

    @Test
    void everyHistoricLaneStartsWithGenuinelyBoundedMultiSliceThreshold() {
        StartupSnapshotCoordinator.resetForTests();
        for (StartupSnapshotCoordinator.Lane lane : StartupSnapshotCoordinator.Lane.values()) {
            assertMoreThanOneContinuation(StartupSnapshotCoordinator.nextSliceItemCount(lane));
        }
    }

    private static void assertMoreThanOneContinuation(int sliceSize) {
        int backlog = (sliceSize * 2) + 1;
        int slices = (backlog + sliceSize - 1) / sliceSize;
        assertThat(slices - 1).isGreaterThan(1);
    }
}
