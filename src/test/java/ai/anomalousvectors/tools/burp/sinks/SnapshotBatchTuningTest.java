package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class SnapshotBatchTuningTest {

    @Test
    void adjustTarget_growsOnFullSuccessWithinCap() {
        assertThat(SnapshotBatchTuning.adjustTarget(250, 250, 250)).isEqualTo(312);
        assertThat(SnapshotBatchTuning.adjustTarget(1490, 1490, 1490)).isEqualTo(1500);
    }

    @Test
    void adjustTarget_shrinksOnPartialFailureWithinFloor() {
        assertThat(SnapshotBatchTuning.adjustTarget(400, 400, 175)).isEqualTo(175);
        assertThat(SnapshotBatchTuning.adjustTarget(150, 150, 25)).isEqualTo(50);
    }

    @Test
    void adjustTarget_keepsCurrentWhenAttemptedCountIsZero() {
        assertThat(SnapshotBatchTuning.adjustTarget(360, 0, 0)).isEqualTo(360);
    }

    @Test
    void clampTargetForBulkBytes_capsDocTargetWhenAverageBodyIsLarge() {
        long fiveMiB = 5L * 1024 * 1024;
        int capped = SnapshotBatchTuning.clampTargetForBulkBytes(1500, fiveMiB, 10);
        assertThat(capped).isLessThan(1500);
        assertThat(capped).isGreaterThanOrEqualTo(50);
    }

    @Test
    void adjustTargetForChunk_appliesByteCapAfterSuccessGrowth() {
        long fiveMiB = 5L * 1024 * 1024;
        int next = SnapshotBatchTuning.adjustTargetForChunk(250, 250, 250, fiveMiB);
        assertThat(next).isLessThan(312);
        assertThat(next).isGreaterThanOrEqualTo(50);
    }
}
