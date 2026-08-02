package ai.anomalousvectors.tools.burp.utils;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Constrained-heap / headroom budget coverage for {@link ExportAdmissionController}.
 */
class ExportAdmissionControllerTest {

    @AfterEach
    void tearDown() {
        ExportAdmissionController.resetForTests();
    }

    @Test
    void memBudget_respectsOverrideIncludingConstrainedHeap() {
        ExportAdmissionController.setMemBudgetOverrideForTests(4L * 1024L * 1024L);
        assertThat(ExportAdmissionController.memBudgetBytes()).isEqualTo(4L * 1024L * 1024L);

        ExportAdmissionController.setMemBudgetOverrideForTests(512L * 1024L * 1024L);
        assertThat(ExportAdmissionController.memBudgetBytes())
                .isEqualTo(512L * 1024L * 1024L);
    }

    @Test
    void memAccepts_hardWatermarkRejectsWhenNearBudget() {
        ExportAdmissionController.setMemBudgetOverrideForTests(10L * 1024L * 1024L);
        long budget = ExportAdmissionController.memBudgetBytes();
        long hard = (long) (budget * ExportAdmissionController.MEM_HARD_WATERMARK);
        assertThat(ExportAdmissionController.memAccepts(hard - 1L, 1L)).isTrue();
        assertThat(ExportAdmissionController.memAccepts(hard, 1L)).isFalse();
    }

    @Test
    void shouldPreferSpill_softWatermark() {
        ExportAdmissionController.setMemBudgetOverrideForTests(10L * 1024L * 1024L);
        long budget = ExportAdmissionController.memBudgetBytes();
        long soft = (long) (budget * ExportAdmissionController.MEM_SOFT_WATERMARK);
        assertThat(ExportAdmissionController.shouldPreferSpill(soft - 1L, 1L)).isFalse();
        assertThat(ExportAdmissionController.shouldPreferSpill(soft + 1L, 1L)).isTrue();
    }

    @Test
    void classifySpill_readyInUseFull() {
        assertThat(ExportAdmissionController.classifySpill(0, 0L, 1000L, true))
                .isEqualTo(ExportAdmissionController.SpillStatus.READY);
        assertThat(ExportAdmissionController.classifySpill(10, 100L, 1000L, true))
                .isEqualTo(ExportAdmissionController.SpillStatus.IN_USE);
        assertThat(ExportAdmissionController.classifySpill(10, 100L, 1000L, false))
                .isEqualTo(ExportAdmissionController.SpillStatus.FULL);
    }

    @Test
    void retryBudget_overrideApplies() {
        ExportAdmissionController.setRetryBudgetOverrideForTests(16L * 1024L * 1024L);
        assertThat(ExportAdmissionController.retryBudgetBytes()).isEqualTo(16L * 1024L * 1024L);
        assertThat(ExportAdmissionController.retryBudgetBytesPerIndex())
                .isEqualTo(16L * 1024L * 1024L);
    }

    @Test
    void spillBudget_overrideApplies() {
        ExportAdmissionController.setSpillBudgetOverrideForTests(64L * 1024L * 1024L);
        assertThat(ExportAdmissionController.spillBudgetBytes(null))
                .isEqualTo(64L * 1024L * 1024L);
    }
}
