package ai.anomalousvectors.tools.burp.utils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import ai.anomalousvectors.tools.burp.utils.search.BulkRateLimitBackoff;

/**
 * Constrained-heap / headroom budget coverage for {@link ExportAdmissionController}.
 */
class ExportAdmissionControllerTest {

    private static final long MIB = 1024L * 1024L;

    @AfterEach
    void tearDown() {
        ExportAdmissionController.resetForTests();
    }

    @ParameterizedTest
    @CsvSource({
            "0, 0, 0, 8, 8",
            "100, 300, 600, 16, 12",
            "100, 500, 300, 16, 12",
            "100, 100, 300, 16, 12",
            "100, 300, -1, 16, 12",
            "0, 10000, 20000, 256, 256"
    })
    void productionBudgets_useOnlyHeapHeadroom(long usedMiB, long committedMiB, long maxMiB,
            long memoryMiB, long retryMiB) {
        try (var metrics = mockStatic(SystemMetrics.class);
                var cooldown = mockStatic(BulkRateLimitBackoff.class)) {
            metrics.when(SystemMetrics::heapSnapshot).thenReturn(new SystemMetrics.HeapSnapshot(
                    usedMiB * MIB, committedMiB * MIB, maxMiB * MIB));
            cooldown.when(BulkRateLimitBackoff::isCoolingDown).thenReturn(false);

            assertThat(ExportAdmissionController.memBudgetBytes()).isEqualTo(memoryMiB * MIB);
            assertThat(ExportAdmissionController.retryBudgetBytes()).isEqualTo(retryMiB * MIB);
            assertThat(ExportAdmissionController.retryBudgetBytesPerIndex())
                    .isEqualTo(Math.max(8L, retryMiB / 2L) * MIB);
            metrics.verify(SystemMetrics::snapshot, never());
        }
    }

    @Test
    void productionBudgets_preservePressureAdjustment() {
        try (var metrics = mockStatic(SystemMetrics.class);
                var cooldown = mockStatic(BulkRateLimitBackoff.class)) {
            metrics.when(SystemMetrics::heapSnapshot).thenReturn(new SystemMetrics.HeapSnapshot(
                    100L * MIB, 900L * MIB, 2000L * MIB));
            cooldown.when(BulkRateLimitBackoff::isCoolingDown).thenReturn(true);

            assertThat(ExportAdmissionController.memBudgetBytes()).isEqualTo(32L * MIB);
            assertThat(ExportAdmissionController.retryBudgetBytes()).isEqualTo(24L * MIB);
            assertThat(ExportAdmissionController.retryBudgetBytesPerIndex()).isEqualTo(12L * MIB);
            metrics.verify(SystemMetrics::snapshot, never());
        }
    }

    @Test
    void liveReservationAndWatermarks_doNotCollectFullProcessMetrics() {
        try (var metrics = mockStatic(SystemMetrics.class)) {
            metrics.when(SystemMetrics::heapSnapshot).thenReturn(new SystemMetrics.HeapSnapshot(
                    100L * MIB, 900L * MIB, 2000L * MIB));

            assertThat(ExportAdmissionController.tryReserveLiveBytes(1L)).isTrue();
            try {
                assertThat(ExportAdmissionController.memAccepts(0L, 1L)).isTrue();
                assertThat(ExportAdmissionController.shouldPreferSpill(0L, 1L)).isFalse();
                assertThat(ExportAdmissionController.tryReserveLiveBytes(0L)).isTrue();
                metrics.verify(SystemMetrics::snapshot, never());
            } finally {
                ExportAdmissionController.releaseLiveBytes(1L);
            }
        }
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
