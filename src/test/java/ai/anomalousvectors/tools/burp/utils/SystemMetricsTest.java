package ai.anomalousvectors.tools.burp.utils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;

import java.lang.management.ManagementFactory;

import org.junit.jupiter.api.Test;

/**
 * Sanity coverage for {@link SystemMetrics#snapshot()}.
 *
 * <p>JMX values are JVM-dependent, so the test just pins the invariants the rest of the
 * codebase relies on: heap is non-negative, {@code used <= committed <= max}, and the
 * "available" buffer-pool fields are either non-negative or the explicit {@code -1}
 * sentinel.</p>
 */
class SystemMetricsTest {

    @Test
    void heapSnapshot_doesNotCollectManagementMetrics() {
        try (var management = mockStatic(ManagementFactory.class)) {
            SystemMetrics.HeapSnapshot heap = SystemMetrics.heapSnapshot();

            assertThat(heap.heapUsedBytes()).isGreaterThanOrEqualTo(0L);
            assertThat(heap.heapCommittedBytes()).isGreaterThanOrEqualTo(heap.heapUsedBytes());
            assertThat(heap.heapMaxBytes()).isGreaterThanOrEqualTo(heap.heapCommittedBytes());
            management.verifyNoInteractions();
        }
    }

    @Test
    void snapshot_reusesHeapOnlyCollection() {
        SystemMetrics.HeapSnapshot heap = new SystemMetrics.HeapSnapshot(100L, 200L, 400L);
        try (var metrics = mockStatic(SystemMetrics.class, CALLS_REAL_METHODS)) {
            metrics.when(SystemMetrics::heapSnapshot).thenReturn(heap);

            SystemMetrics.Snapshot snapshot = SystemMetrics.snapshot();

            assertThat(snapshot.heapUsedBytes()).isEqualTo(heap.heapUsedBytes());
            assertThat(snapshot.heapCommittedBytes()).isEqualTo(heap.heapCommittedBytes());
            assertThat(snapshot.heapMaxBytes()).isEqualTo(heap.heapMaxBytes());
            metrics.verify(SystemMetrics::heapSnapshot);
        }
    }

    @Test
    void snapshot_heapValuesAreOrdered_andCommittedExposed() {
        SystemMetrics.Snapshot snapshot = SystemMetrics.snapshot();

        assertThat(snapshot.heapUsedBytes()).isGreaterThanOrEqualTo(0L);
        assertThat(snapshot.heapCommittedBytes())
                .as("committed heap must be at least heap used")
                .isGreaterThanOrEqualTo(snapshot.heapUsedBytes());
        assertThat(snapshot.heapMaxBytes())
                .as("max heap must be at least committed")
                .isGreaterThanOrEqualTo(snapshot.heapCommittedBytes());
    }

    @Test
    void snapshot_bufferPoolFields_areNonNegativeOrMinusOneSentinel() {
        SystemMetrics.Snapshot snapshot = SystemMetrics.snapshot();
        assertThat(snapshot.directBufferUsedBytes()).isGreaterThanOrEqualTo(-1L);
        assertThat(snapshot.mappedBufferUsedBytes()).isGreaterThanOrEqualTo(-1L);
    }

    @Test
    void snapshot_threadCounts_areConsistent() {
        SystemMetrics.Snapshot snapshot = SystemMetrics.snapshot();
        assertThat(snapshot.threadCount()).isGreaterThan(0);
        assertThat(snapshot.peakThreadCount()).isGreaterThanOrEqualTo(snapshot.threadCount());
    }
}
