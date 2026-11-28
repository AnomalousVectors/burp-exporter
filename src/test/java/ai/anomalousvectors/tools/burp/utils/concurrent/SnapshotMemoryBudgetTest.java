package ai.anomalousvectors.tools.burp.utils.concurrent;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import ai.anomalousvectors.tools.burp.utils.ExportStats;

/** Exercises bounded admission without allocating large payloads or generating network traffic. */
@Timeout(10)
class SnapshotMemoryBudgetTest {
    @AfterEach
    void resetCounters() {
        assertThat(ExportStats.getSnapshotBuildAheadReservedPermits()).isZero();
        ExportStats.resetForTests();
    }

    @Test
    void oversizedReservationBlocksAnotherBuilderUntilReleased() throws Exception {
        SnapshotMemoryBudget budget = new SnapshotMemoryBudget();
        var first = budget.acquire(Long.MAX_VALUE, () -> true);
        try (var worker = Executors.newSingleThreadExecutor()) {
            CountDownLatch attempted = new CountDownLatch(1);
            var next = worker.submit(() -> {
                attempted.countDown();
                return budget.acquire(1L, () -> true);
            });
            try {
                assertThat(attempted.await(1, TimeUnit.SECONDS)).isTrue();
                assertThat(ExportStats.getSnapshotBuildAheadReservedPermits()).isEqualTo(1_024);
                assertThat(next.isDone()).isFalse();
                first.close();
                try (var admitted = next.get(1, TimeUnit.SECONDS)) {
                    assertThat(admitted).isNotNull();
                    assertThat(ExportStats.getSnapshotBuildAheadReservedPermits()).isEqualTo(1);
                }
            } finally {
                first.close();
                next.cancel(true);
                worker.shutdownNow();
            }
        } finally {
            first.close();
        }
    }

    @Test
    void underestimatedCompletedBuildsReconcileWithoutUpgradeDeadlock() throws Exception {
        SnapshotMemoryBudget budget = new SnapshotMemoryBudget();
        var first = budget.acquire(1L, () -> true);
        try (var second = budget.acquire(1L, () -> true)) {
            first.accountPreparedBytes(Long.MAX_VALUE);
            second.accountPreparedBytes(Long.MAX_VALUE);
            assertThat(ExportStats.getSnapshotBuildAheadReservedPermits()).isEqualTo(2_048);
            assertThat(budget.acquire(1L, () -> false)).isNull();
            first.close();
            first.close();
            assertThat(ExportStats.getSnapshotBuildAheadReservedPermits()).isEqualTo(1_024);
        } finally {
            first.close();
        }
    }

    @Test
    void startResetRetainsReservationsStillOwnedByOlderWork() throws Exception {
        SnapshotMemoryBudget budget = new SnapshotMemoryBudget();
        try (var reservation = budget.acquire(Long.MAX_VALUE, () -> true)) {
            assertThat(reservation).isNotNull();
            ExportStats.resetForRun();
            assertThat(ExportStats.getSnapshotBuildAheadReservedPermits()).isEqualTo(1_024);
            assertThat(ExportStats.getPeakSnapshotBuildAheadReservedPermits()).isEqualTo(1_024);
        }
    }

    @Test
    void inactiveRunDoesNotAcquireAndInterruptedWaitDoesNotLeak() throws Exception {
        SnapshotMemoryBudget budget = new SnapshotMemoryBudget();
        assertThat(budget.acquire(1L, () -> false)).isNull();
        try (var first = budget.acquire(Long.MAX_VALUE, () -> true);
                var worker = Executors.newSingleThreadExecutor()) {
            assertThat(first).isNotNull();
            CountDownLatch attempted = new CountDownLatch(1);
            var blocked = worker.submit(() -> {
                attempted.countDown();
                return budget.acquire(1L, () -> true);
            });
            try {
                assertThat(attempted.await(1, TimeUnit.SECONDS)).isTrue();
                blocked.cancel(true);
                worker.shutdownNow();
                assertThat(worker.awaitTermination(1, TimeUnit.SECONDS)).isTrue();
                assertThat(ExportStats.getSnapshotBuildAheadReservedPermits()).isEqualTo(1_024);
            } finally {
                blocked.cancel(true);
                worker.shutdownNow();
            }
        }
    }
}
