package ai.anomalousvectors.tools.burp.utils.concurrent;

import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import ai.anomalousvectors.tools.burp.utils.ExportStats;

/**
 * Shared estimated-memory admission from snapshot construction through delivery.
 *
 * <p>Reservations are quantized, not heap measurements. Completed builds may reconcile above
 * the admission envelope; new builds then wait until capacity returns. An oversized estimate
 * reserves the entire envelope, while its full document remains eligible for Files output.</p>
 */
final class SnapshotMemoryBudget {
    private int held;

    synchronized Reservation acquire(long estimatedBytes, BooleanSupplier active) throws InterruptedException {
        int permits = SnapshotExportEngine.buildAheadReservationPermits(estimatedBytes);
        while (active.getAsBoolean()) {
            if (held + permits <= SnapshotExportEngine.maxBuildAheadPermits()) {
                held += permits;
                ExportStats.reserveSnapshotBuildAhead(
                        permits, SnapshotExportEngine.buildAheadReservationBytes(permits));
                return new Reservation(permits);
            }
            TimeUnit.MILLISECONDS.timedWait(this, 100L);
        }
        return null;
    }

    final class Reservation implements AutoCloseable {
        private int permits;
        private boolean closed;

        private Reservation(int permits) {
            this.permits = permits;
        }

        // Do not wait while upgrading a completed build: several underestimated items could
        // otherwise hold every permit while each waits for the others to release theirs.
        void accountPreparedBytes(long bytes) {
            synchronized (SnapshotMemoryBudget.this) {
                if (closed) return;
                int required = SnapshotExportEngine.buildAheadReservationPermits(bytes);
                int extra = Math.max(0, required - permits);
                held += extra;
                permits += extra;
                ExportStats.reserveSnapshotBuildAhead(
                        extra, SnapshotExportEngine.buildAheadReservationBytes(extra));
            }
        }

        /** Releases this reservation once; repeated calls after cancellation are harmless. */
        @Override
        public void close() {
            synchronized (SnapshotMemoryBudget.this) {
                if (closed) return;
                closed = true;
                held -= permits;
                ExportStats.releaseSnapshotBuildAhead(
                        permits, SnapshotExportEngine.buildAheadReservationBytes(permits));
                SnapshotMemoryBudget.this.notifyAll();
            }
        }
    }
}
