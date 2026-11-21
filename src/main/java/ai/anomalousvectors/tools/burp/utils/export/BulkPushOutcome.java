package ai.anomalousvectors.tools.burp.utils.export;

/**
 * Outcome of one prepared bulk push through the shared destination wrapper.
 *
 * <p>For Database export, the indexed count excludes noops. Files-only factories use the offered
 * count as the delivery-path result; file-write success and integrity remain independently
 * recorded by {@link ai.anomalousvectors.tools.burp.utils.FileExportStats}.</p>
 *
 * @param attempted documents offered to sinks
 * @param exportedCount database documents indexed, or offered count for a Files-only outcome
 * @param breakdown per-item database classification when the destination was active
 * @param fileFlushMs file-write elapsed milliseconds, or {@code -1} when unavailable
 * @param openSearchFlushMs database-write elapsed milliseconds, or {@code -1} when unavailable
 */
public record BulkPushOutcome(
        int attempted,
        int exportedCount,
        BulkOutcomeBreakdown breakdown,
        long fileFlushMs,
        long openSearchFlushMs) {

    /**
     * Creates an outcome without destination timing measurements.
     *
     * @param attempted documents offered to the destination path
     * @param exportedCount indexed count, or offered count for Files alone
     * @param breakdown per-item database classification
     */
    public BulkPushOutcome(int attempted, int exportedCount, BulkOutcomeBreakdown breakdown) {
        this(attempted, exportedCount, breakdown, -1L, -1L);
    }

    /**
     * Returns the offered chunk size, not a destination acknowledgment.
     */
    public int accepted() {
        return attempted;
    }

    /**
     * Returns indexed database documents, or the offered count for a Files-only outcome.
     *
     * <p>Database counts exclude {@code noop} items. Files-only callers must use file statistics
     * to determine which appends succeeded.</p>
     */
    public int successCount() {
        return exportedCount;
    }

    /**
     * Creates a Files-only path result without a database outcome.
     *
     * @param attempted documents offered to Files
     * @param fileFlushMs file-write elapsed milliseconds, or {@code -1} when unavailable
     * @return offered count with an empty database breakdown
     */
    public static BulkPushOutcome fileOnly(int attempted, long fileFlushMs) {
        return new BulkPushOutcome(attempted, attempted, BulkOutcomeBreakdown.empty(), fileFlushMs, -1L);
    }

    /**
     * Creates a Files-only path result without timing measurements.
     *
     * @param attempted documents offered to Files
     * @return offered count with no database or timing measurements
     */
    public static BulkPushOutcome fileOnly(int attempted) {
        return fileOnly(attempted, -1L);
    }

    /** Returns an empty outcome with no destination timing measurements. */
    public static BulkPushOutcome empty() {
        return new BulkPushOutcome(0, 0, BulkOutcomeBreakdown.empty());
    }

}
