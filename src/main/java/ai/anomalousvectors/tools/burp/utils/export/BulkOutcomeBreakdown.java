package ai.anomalousvectors.tools.burp.utils.export;

/**
 * Per-bulk OpenSearch outcome classified by index {@code result} when available.
 *
 * <p>{@link #exportedCount()} is {@code created + updated} — documents actually indexed.
 * {@link #successTotal()} also includes {@code noop} operations.</p>
 *
 * @param created newly created document count; negative values become zero
 * @param updated updated document count; negative values become zero
 * @param noop acknowledged operations that did not write a document; negative values become zero
 * @param failed failed operation count; negative values become zero
 */
public record BulkOutcomeBreakdown(int created, int updated, int noop, int failed) {

    /** Normalizes negative operation counts to zero. */
    public BulkOutcomeBreakdown {
        created = Math.max(0, created);
        updated = Math.max(0, updated);
        noop = Math.max(0, noop);
        failed = Math.max(0, failed);
    }

    /** Documents actually indexed to OpenSearch (excludes {@code noop}). */
    public int exportedCount() {
        return created + updated;
    }

    /** All successful bulk item operations. */
    public int successTotal() {
        return created + updated + noop;
    }

    /** Empty breakdown with no successes or failures. */
    public static BulkOutcomeBreakdown empty() {
        return new BulkOutcomeBreakdown(0, 0, 0, 0);
    }

    /**
     * Fallback when the transport layer only knows how many items succeeded without per-item
     * {@code result} classification.
     *
     * @param successCount acknowledged operations; negative values produce an empty breakdown
     * @return aggregate successes attributed to updates, with no failures
     */
    public static BulkOutcomeBreakdown assumeExported(int successCount) {
        return classified(successCount, successCount);
    }

    /**
     * Fallback when only aggregate success and attempt counts are known (no per-item {@code result}).
     *
     * @param successCount acknowledged operations; the caller supplies a valid aggregate count
     * @param attemptedCount attempted operations used to derive the non-negative failure count
     * @return breakdown with successful operations attributed to updates
     */
    public static BulkOutcomeBreakdown classified(int successCount, int attemptedCount) {
        int failed = Math.max(0, attemptedCount - successCount);
        if (successCount <= 0 && failed <= 0) {
            return empty();
        }
        return new BulkOutcomeBreakdown(0, successCount, 0, failed);
    }

    /**
     * Adds another outcome's operation counts without changing either record.
     *
     * @param other outcome to add; {@code null} leaves this record unchanged
     * @return combined outcome, or this record when {@code other} is {@code null}
     */
    public BulkOutcomeBreakdown plus(BulkOutcomeBreakdown other) {
        if (other == null) {
            return this;
        }
        return new BulkOutcomeBreakdown(
                created + other.created,
                updated + other.updated,
                noop + other.noop,
                failed + other.failed);
    }
}
