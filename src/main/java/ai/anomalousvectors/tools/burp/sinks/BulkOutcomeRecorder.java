package ai.anomalousvectors.tools.burp.sinks;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.export.BulkOutcomeBreakdown;
import ai.anomalousvectors.tools.burp.utils.export.BulkPushOutcome;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.concurrent.ExportRunContext;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchPushCancellation;

/**
 * Shared bulk-outcome accounting for search database bulk requests across reporters.
 *
 * <p>Centralizes the success/failure bookkeeping that one-shot and periodic reporters
 * (Sitemap, Findings, and — via {@link TrafficRouteBucket#recordBulkOutcome} — the traffic
 * reporters) would otherwise duplicate. Callers invoke this helper once per bulk request.</p>
 */
public final class BulkOutcomeRecorder {

    private BulkOutcomeRecorder() {}

    /**
     * Records one search database bulk outcome.
     *
     * <p>Safe to call from any thread. Updates export counters and failure details and may emit a
     * panel warning. Returns without mutation when the current run no longer accepts results.</p>
     *
     * @param indexKey logical index key credited with the outcome
     * @param logPrefix source label for a failure warning; blank uses {@code Export}
     * @param label operation label for failure details; blank uses {@code bulk push}
     * @param outcome bulk result; {@code null} is treated as an empty result
     * @param openSearchActive whether search-destination accounting is active
     * @return acknowledged document count after clamping, or {@code 0} when run mutation is denied
     * @throws IllegalArgumentException if accounting proceeds and {@code indexKey} is blank
     */
    public static int record(
            String indexKey,
            String logPrefix,
            String label,
            BulkPushOutcome outcome,
            boolean openSearchActive) {
        if (!ExportRunContext.allowsRunMutation()) {
            return 0;
        }
        if (outcome == null) {
            return record(indexKey, logPrefix, label, 0, 0, openSearchActive, null);
        }
        return record(
                indexKey,
                logPrefix,
                label,
                outcome.attempted(),
                outcome.successCount(),
                openSearchActive,
                outcome.breakdown());
    }

    /**
     * Records bulk counts without a detailed item breakdown.
     *
     * <p>Safe to call from any thread. Attempted and sent counts are clamped to a valid
     * non-negative range; active-destination failures update counters and may emit a warning.</p>
     *
     * @param indexKey logical index key credited with the outcome
     * @param logPrefix source label for a failure warning; blank uses {@code Export}
     * @param label operation label for failure details; blank uses {@code bulk push}
     * @param attempted attempted document count; negative values are treated as zero
     * @param sent acknowledged document count; clamped to {@code [0, attempted]}
     * @param openSearchActive whether search-destination accounting is active
     * @return clamped acknowledged document count
     * @throws IllegalArgumentException if {@code indexKey} is blank
     */
    public static int record(
            String indexKey,
            String logPrefix,
            String label,
            int attempted,
            int sent,
            boolean openSearchActive) {
        return record(indexKey, logPrefix, label, attempted, sent, openSearchActive, null);
    }

    /**
     * Records bulk counts and an optional item-level outcome breakdown.
     *
     * <p>Safe to call from any thread. Exported, no-op, and failure counters are updated when the
     * search destination is active. Expected cancellation suppresses failure accounting and its
     * warning while preserving the acknowledged count.</p>
     *
     * @param indexKey logical index key credited with the outcome
     * @param logPrefix source label for a failure warning; blank uses {@code Export}
     * @param label operation label for failure details; blank uses {@code bulk push}
     * @param attempted attempted document count; negative values are treated as zero
     * @param sent acknowledged document count; clamped to {@code [0, attempted]}
     * @param openSearchActive whether search-destination accounting is active
     * @param breakdown item-level outcome counts; {@code null} uses aggregate counts
     * @return clamped acknowledged document count
     * @throws IllegalArgumentException if {@code indexKey} is blank
     */
    public static int record(
            String indexKey,
            String logPrefix,
            String label,
            int attempted,
            int sent,
            boolean openSearchActive,
            BulkOutcomeBreakdown breakdown) {
        return recordDetailed(
                indexKey, logPrefix, label, attempted, sent, openSearchActive, breakdown).sent();
    }

    static RecordResult recordDetailed(
            String indexKey,
            String logPrefix,
            String label,
            int attempted,
            int sent,
            boolean openSearchActive,
            BulkOutcomeBreakdown breakdown) {
        if (indexKey == null || indexKey.isBlank()) {
            throw new IllegalArgumentException("indexKey must not be blank");
        }
        int clampedAttempted = Math.max(0, attempted);
        int clampedSent = Math.max(0, Math.min(sent, clampedAttempted));
        if (!openSearchActive) {
            return new RecordResult(clampedSent, false);
        }
        int transportFailure = clampedAttempted - clampedSent;
        int failure = breakdown != null
                ? Math.max(breakdown.failed(), transportFailure)
                : transportFailure;
        boolean failuresSuppressed = failure > 0
                && OpenSearchPushCancellation.shouldSuppressFailureAccounting();
        if (breakdown != null) {
            ExportStats.recordExported(indexKey, breakdown.exportedCount());
            ExportStats.recordNoop(indexKey, breakdown.noop());
            if (!failuresSuppressed && breakdown.failed() > 0) {
                ExportStats.recordFailure(indexKey, breakdown.failed());
            }
        } else if (clampedSent > 0) {
            ExportStats.recordSuccess(indexKey, clampedSent);
        }
        if (failure > 0) {
            if (failuresSuppressed) {
                return new RecordResult(clampedSent, true);
            }
            if (breakdown == null) {
                ExportStats.recordFailure(indexKey, failure);
            } else if (breakdown.failed() < failure) {
                ExportStats.recordFailure(indexKey, failure - breakdown.failed());
            }
            String resolvedLabel = (label == null || label.isBlank()) ? "bulk push" : label.trim();
            String resolvedSource = (logPrefix == null || logPrefix.isBlank()) ? "Export" : logPrefix.trim();
            ExportStats.recordLastError(indexKey, resolvedLabel + " had " + failure + " failure(s)");
            Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix() + " " + resolvedSource
                    + ": " + lowerFirst(resolvedLabel) + " completed with " + failure + " failure(s).");
        }
        return new RecordResult(clampedSent, false);
    }

    record RecordResult(int sent, boolean failuresSuppressed) { }

    private static String lowerFirst(String value) {
        if (value == null || value.isBlank()) {
            return "bulk";
        }
        return Character.toLowerCase(value.charAt(0)) + value.substring(1);
    }
}
