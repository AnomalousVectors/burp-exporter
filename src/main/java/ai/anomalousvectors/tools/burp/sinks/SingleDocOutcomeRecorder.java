package ai.anomalousvectors.tools.burp.sinks;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.search.SearchPushCancellation;

/**
 * Shared single-document outcome accounting for reporters that push one document at a time.
 *
 * <p>Complements {@link BulkOutcomeRecorder} for callers such as {@code ExporterIndexConfigReporter},
 * {@code ExporterIndexLogForwarder}, {@code ExporterIndexStatsReporter}, and
 * {@code SettingsIndexReporter}, which each push individual documents via
 * {@code SearchClientWrapper.pushDocument} and would otherwise duplicate the same
 * {@code recordSuccess/recordFailure/recordLastError} triplet on every call site.</p>
 *
 * <p>When {@code openSearchActive} is {@code false}, counters are not touched (file-sink
 * accounting is handled elsewhere). Callers are responsible for any panel-only log output;
 * this helper intentionally avoids emitting logs because prefix and wording vary per reporter.</p>
 */
public final class SingleDocOutcomeRecorder {

    private SingleDocOutcomeRecorder() {}

    /**
     * Records one single-document push outcome for {@code indexKey}.
     *
     * @param indexKey logical index key (for example {@code "exporter"}, {@code "settings"});
     *                 must not be {@code null} or blank
     * @param ok {@code true} when the push succeeded; {@code false} when it failed
     * @param openSearchActive whether the OpenSearch sink was active for this push; when
     *                         {@code false} the helper returns without touching counters
     * @param errorSummary short error description stored via
     *                     {@link ExportStats#recordLastError(String, String)} when {@code !ok};
     *                     blank or {@code null} falls back to {@code "Single-document push failed"}
     * @throws IllegalArgumentException if {@code indexKey} is {@code null} or blank
     */
    public static void record(
            String indexKey,
            boolean ok,
            boolean openSearchActive,
            String errorSummary) {
        if (indexKey == null || indexKey.isBlank()) {
            throw new IllegalArgumentException("indexKey must not be blank");
        }
        if (!openSearchActive) {
            return;
        }
        if (ok) {
            // Index success counters are recorded by SearchClientWrapper.pushDocument.
            return;
        }
        if (SearchPushCancellation.shouldSuppressFailureAccounting()) {
            return;
        }
        ExportStats.recordFailure(indexKey, 1);
        String resolved = (errorSummary == null || errorSummary.isBlank())
                ? "Single-document push failed"
                : errorSummary;
        ExportStats.recordLastError(indexKey, resolved);
    }
}
