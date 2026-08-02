package ai.anomalousvectors.tools.burp.sinks;

import ai.anomalousvectors.tools.burp.utils.Logger;

/**
 * Session-boundary logging for parameter-integrity and final Stats export outcomes.
 *
 * <p>Session-final Stats totals (File Counts, Database Counts, Misc Stats including Parameter
 * Integrity) are INFO from {@link ai.anomalousvectors.tools.burp.ui.StatsClipboardSnapshot} after
 * the final exporter stats push. Per-category live rollups remain in
 * {@link BodyEnumerationSkippedLog} and {@link CompressedWireBodyParamsLog}.</p>
 */
public final class ParameterIntegritySessionLog {

    private ParameterIntegritySessionLog() {}

    /**
     * Emits DEBUG URL samples from parameter-integrity rollups at Stop before teardown.
     *
     * <p>Safe to call multiple times; intended once per export Stop before connection teardown.
     * Clipboard-equivalent Stats totals are logged from
     * {@link ai.anomalousvectors.tools.burp.ui.StatsClipboardSnapshot#logSessionStopSummary()}
     * after the final exporter stats push.</p>
     */
    public static void flushStopDebugValidation() {
        BodyEnumerationSkippedLog.flushStopDebugSamples();
        CompressedWireBodyParamsLog.flushStopDebugSamples();
        BodyParameterTruncationLog.flushStopSummary();
        UrlParameterTruncationLog.flushStopSummary();
    }

    /**
     * Logs the final exporter stats push outcome at Stop.
     *
     * @param outcome result from {@link ExporterIndexStatsReporter#pushFinalSnapshotNow()}
     */
    public static void logFinalExporterStatsPush(ExporterStatsPushOutcome outcome) {
        if (outcome == null) {
            return;
        }
        switch (outcome.kind()) {
            case SUCCESS -> Logger.logInfoPanelOnly(
                    "[Stats] Final exporter stats push: success.");
            case SKIPPED_DISABLED, SKIPPED_NO_SINK -> Logger.logDebug(
                    "[Stats] Final exporter stats push: skipped ("
                            + outcome.detail() + ").");
            case FAILED -> Logger.logWarnPanelOnly(
                    "[Stats] Final exporter stats push: failed ("
                            + outcome.detail() + ").");
            default -> {
                // exhaustive enum
            }
        }
    }
}
