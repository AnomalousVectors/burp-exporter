package ai.anomalousvectors.tools.burp.sinks;

import ai.anomalousvectors.tools.burp.utils.Logger;

/**
 * Session-boundary logging for parameter-integrity and final Stats export outcomes.
 *
 * <p>Session-final Stats totals (File Counts, Database Counts, Misc Stats including Parameter
 * Integrity) are INFO from {@link ai.anomalousvectors.tools.burp.ui.StatsClipboardSnapshot} after
 * the final exporter stats push. Per-category live rollups remain in
     * {@link BodyEnumerationSkippedLog} and {@link CompressedWireBodyParamsLog}. Supplemental form
     * decoding records component counts here, with one DEBUG notice and changed totals at Stop;
     * repeated extraction for separate destinations is counted separately, not as unique traffic.</p>
 */
public final class ParameterIntegritySessionLog {

    private static final Object FORM_LOCK = new Object();
    private static long malformedFormComponents;
    private static long undecodableFormComponents;
    private static long reportedMalformedFormComponents;
    private static long reportedUndecodableFormComponents;
    private static boolean formNoticeEmitted;

    private ParameterIntegritySessionLog() {}

    /**
     * Resets form-decoding counters and notice state at an export-run boundary.
     *
     * <p>Safe from any thread. The lifecycle owner calls this before starting producers or after
     * their final flush; resetting an active run deliberately discards its accumulated totals.</p>
     */
    public static void startForCurrentRun() {
        synchronized (FORM_LOCK) {
            malformedFormComponents = 0;
            undecodableFormComponents = 0;
            reportedMalformedFormComponents = 0;
            reportedUndecodableFormComponents = 0;
            formNoticeEmitted = false;
        }
    }

    /** Counts exceptional components only; retains no URLs, parameter names, or values. */
    static void recordFormDecodingIssues(int malformed, int undecodable) {
        if (malformed == 0 && undecodable == 0) {
            return;
        }
        boolean first;
        synchronized (FORM_LOCK) {
            malformedFormComponents += malformed;
            undecodableFormComponents += undecodable;
            first = !formNoticeEmitted;
            formNoticeEmitted = true;
        }
        if (first) {
            Logger.logDebug("[ParameterIntegrity] Form decoding encountered malformed escapes or undecodable bytes; "
                    + "literal content was retained instead of discarding other parameters. "
                    + "A component summary follows at Stop.");
        }
    }

    /** Emits at most one summary per changed counter snapshot, including late shutdown work. */
    static void flushFormDecodingSummary() {
        long malformed;
        long undecodable;
        synchronized (FORM_LOCK) {
            malformed = malformedFormComponents;
            undecodable = undecodableFormComponents;
            if (malformed == reportedMalformedFormComponents && undecodable == reportedUndecodableFormComponents) {
                return;
            }
            reportedMalformedFormComponents = malformed;
            reportedUndecodableFormComponents = undecodable;
        }
        Logger.logDebug("[ParameterIntegrity] Form decoding component totals: malformed_escape=" + malformed
                + ", undecodable=" + undecodable
                + "; malformed escapes remain literal and undecodable components retain their encoded spelling.");
    }

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
        flushFormDecodingSummary();
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
