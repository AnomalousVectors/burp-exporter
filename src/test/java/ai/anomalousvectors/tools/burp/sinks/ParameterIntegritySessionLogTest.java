package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;

/** Unit tests for {@link ParameterIntegritySessionLog}. */
class ParameterIntegritySessionLogTest {

    private final List<String> infoMessages = new CopyOnWriteArrayList<>();
    private final List<String> debugMessages = new CopyOnWriteArrayList<>();
    private final List<String> warnMessages = new CopyOnWriteArrayList<>();
    private final Logger.LogListener listener = (level, message) -> {
        switch (level) {
            case "INFO" -> infoMessages.add(message);
            case "DEBUG" -> debugMessages.add(message);
            case "WARN" -> warnMessages.add(message);
            default -> {
            }
        }
    };

    /** Resets run counters and attaches an isolated log listener. */
    @BeforeEach
    public void setUp() {
        ExportStats.resetForTests();
        ParameterIntegritySessionLog.startForCurrentRun();
        Logger.resetState();
        Logger.registerListener(listener);
    }

    /** Detaches the listener and clears shared logging and run counters. */
    @AfterEach
    public void tearDown() {
        Logger.unregisterListener(listener);
        Logger.resetState();
        ExportStats.resetForTests();
        ParameterIntegritySessionLog.startForCurrentRun();
    }

    @Test
    void flushStopDebugValidation_doesNotEmitInfoOrOpenSearchProbeHints() throws Exception {
        ParameterIntegritySessionLog.flushStopDebugValidation();
        flushLogListeners();

        assertThat(infoMessages).isEmpty();
        assertThat(debugMessages).noneMatch(m -> m.contains("OpenSearch reconcile"));
        assertThat(debugMessages).noneMatch(m -> m.contains("acceptance probe"));
    }

    @Test
    void logFinalExporterStatsPush_successIsInfoOnly() throws Exception {
        ParameterIntegritySessionLog.logFinalExporterStatsPush(ExporterStatsPushOutcome.success());
        flushLogListeners();

        assertThat(infoMessages).anyMatch(m -> m.equals("[Stats] Final exporter stats push: success."));
        assertThat(debugMessages).isEmpty();
    }

    @Test
    void logFinalExporterStatsPush_expectedSkipIsDebugOnly() throws Exception {
        ParameterIntegritySessionLog.logFinalExporterStatsPush(ExporterStatsPushOutcome.skippedDisabled());
        flushLogListeners();

        assertThat(debugMessages).anyMatch(m -> m.startsWith("[Stats] Final exporter stats push: skipped"));
        assertThat(infoMessages).isEmpty();
        assertThat(warnMessages).isEmpty();
    }

    @Test
    void logFinalExporterStatsPush_failureIsWarnOnly() throws Exception {
        ParameterIntegritySessionLog.logFinalExporterStatsPush(
                ExporterStatsPushOutcome.failed("connection closed"));
        flushLogListeners();

        assertThat(warnMessages).anyMatch(m -> m.equals(
                "[Stats] Final exporter stats push: failed (connection closed)."));
        assertThat(debugMessages).isEmpty();
    }

    private static void flushLogListeners() throws Exception {
        SwingUtilities.invokeAndWait(() -> {});
    }

    @Test
    void formIssues_highVolumeEmitsOneNoticeAndOneSummaryWithoutContent() throws Exception {
        for (int i = 0; i < 20_000; i++) {
            ParameterIntegritySessionLog.recordFormDecodingIssues(1, 1);
        }
        ParameterIntegritySessionLog.flushFormDecodingSummary();
        ParameterIntegritySessionLog.flushFormDecodingSummary();
        flushLogListeners();

        assertThat(debugMessages).hasSize(2);
        assertThat(debugMessages.getLast()).contains("malformed_escape=20000", "undecodable=20000");
        assertThat(infoMessages).isEmpty();
        assertThat(warnMessages).isEmpty();
    }

    @Test
    void formIssues_resetAndLateFlushDoNotRepeatOldTotals() throws Exception {
        ParameterIntegritySessionLog.recordFormDecodingIssues(1, 0);
        ParameterIntegritySessionLog.flushFormDecodingSummary();
        ParameterIntegritySessionLog.recordFormDecodingIssues(0, 2);
        ParameterIntegritySessionLog.flushFormDecodingSummary();
        ParameterIntegritySessionLog.startForCurrentRun();
        ParameterIntegritySessionLog.recordFormDecodingIssues(0, 0);
        ParameterIntegritySessionLog.flushFormDecodingSummary();
        flushLogListeners();

        assertThat(debugMessages).hasSize(3);
        assertThat(debugMessages.getLast()).contains("malformed_escape=1", "undecodable=2");
    }
}
