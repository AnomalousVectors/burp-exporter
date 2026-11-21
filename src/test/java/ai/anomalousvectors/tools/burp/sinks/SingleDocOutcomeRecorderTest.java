package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

/**
 * Unit tests for {@link SingleDocOutcomeRecorder}, covering the success/failure/last-error
 * accounting used by reporters that push one document at a time.
 *
 * <p>Static {@link ExportStats} counters are reset per-test via the constructor (JUnit 5
 * creates a new instance per {@code @Test} method by default), which keeps state isolated
 * without relying on a {@code @BeforeEach} hook.</p>
 */
class SingleDocOutcomeRecorderTest {

    public SingleDocOutcomeRecorderTest() {
        ExportStats.resetForTests();
    }

    @Test
    void record_success_leavesCountersToSearchClientWrapper() {
        SingleDocOutcomeRecorder.record("exporter", true, true, "should-be-ignored");

        assertThat(ExportStats.getSuccessCount("exporter")).isZero();
        assertThat(ExportStats.getFailureCount("exporter")).isZero();
        assertThat(ExportStats.getLastError("exporter")).isNull();
    }

    @Test
    void record_failureSkippedWhenExportStopped() {
        RuntimeConfig.setExportRunning(false);

        SingleDocOutcomeRecorder.record("exporter", false, true, "Exporter log push failed");

        assertThat(ExportStats.getFailureCount("exporter")).isZero();
        assertThat(ExportStats.getLastError("exporter")).isNull();
    }

    @Test
    void record_failure_incrementsFailureAndLastError() {
        RuntimeConfig.setExportRunning(true);
        SingleDocOutcomeRecorder.record("exporter", false, true, "Exporter config snapshot push failed");

        assertThat(ExportStats.getSuccessCount("exporter")).isZero();
        assertThat(ExportStats.getFailureCount("exporter")).isEqualTo(1);
        assertThat(ExportStats.getLastError("exporter")).isEqualTo("Exporter config snapshot push failed");
    }

    @Test
    void record_failureWithBlankSummary_usesDefaultMessage() {
        RuntimeConfig.setExportRunning(true);
        SingleDocOutcomeRecorder.record("settings", false, true, "  ");

        assertThat(ExportStats.getLastError("settings")).isEqualTo("Single-document push failed");
    }

    @Test
    void record_failureWithNullSummary_usesDefaultMessage() {
        RuntimeConfig.setExportRunning(true);
        SingleDocOutcomeRecorder.record("settings", false, true, null);

        assertThat(ExportStats.getLastError("settings")).isEqualTo("Single-document push failed");
    }

    @Test
    void record_openSearchInactive_isNoop() {
        SingleDocOutcomeRecorder.record("exporter", true, false, null);
        SingleDocOutcomeRecorder.record("exporter", false, false, "ignored");

        assertThat(ExportStats.getSuccessCount("exporter")).isZero();
        assertThat(ExportStats.getFailureCount("exporter")).isZero();
        assertThat(ExportStats.getLastError("exporter")).isNull();
    }

    @Test
    void record_rejectsBlankIndexKey() {
        assertThatThrownBy(() -> SingleDocOutcomeRecorder.record("", true, true, null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SingleDocOutcomeRecorder.record(null, true, true, null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SingleDocOutcomeRecorder.record("  ", true, true, null))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
