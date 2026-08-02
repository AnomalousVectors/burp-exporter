package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.BulkOutcomeBreakdown;
import ai.anomalousvectors.tools.burp.utils.export.BulkPushOutcome;

/**
 * Unit tests for {@link BulkOutcomeRecorder}, which centralizes success/failure bookkeeping
 * for bulk pushes across traffic and non-traffic reporters.
 */
class BulkOutcomeRecorderTest {

    @AfterEach
    public void resetStats() {
        ExportStats.resetForTests();
    }

    @Test
    void record_fullSuccess_recordsOnlySuccess() {
        RuntimeConfig.setExportRunning(true);
        int clamped = BulkOutcomeRecorder.record("sitemap", "Sitemap", "Bulk push", 4, 4, true);

        assertThat(clamped).isEqualTo(4);
        assertThat(ExportStats.getSuccessCount("sitemap")).isEqualTo(4);
        assertThat(ExportStats.getFailureCount("sitemap")).isZero();
    }

    @Test
    void record_partialFailureSkippedWhenExportStopped() {
        RuntimeConfig.setExportRunning(false);

        int clamped = BulkOutcomeRecorder.record("findings", "Findings", "Bulk push", 5, 3, true);

        assertThat(clamped).isEqualTo(3);
        assertThat(ExportStats.getSuccessCount("findings")).isEqualTo(3);
        assertThat(ExportStats.getFailureCount("findings")).isZero();
        assertThat(ExportStats.getLastError("findings")).isNull();
    }

    @Test
    void record_partialFailure_recordsBothAndLastError() {
        RuntimeConfig.setExportRunning(true);
        BulkOutcomeRecorder.record("findings", "Findings", "Bulk push", 5, 3, true);

        assertThat(ExportStats.getSuccessCount("findings")).isEqualTo(3);
        assertThat(ExportStats.getFailureCount("findings")).isEqualTo(2);
        assertThat(ExportStats.getLastError("findings")).contains("2 failure(s)");
    }

    @Test
    void record_openSearchInactive_isNoop() {
        int clamped = BulkOutcomeRecorder.record("sitemap", "Sitemap", "Bulk push", 4, 2, false);

        assertThat(clamped).isEqualTo(2);
        assertThat(ExportStats.getSuccessCount("sitemap")).isZero();
        assertThat(ExportStats.getFailureCount("sitemap")).isZero();
    }

    @Test
    void record_clampsSentAboveAttempted() {
        int clamped = BulkOutcomeRecorder.record("sitemap", "Sitemap", "Bulk push", 3, 99, true);

        assertThat(clamped).isEqualTo(3);
        assertThat(ExportStats.getSuccessCount("sitemap")).isEqualTo(3);
        assertThat(ExportStats.getFailureCount("sitemap")).isZero();
    }

    @Test
    void record_clampsNegativeAttemptedToZero() {
        int clamped = BulkOutcomeRecorder.record("sitemap", "Sitemap", "Bulk push", -7, 4, true);

        assertThat(clamped).isZero();
        assertThat(ExportStats.getSuccessCount("sitemap")).isZero();
        assertThat(ExportStats.getFailureCount("sitemap")).isZero();
    }

    @Test
    void record_usesFallbackPrefixAndLabelWhenBlank() {
        RuntimeConfig.setExportRunning(true);
        BulkOutcomeRecorder.record("findings", " ", null, 2, 0, true);
        assertThat(ExportStats.getLastError("findings")).contains("bulk push had");
    }

    @Test
    void record_breakdownWithPartialOsFailure_recordsOnlyRealFailures() {
        RuntimeConfig.setExportRunning(true);
        BulkOutcomeBreakdown breakdown = new BulkOutcomeBreakdown(0, 3, 0, 1);
        BulkPushOutcome outcome = new BulkPushOutcome(4, 3, breakdown);

        BulkOutcomeRecorder.record("sitemap", "Sitemap", "Bulk push", outcome, true);

        assertThat(ExportStats.getSuccessCount("sitemap")).isEqualTo(3);
        assertThat(ExportStats.getFailureCount("sitemap")).isEqualTo(1);
    }

    @Test
    void record_stoppedBreakdown_recordsConfirmedSuccessButSuppressesFailure() {
        RuntimeConfig.setExportRunning(false);
        BulkOutcomeBreakdown breakdown = new BulkOutcomeBreakdown(1, 2, 0, 1);

        BulkOutcomeRecorder.record("sitemap", "Sitemap", "Bulk push", 4, 3, true, breakdown);

        assertThat(ExportStats.getSuccessCount("sitemap")).isEqualTo(3);
        assertThat(ExportStats.getFailureCount("sitemap")).isZero();
        assertThat(ExportStats.getLastError("sitemap")).isNull();
    }

    @Test
    void record_rejectsBlankIndexKey() {
        assertThatThrownBy(() -> BulkOutcomeRecorder.record("", "X", "Bulk", 1, 1, true))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> BulkOutcomeRecorder.record(null, "X", "Bulk", 1, 1, true))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
