package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.opensearch.ChunkedBulkSender;

/**
 * Unit tests for {@link TrafficExportQueue#applyBulkOutcome(ChunkedBulkSender.Result, long, int)},
 * covering the streaming drain's post-push accounting convergence on {@link BulkOutcomeRecorder}.
 *
 * <p>Assertions focus on index-level totals, per-tool-type and per-source counter propagation,
 * last-error visibility on partial failure, and byte/duration bookkeeping that StatsPanel reads.
 * Static {@link ExportStats} counters are reset per-test via the constructor so each case
 * observes deltas from a clean baseline.</p>
 */
class TrafficExportQueueBulkOutcomeTest {

    public TrafficExportQueueBulkOutcomeTest() {
        ExportStats.resetForTests();
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.setExportStarting(false);
    }

    @Test
    void applyBulkOutcome_fullSuccess_updatesCountsAndDoesNotRecordLastError() {
        ChunkedBulkSender.Result result = new ChunkedBulkSender.Result(
                4,
                4,
                1_000L,
                800L,
                Map.of("PROXY", 3, "REPEATER", 1),
                Map.of(),
                Map.of("proxy_live_http", 4),
                Map.of());

        TrafficExportQueue.applyBulkOutcome(result, 125L, 100);

        assertThat(ExportStats.getSuccessCount("traffic")).isEqualTo(4);
        assertThat(ExportStats.getFailureCount("traffic")).isZero();
        assertThat(ExportStats.getLastError("traffic")).isNull();
        assertThat(ExportStats.getLastLiveBulkDurationMs("traffic")).isEqualTo(125L);
        assertThat(ExportStats.getLastBulkTargetBatch()).isEqualTo(100);
        assertThat(ExportStats.getLastBulkAttemptedDocs()).isEqualTo(4);
        assertThat(ExportStats.getExportedBytes("traffic")).isEqualTo(800L);
        assertThat(ExportStats.getTrafficToolTypeSuccessCount("PROXY")).isEqualTo(3);
        assertThat(ExportStats.getTrafficToolTypeSuccessCount("REPEATER")).isEqualTo(1);
        assertThat(ExportStats.getTrafficToolTypeFailureCount("PROXY")).isZero();
        assertThat(ExportStats.getTrafficSourceSuccessCount("proxy_live_http")).isEqualTo(4);
        assertThat(ExportStats.getTrafficSourceFailureCount("proxy_live_http")).isZero();
    }

    @Test
    void applyBulkOutcome_partialFailure_recordsFailureMapsAndLastError() {
        ChunkedBulkSender.Result result = new ChunkedBulkSender.Result(
                3,
                5,
                2_000L,
                1_200L,
                Map.of("PROXY", 2, "REPEATER", 1),
                Map.of("PROXY", 1, "REPEATER", 1),
                Map.of("proxy_live_http", 3),
                Map.of("proxy_live_http", 2));

        TrafficExportQueue.applyBulkOutcome(result, 300L, 200);

        assertThat(ExportStats.getSuccessCount("traffic")).isEqualTo(3);
        assertThat(ExportStats.getFailureCount("traffic")).isEqualTo(2);
        assertThat(ExportStats.getLastError("traffic")).contains("2 failure(s)");
        assertThat(ExportStats.getTrafficToolTypeSuccessCount("PROXY")).isEqualTo(2);
        assertThat(ExportStats.getTrafficToolTypeFailureCount("PROXY")).isEqualTo(1);
        assertThat(ExportStats.getTrafficToolTypeFailureCount("REPEATER")).isEqualTo(1);
        assertThat(ExportStats.getTrafficSourceFailureCount("proxy_live_http")).isEqualTo(2);
        assertThat(ExportStats.getLastLiveBulkDurationMs("traffic")).isEqualTo(300L);
        assertThat(ExportStats.getExportedBytes("traffic")).isEqualTo(1_200L);
    }

    @Test
    void applyBulkOutcome_stoppedPartial_recordsSuccessMapsButSuppressesFailures() {
        RuntimeConfig.setExportRunning(false);
        ChunkedBulkSender.Result result = new ChunkedBulkSender.Result(
                1,
                2,
                1_000L,
                400L,
                Map.of("PROXY", 1),
                Map.of("REPEATER", 1),
                Map.of("proxy_live_http", 1),
                Map.of("repeater_live_http", 1));

        TrafficExportQueue.applyBulkOutcome(result, 100L, 10);

        assertThat(ExportStats.getSuccessCount("traffic")).isEqualTo(1);
        assertThat(ExportStats.getFailureCount("traffic")).isZero();
        assertThat(ExportStats.getTrafficToolTypeSuccessCount("PROXY")).isEqualTo(1);
        assertThat(ExportStats.getTrafficToolTypeFailureCount("REPEATER")).isZero();
        assertThat(ExportStats.getTrafficSourceFailureCount("repeater_live_http")).isZero();
    }

    @Test
    void applyBulkOutcome_zeroAttempted_noCountersAdvance() {
        ChunkedBulkSender.Result result = new ChunkedBulkSender.Result(
                0,
                0,
                0L,
                0L,
                Map.of(),
                Map.of(),
                Map.of(),
                Map.of());

        TrafficExportQueue.applyBulkOutcome(result, 50L, 100);

        assertThat(ExportStats.getSuccessCount("traffic")).isZero();
        assertThat(ExportStats.getFailureCount("traffic")).isZero();
        assertThat(ExportStats.getLastError("traffic")).isNull();
    }
}
