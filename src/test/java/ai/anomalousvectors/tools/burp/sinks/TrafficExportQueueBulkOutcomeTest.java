package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterEach;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.concurrent.ExportRunContext;
import ai.anomalousvectors.tools.burp.utils.export.BulkOutcomeBreakdown;
import ai.anomalousvectors.tools.burp.utils.opensearch.ChunkedBulkSender;

/**
 * Unit tests for {@link TrafficExportQueue#applyBulkOutcome(ChunkedBulkSender.Result, long, int)},
 * covering the streaming drain's post-push accounting convergence on {@link BulkOutcomeRecorder}.
 *
 * <p>Assertions focus on index-level totals, per-tool-type and per-source counter propagation,
 * last-error visibility on partial failure, destination health, and byte/duration bookkeeping
 * that StatsPanel reads. Stale-run and expected-cancellation outcomes cannot advance health failures.
 * Static {@link ExportStats} counters are reset per-test via the constructor so each case
 * observes deltas from a clean baseline.</p>
 */
class TrafficExportQueueBulkOutcomeTest {

    public TrafficExportQueueBulkOutcomeTest() {
        ExportStats.resetForTests();
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.setExportStarting(false);
    }

    @AfterEach
    void resetRunState() {
        RuntimeConfig.resetExportRunForTests();
        ExportStats.resetForTests();
    }

    @Test
    void applyBulkOutcome_fullSuccess_updatesCountsAndDoesNotRecordLastError() {
        ExportStats.recordOpenSearchFailure();
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
        assertThat(ExportStats.getOpenSearchLastSuccessAtMs()).isPositive();
        assertThat(ExportStats.getOpenSearchConsecutiveFailures()).isZero();
    }

    @Test
    void applyBulkOutcome_partialFailure_recordsFailureMapsAndLastError() {
        ExportStats.recordOpenSearchFailure();
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
        assertThat(ExportStats.getOpenSearchLastSuccessAtMs()).isPositive();
        assertThat(ExportStats.getOpenSearchConsecutiveFailures()).isZero();
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
        assertThat(ExportStats.getOpenSearchLastSuccessAtMs()).isPositive();
        assertThat(ExportStats.getOpenSearchConsecutiveFailures()).isZero();
    }

    @Test
    void applyBulkOutcome_zeroAttempted_noCountersAdvance() {
        ExportStats.recordOpenSearchFailure();
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
        assertThat(ExportStats.getOpenSearchLastSuccessAtMs()).isEqualTo(-1L);
        assertThat(ExportStats.getOpenSearchConsecutiveFailures()).isEqualTo(1L);
    }

    @Test
    void applyBulkOutcome_noopAcknowledgment_updatesHealthWithoutInventingExportedDocs() {
        ChunkedBulkSender.Result result = new ChunkedBulkSender.Result(
                1, 1, 100L, 100L, Map.of(), Map.of(), Map.of(), Map.of(),
                new BulkOutcomeBreakdown(0, 0, 1, 0));

        TrafficExportQueue.applyBulkOutcome(result, 50L, 100);

        assertThat(ExportStats.getOpenSearchLastSuccessAtMs()).isPositive();
        assertThat(ExportStats.getOpenSearchConsecutiveFailures()).isZero();
        assertThat(ExportStats.getSuccessCount("traffic")).isZero();
        assertThat(ExportStats.getNoopCount("traffic")).isEqualTo(1L);
    }

    @Test
    void applyBulkOutcome_totalFailure_preservesLastSuccessAndAdvancesHealthFailures() {
        ExportStats.recordOpenSearchSuccess();
        long previousSuccess = ExportStats.getOpenSearchLastSuccessAtMs();
        ChunkedBulkSender.Result result = failedResult();

        TrafficExportQueue.applyBulkOutcome(result, 50L, 100);
        TrafficExportQueue.applyBulkOutcome(result, 50L, 100);

        assertThat(ExportStats.getOpenSearchLastSuccessAtMs()).isEqualTo(previousSuccess);
        assertThat(ExportStats.getOpenSearchConsecutiveFailures()).isEqualTo(2L);
        assertThat(ExportStats.getSuccessCount("traffic")).isZero();
        assertThat(ExportStats.getFailureCount("traffic")).isEqualTo(2L);
    }

    @Test
    void applyBulkOutcome_stoppedFailure_doesNotInventHealthFailureOrSuccess() {
        RuntimeConfig.setExportRunning(false);

        TrafficExportQueue.applyBulkOutcome(failedResult(), 50L, 100);

        assertThat(ExportStats.getOpenSearchLastSuccessAtMs()).isEqualTo(-1L);
        assertThat(ExportStats.getOpenSearchConsecutiveFailures()).isZero();
        assertThat(ExportStats.getFailureCount("traffic")).isZero();
    }

    @Test
    void applyBulkOutcome_staleRun_cannotChangeNextRunHealthOrCounts() {
        var oldToken = RuntimeConfig.currentExportRunToken();
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportRunning(true);
        ChunkedBulkSender.Result success = new ChunkedBulkSender.Result(
                1, 1, 100L, 100L, Map.of("PROXY", 1), Map.of(),
                Map.of("proxy_live_http", 1), Map.of());

        ExportRunContext.call(oldToken, () -> {
            TrafficExportQueue.applyBulkOutcome(success, 50L, 100);
            TrafficExportQueue.applyBulkOutcome(failedResult(), 50L, 100);
            return null;
        });

        assertThat(ExportStats.getOpenSearchLastSuccessAtMs()).isEqualTo(-1L);
        assertThat(ExportStats.getOpenSearchConsecutiveFailures()).isZero();
        assertThat(ExportStats.getSuccessCount("traffic")).isZero();
        assertThat(ExportStats.getFailureCount("traffic")).isZero();
    }

    private static ChunkedBulkSender.Result failedResult() {
        return new ChunkedBulkSender.Result(
                0, 1, 100L, 0L, Map.of(), Map.of("PROXY", 1),
                Map.of(), Map.of("proxy_live_http", 1));
    }
}
