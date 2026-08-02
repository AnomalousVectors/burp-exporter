package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

/**
 * Unit tests for {@link BulkByteBudget}.
 *
 * <p>Setup and teardown are invoked explicitly from each {@code @Test} method (no
 * {@code @BeforeEach}/{@code @AfterEach} and no test-class constructor hooks) so IDE
 * "never used" hints on JUnit lifecycle entry points do not fire.</p>
 */
class BulkByteBudgetTest {

    private final ConfigState.State previous = RuntimeConfig.getState();
    private final AtomicLong nowNanos = new AtomicLong();

    private void prepare() {
        BulkRateLimitBackoff.clear();
        IndexingRetryCoordinator.getInstance().setSoftCapacityOutageForTests(false);
        BatchSizeController.setInstance(new BatchSizeController());
        nowNanos.set(0L);
        OfferedLoadGovernor.setSharedForTests(OfferedLoadGovernor.createForTests(
                nowNanos::get,
                nowNanos::addAndGet,
                () -> false,
                () -> 0L));
    }

    private void restore() {
        IndexingRetryCoordinator.getInstance().setSoftCapacityOutageForTests(false);
        BulkRateLimitBackoff.clear();
        BatchSizeController.setInstance(null);
        OfferedLoadGovernor.restoreProductionForTests();
        RuntimeConfig.updateState(previous);
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStarting(false);
    }

    @Test
    void nonAmazon_startsConservative_andAdaptsUnderPressure() {
        prepare();
        try {
            applyOpenSearchRuntime();
            BulkByteBudget.resetForStart();
            assertThat(BulkByteBudget.isAmazonDestination()).isFalse();
            assertThat(BulkByteBudget.isAdaptiveDestination()).isTrue();
            assertThat(BulkByteBudget.currentMaxBytes()).isEqualTo(BulkByteBudget.AMAZON_INITIAL_BYTES);
            assertThat(BulkByteBudget.maxInFlightFlushes()).isEqualTo(1);

            BulkByteBudget.applyRateLimitPressure(429, "idx", "Prepared bulk", 5_000L);

            assertThat(BulkByteBudget.currentMaxBytes()).isEqualTo(BulkByteBudget.ADAPTIVE_MIN_BYTES);
            assertThat(BulkByteBudget.maxInFlightFlushes()).isEqualTo(1);
        } finally {
            restore();
        }
    }

    @Test
    void amazon_startsAt1MiB_growsToward5MiB_andShrinksOnFailure() {
        prepare();
        try {
            applyAmazonRuntime();
            BulkByteBudget.resetForStart();
            assertThat(BulkByteBudget.isAmazonDestination()).isTrue();
            assertThat(BulkByteBudget.currentMaxBytes()).isEqualTo(BulkByteBudget.AMAZON_INITIAL_BYTES);

            recordAfterStableWindow(BulkByteBudget.AMAZON_INITIAL_BYTES);
            assertThat(BulkByteBudget.currentMaxBytes())
                    .isGreaterThan(BulkByteBudget.AMAZON_INITIAL_BYTES)
                    .isLessThanOrEqualTo(BulkByteBudget.AMAZON_MAX_BYTES);

            long afterGrow = BulkByteBudget.currentMaxBytes();
            BulkByteBudget.recordFailure();
            assertThat(BulkByteBudget.currentMaxBytes())
                    .isEqualTo(Math.max(BulkByteBudget.AMAZON_MIN_BYTES, afterGrow / 2));
        } finally {
            restore();
        }
    }

    @Test
    void amazon_rateLimit_serializesFlushesAndSkipsDoubleShrink() {
        prepare();
        try {
            applyAmazonRuntime();
            BulkByteBudget.resetForStart();
            BulkByteBudget.applyAmazonRateLimitPressure(429, "tool-burp-traffic", "Prepared bulk", 5_000L);
            assertThat(BulkByteBudget.currentMaxBytes()).isEqualTo(BulkByteBudget.AMAZON_MIN_BYTES);
            assertThat(BulkByteBudget.maxInFlightFlushes()).isEqualTo(1);

            long afterRateLimit = BulkByteBudget.currentMaxBytes();
            BulkByteBudget.recordFailure();
            assertThat(BulkByteBudget.currentMaxBytes()).isEqualTo(afterRateLimit);

            recordAfterStableWindow(afterRateLimit);
            assertThat(BulkByteBudget.maxInFlightFlushes()).isEqualTo(2);
        } finally {
            restore();
        }
    }

    @Test
    void healthySuccessStreak_climbsTowardCeilingAndRaisesInFlight() {
        prepare();
        try {
            applyAmazonRuntime();
            BulkByteBudget.resetForStart();
            BulkRateLimitBackoff.clearCooldownDeadline();
            recordAfterStableWindow(BulkByteBudget.AMAZON_INITIAL_BYTES);
            advanceStableWindow();
            BulkByteBudget.recordSuccess(BulkByteBudget.AMAZON_INITIAL_BYTES);
            assertThat(BulkByteBudget.currentMaxBytes())
                    .isGreaterThan(BulkByteBudget.AMAZON_INITIAL_BYTES);
            assertThat(BulkByteBudget.maxInFlightFlushes()).isEqualTo(3);
        } finally {
            restore();
        }
    }

    @Test
    void elevatedLatency_blocksGrowthAndMayShrink() {
        prepare();
        try {
            applyAmazonRuntime();
            BulkByteBudget.resetForStart();
            BulkRateLimitBackoff.clearCooldownDeadline();
            // Seed a healthy baseline, then inject elevated latency samples.
            for (int i = 0; i < 8; i++) {
                BulkByteBudget.recordBulkLatency(300L);
            }
            assertThat(BulkByteBudget.latencyElevated()).isFalse();
            for (int i = 0; i < 8; i++) {
                BulkByteBudget.recordBulkLatency(3_000L);
            }
            assertThat(BulkByteBudget.latencyElevated()).isTrue();
            long before = BulkByteBudget.currentMaxBytes();
            BulkByteBudget.recordSuccess(before);
            assertThat(BulkByteBudget.currentMaxBytes()).isLessThanOrEqualTo(before);
        } finally {
            restore();
        }
    }

    @Test
    void restoreAfterRecovery_holdsFloorAndKeepsFlushesSerialized() {
        prepare();
        try {
            applyAmazonRuntime();
            BulkByteBudget.resetForStart();
            recordAfterStableWindow(2L * 1024 * 1024);
            assertThat(BulkByteBudget.currentMaxBytes()).isGreaterThan(BulkByteBudget.AMAZON_INITIAL_BYTES);

            BulkByteBudget.applyRateLimitPressure(429, "tool-burp-traffic", "Prepared bulk", 5_000L);
            assertThat(BulkByteBudget.currentMaxBytes()).isEqualTo(BulkByteBudget.AMAZON_MIN_BYTES);
            assertThat(BulkByteBudget.maxInFlightFlushes()).isEqualTo(1);

            BulkRateLimitBackoff.clearCooldownDeadline();
            BulkByteBudget.restoreAfterRecovery("soft_outage_cleared");

            // Soft Outage clear must not re-inflate concurrency or bump the floored budget.
            assertThat(BulkByteBudget.maxInFlightFlushes()).isEqualTo(1);
            assertThat(BulkByteBudget.currentMaxBytes()).isEqualTo(BulkByteBudget.AMAZON_MIN_BYTES);
        } finally {
            restore();
        }
    }

    @Test
    void eightPayloadSuccesses_clearEveryPressureEpoch_andGrowthResumes() {
        prepare();
        try {
            applyAmazonRuntime();
            BulkRateLimitBackoff.noteRateLimited(
                    429, null, "tool-burp-traffic", "Prepared bulk");
            BulkRateLimitBackoff.noteItemCapacityPressure(
                    "tool-burp-traffic",
                    "Bulk item",
                    "es_rejected_execution_exception: queue full");
            IndexingRetryCoordinator coordinator = IndexingRetryCoordinator.getInstance();
            coordinator.setSoftCapacityOutageForTests(true);

            for (int success = 0; success < OfferedLoadGovernor.RECOVERY_SUCCESS_STREAK; success++) {
                nowNanos.addAndGet(OfferedLoadGovernor.MIN_SUCCESS_SPACING_NANOS);
                coordinator.noteFullPayloadBulkSuccess(
                        "traffic", BulkByteBudget.currentMaxBytes());
            }

            assertThat(coordinator.isSoftCapacityOutage()).isFalse();
            assertThat(BulkRateLimitBackoff.pressureStreak()).isZero();
            assertThat(BulkRateLimitBackoff.remainingCooldownMs("tool-burp-traffic")).isZero();
            assertThat(OfferedLoadGovernor.isPressureActive()).isFalse();
            assertThat(OfferedLoadGovernor.currentRecoveryStreak()).isZero();
            long recoveredBudget = BulkByteBudget.currentMaxBytes();
            assertThat(recoveredBudget).isEqualTo(BulkByteBudget.ADAPTIVE_MIN_BYTES);
            assertThat(BulkByteBudget.maxInFlightFlushes()).isEqualTo(1);

            advanceStableWindow();
            coordinator.noteFullPayloadBulkSuccess("traffic", recoveredBudget);

            assertThat(BulkByteBudget.currentMaxBytes()).isGreaterThan(recoveredBudget);
        } finally {
            restore();
        }
    }

    @Test
    void hardPressure_floorsImmediatelyFromGrownBudget() {
        prepare();
        try {
            applyAmazonRuntime();
            BulkByteBudget.resetForStart();
            BulkRateLimitBackoff.clearCooldownDeadline();
            recordAfterStableWindow(BulkByteBudget.AMAZON_INITIAL_BYTES);
            assertThat(BulkByteBudget.currentMaxBytes()).isGreaterThan(BulkByteBudget.AMAZON_INITIAL_BYTES);

            BulkByteBudget.applyRateLimitPressure(429, "tool-burp-findings", "Prepared bulk", 5_000L);

            assertThat(BulkByteBudget.currentMaxBytes()).isEqualTo(BulkByteBudget.ADAPTIVE_MIN_BYTES);
            assertThat(BulkByteBudget.maxInFlightFlushes()).isEqualTo(1);
        } finally {
            restore();
        }
    }

    @Test
    void clear_capturesLastActiveCapacityBeforeResettingControllers() {
        prepare();
        try {
            ExportStats.resetForTests();
            applyAmazonRuntime();
            BulkByteBudget.resetForStart();
            BulkRateLimitBackoff.clearCooldownDeadline();
            recordAfterStableWindow(BulkByteBudget.AMAZON_INITIAL_BYTES);
            advanceStableWindow();
            BulkByteBudget.recordSuccess(BulkByteBudget.currentMaxBytes());
            long liveBudget = BulkByteBudget.currentMaxBytes();
            int liveFlushCap = BulkByteBudget.maxInFlightFlushes();

            BulkRateLimitBackoff.clear();

            assertThat(ExportStats.getLastActiveBulkByteBudget()).isEqualTo(liveBudget);
            assertThat(ExportStats.getLastActiveSnapshotFlushCap()).isEqualTo(liveFlushCap);
            assertThat(BulkByteBudget.currentMaxBytes()).isEqualTo(BulkByteBudget.AMAZON_INITIAL_BYTES);
            assertThat(BulkByteBudget.maxInFlightFlushes()).isEqualTo(1);
        } finally {
            restore();
            ExportStats.resetForTests();
        }
    }

    @Test
    void exceedsLiveBudget_matchesCurrentCeiling() {
        prepare();
        try {
            applyAmazonRuntime();
            BulkByteBudget.resetForStart();
            long ceiling = BulkByteBudget.currentMaxBytes();
            assertThat(BulkByteBudget.exceedsLiveBudget(ceiling)).isFalse();
            assertThat(BulkByteBudget.exceedsLiveBudget(ceiling + 1L)).isTrue();
        } finally {
            restore();
        }
    }

    private static void applyOpenSearchRuntime() {
        applySearchDestination(ConfigState.SearchDestination.OPEN_SEARCH);
    }

    private void recordAfterStableWindow(long bulkBytes) {
        BulkByteBudget.recordSuccess(bulkBytes);
        advanceStableWindow();
        BulkByteBudget.recordSuccess(bulkBytes);
    }

    private void advanceStableWindow() {
        nowNanos.addAndGet(OfferedLoadGovernor.STABLE_GROWTH_WINDOW_NANOS);
    }

    private static void applyAmazonRuntime() {
        applySearchDestination(ConfigState.SearchDestination.OPEN_SEARCH_AMAZON);
    }

    private static void applySearchDestination(ConfigState.SearchDestination destination) {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_SETTINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, "", false, true,
                        true, ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                        true, ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                        true, "https://opensearch.url:9200", "", "",
                        ConfigState.OPEN_SEARCH_TLS_VERIFY,
                        ConfigState.defaultOpenSearchOptions(),
                        destination.configKey(),
                        "https://amazon-opensearch.example",
                        ConfigState.defaultOpenSearchAmazonOptions(),
                        "http://localhost:9201",
                        ConfigState.defaultElasticsearchOptions()),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
    }
}
