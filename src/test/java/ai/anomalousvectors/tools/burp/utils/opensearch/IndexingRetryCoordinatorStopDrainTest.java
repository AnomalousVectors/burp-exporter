package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.sinks.TrafficRouteBucket;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

/**
 * Unit coverage for Stop-time retry drain helpers that do not require a live search cluster.
 */
class IndexingRetryCoordinatorStopDrainTest {

    private final List<LoggedEvent> events = new CopyOnWriteArrayList<>();
    private final Logger.LogListener listener = (level, message) -> events.add(new LoggedEvent(level, message));

    @BeforeEach
    void setUp() {
        Logger.resetState();
        Logger.registerListener(listener);
        IndexingRetryCoordinator.getInstance().clearPendingWork();
        IndexingRetryCoordinator.getInstance().stopDrainThread();
        ExportStats.resetForTests();
        BulkRateLimitBackoff.clear();
        RuntimeConfig.setExportStopping(false);
        RuntimeConfig.setExportRunning(false);
    }

    @AfterEach
    void tearDown() {
        Logger.unregisterListener(listener);
        Logger.resetState();
        IndexingRetryCoordinator.getInstance().clearPendingWork();
        IndexingRetryCoordinator.getInstance().stopDrainThread();
        ExportStats.resetForTests();
        BulkRateLimitBackoff.clear();
        RuntimeConfig.setExportStopping(false);
        RuntimeConfig.setExportRunning(false);
        events.clear();
    }

    @Test
    void drainPendingRetriesDuringShutdown_emptyQueue_isNoOp() {
        IndexingRetryCoordinator.StopDrainResult result =
                IndexingRetryCoordinator.getInstance().drainPendingRetriesDuringShutdown(5_000);
        assertThat(result.attempted()).isZero();
        assertThat(result.recovered()).isZero();
        assertThat(result.remaining()).isZero();
    }

    @Test
    void recordTrafficRouteRecoveries_attributesOnlySuccessfulRetryItems() {
        PreparedExportDocument proxyHistory = trafficDocument("Proxy History");
        PreparedExportDocument repeater = trafficDocument("Repeater");

        IndexingRetryCoordinator.RouteRecoveryAttribution attributed =
                IndexingRetryCoordinator.recordTrafficRouteRecoveries(
                        List.of(proxyHistory, repeater),
                        List.of(new OpenSearchClientWrapper.FailedItem(1, "es_rejected_execution_exception", "busy")),
                        1);

        assertThat(attributed.attributed()).isEqualTo(1);
        assertThat(attributed.routeSummary()).contains("Proxy History=1");
        assertThat(ExportStats.getTrafficSourceRecoveryCount("proxy_history_snapshot")).isEqualTo(1);
        assertThat(ExportStats.getTrafficSourceSuccessCount("proxy_history_snapshot")).isEqualTo(1);
        assertThat(ExportStats.getTrafficToolTypeRecoveryCount("REPEATER")).isZero();
        assertThat(ExportStats.getTrafficToolTypeSuccessCount("REPEATER")).isZero();
        assertThat(TrafficRouteBucket.resolveOpenSearchSourceSuccess("PROXY_HISTORY")).isEqualTo(1);
    }

    @Test
    void filterTransientFailures_circuitBreaking_setsSharedCapacityCooldown() {
        PreparedExportDocument doc = trafficDocument("Proxy History");
        List<PreparedExportDocument> retry = IndexingRetryCoordinator.filterTransientFailures(
                List.of(doc),
                List.of(new OpenSearchClientWrapper.FailedItem(
                        0,
                        "circuit_breaking_exception",
                        "rejected execution of primary operation [throttled]")),
                0,
                "tool-burp-traffic",
                "traffic");

        assertThat(retry).hasSize(1);
        assertThat(BulkRateLimitBackoff.isCoolingDown()).isFalse();
        assertThat(BulkRateLimitBackoff.isCoolingDown("tool-burp-traffic")).isTrue();
        assertThat(ExportStats.getCapacityPressureEvents()).isEqualTo(1L);
        assertThat(ExportStats.getPermanentDrops("traffic")).isZero();
    }

    @Test
    void warnIfOutstandingFailuresRemain_logsPerIndexBreakdown() throws Exception {
        ExportStats.recordFailure("traffic", 4);
        ExportStats.recordRetryRecovery("traffic", 1);
        ExportStats.recordFailure("sitemap", 2);

        IndexingRetryCoordinator.warnIfOutstandingFailuresRemain();
        javax.swing.SwingUtilities.invokeAndWait(() -> { });

        boolean found = false;
        for (LoggedEvent event : events) {
            String message = event.message();
            if (message != null
                    && message.contains("Stop finished with 5 outstanding exported failure(s)")
                    && message.contains("traffic=3")
                    && message.contains("sitemap=2")) {
                found = true;
                break;
            }
        }
        assertThat(found).isTrue();
    }

    @Test
    void clearPendingWork_countsDiscardedAsPermanentDrops() throws Exception {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("sitemap"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStopping(true);

        PreparedExportDocument doc = new PreparedExportDocument(
                "sitemap-operation",
                "tool-burp-sitemap",
                "sitemap",
                Map.of("k", "v"),
                32L,
                new byte[] { '{' });
        int queued = IndexingRetryCoordinator.getInstance().enqueueFailedPreparedDocuments(
                "tool-burp-sitemap",
                "sitemap",
                List.of(doc, doc, doc),
                List.of(),
                0);
        assertThat(queued).isEqualTo(3);

        ExportStats.recordFailure("sitemap", 3);
        IndexingRetryCoordinator.getInstance().clearPendingWork();
        javax.swing.SwingUtilities.invokeAndWait(() -> { });

        assertThat(ExportStats.getPermanentDrops("sitemap")).isEqualTo(3);
        assertThat(ExportStats.getOutstandingFailureCount("sitemap")).isEqualTo(0);
        assertThat(events.stream().anyMatch(e ->
                e.message() != null
                        && e.message().contains("Discarded 3 queued retry document(s) on Stop")
                        && e.message().contains("Permanent Drops")
                        && e.message().contains("sitemap=3"))).isTrue();
    }

    @Test
    void clearPendingWork_attributesTrafficPermanentDropsByRoute() throws Exception {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStopping(true);

        int queued = IndexingRetryCoordinator.getInstance().enqueueFailedPreparedDocuments(
                "tool-burp-traffic",
                "traffic",
                List.of(
                        trafficDocument("Proxy History"),
                        trafficDocument("Proxy History"),
                        trafficDocument("Repeater")),
                List.of(),
                0);
        assertThat(queued).isEqualTo(3);
        assertThat(ExportStats.getTrafficDisplaySourceQueueSize("PROXY_HISTORY")).isEqualTo(2);
        assertThat(ExportStats.getTrafficDisplaySourceQueueSize("REPEATER")).isEqualTo(1);

        IndexingRetryCoordinator.getInstance().clearPendingWork();
        javax.swing.SwingUtilities.invokeAndWait(() -> { });

        assertThat(ExportStats.getPermanentDrops("traffic")).isEqualTo(3);
        assertThat(ExportStats.getTrafficSourcePermanentDrops("proxy_history_snapshot")).isEqualTo(2);
        assertThat(ExportStats.getTrafficToolTypePermanentDrops("REPEATER")).isEqualTo(1);
        assertThat(ExportStats.getTrafficDisplaySourceQueueSize("PROXY_HISTORY")).isZero();
        assertThat(ExportStats.getTrafficDisplaySourceQueueSize("REPEATER")).isZero();
    }

    private static PreparedExportDocument trafficDocument(String reportingTool) {
        return new PreparedExportDocument(
                "traffic-operation-" + reportingTool,
                "tool-burp-traffic",
                "traffic",
                Map.of("burp", Map.of("reporting_tool", reportingTool)),
                32L,
                new byte[] { '{' });
    }

    private record LoggedEvent(String level, String message) {
    }
}
