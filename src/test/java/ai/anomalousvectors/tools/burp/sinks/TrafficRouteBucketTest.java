package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

/**
 * Unit tests for the centralized {@link TrafficRouteBucket} mapping and stats helpers.
 *
 * <p>The class is the single authority for deciding whether a traffic document rolls up under
 * a {@link TrafficRouteBucket.Kind#SOURCE} or {@link TrafficRouteBucket.Kind#TOOL_TYPE} bucket,
 * and for recording per-bucket counts on both the OpenSearch and file sinks.</p>
 */
class TrafficRouteBucketTest {

    @AfterEach
    void restoreRuntimeFlags() {
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStarting(false);
        RuntimeConfig.setExportStopping(false);
    }

    void resetStats() {
        ExportStats.resetForTests();
        FileExportStats.resetForTests();
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.setExportStarting(false);
    }

    @Test
    void fromToolType_routesProxyHistoryToSnapshotSource() {
        TrafficRouteBucket.Route route = TrafficRouteBucket.fromToolType("PROXY_HISTORY");
        assertThat(route.kind()).isEqualTo(TrafficRouteBucket.Kind.SOURCE);
        assertThat(route.key()).isEqualTo(TrafficRouteBucket.SOURCE_PROXY_HISTORY_SNAPSHOT);
    }

    @Test
    void fromToolType_routesProxyWebSocketToSource() {
        TrafficRouteBucket.Route route = TrafficRouteBucket.fromToolType("PROXY_WEBSOCKET");
        assertThat(route.kind()).isEqualTo(TrafficRouteBucket.Kind.SOURCE);
        assertThat(route.key()).isEqualTo(TrafficRouteBucket.SOURCE_PROXY_WEBSOCKET);
    }

    @Test
    void fromToolType_passesThroughOtherToolTypesAsToolType() {
        TrafficRouteBucket.Route route = TrafficRouteBucket.fromToolType("REPEATER_TABS");
        assertThat(route.kind()).isEqualTo(TrafficRouteBucket.Kind.TOOL_TYPE);
        assertThat(route.key()).isEqualTo("REPEATER_TABS");
    }

    @Test
    void fromToolType_normalizesBlankAndNullToUnknown() {
        assertThat(TrafficRouteBucket.fromToolType(null).key()).isEqualTo(TrafficRouteBucket.TOOL_TYPE_UNKNOWN);
        assertThat(TrafficRouteBucket.fromToolType("").key()).isEqualTo(TrafficRouteBucket.TOOL_TYPE_UNKNOWN);
        assertThat(TrafficRouteBucket.fromToolType("   ").key()).isEqualTo(TrafficRouteBucket.TOOL_TYPE_UNKNOWN);
    }

    @Test
    void fromDocument_derivesRouteFromBurpReportingToolField() {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("burp", Map.of("reporting_tool", "Proxy WebSocket"));
        assertThat(TrafficRouteBucket.fromDocument(doc).key())
                .isEqualTo(TrafficRouteBucket.SOURCE_PROXY_WEBSOCKET);

        Map<String, Object> docWithoutReporter = new HashMap<>();
        assertThat(TrafficRouteBucket.fromDocument(docWithoutReporter).key())
                .isEqualTo(TrafficRouteBucket.TOOL_TYPE_UNKNOWN);

        assertThat(TrafficRouteBucket.fromDocument(null).key())
                .isEqualTo(TrafficRouteBucket.TOOL_TYPE_UNKNOWN);
    }

    @Test
    void fromToolLabel_mapsDisplayLabelsToExistingBuckets() {
        assertThat(TrafficRouteBucket.fromToolLabel("Repeater Tabs").key()).isEqualTo("REPEATER_TABS");
        assertThat(TrafficRouteBucket.fromToolLabel("Proxy").key()).isEqualTo("PROXY");
        assertThat(TrafficRouteBucket.fromToolLabel("Burp AI").key()).isEqualTo("BURP_AI");
    }

    @Test
    void routeRecord_rejectsBlankKeyOrNullKind() {
        assertThatThrownBy(() -> new TrafficRouteBucket.Route(null, "x"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new TrafficRouteBucket.Route(TrafficRouteBucket.Kind.TOOL_TYPE, ""))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void recordOpenSearchPermanentAndRetryQueueDrops_routeSeparatelyAndFoldUnderProxyHistory() {
        resetStats();
        TrafficRouteBucket.recordOpenSearchPermanentDrop(TrafficRouteBucket.proxyHistorySnapshot(), 2);
        TrafficRouteBucket.recordOpenSearchPermanentDrop(TrafficRouteBucket.fromToolType("REPEATER_TABS"), 1);
        TrafficRouteBucket.recordOpenSearchRetryQueueDrop(TrafficRouteBucket.proxyWebSocket(), 3);
        TrafficRouteBucket.recordOpenSearchRetryQueueDrop(TrafficRouteBucket.fromToolType("INTRUDER"), 4);

        assertThat(ExportStats.getTrafficSourcePermanentDrops(TrafficRouteBucket.SOURCE_PROXY_HISTORY_SNAPSHOT))
                .isEqualTo(2);
        assertThat(ExportStats.getTrafficToolTypePermanentDrops("REPEATER_TABS")).isEqualTo(1);
        assertThat(TrafficRouteBucket.resolveOpenSearchSourcePermanentDrops("PROXY_HISTORY")).isEqualTo(2);
        assertThat(TrafficRouteBucket.resolveOpenSearchSourcePermanentDrops("REPEATER_TABS")).isEqualTo(1);

        assertThat(ExportStats.getTrafficSourceRetryQueueDrops(TrafficRouteBucket.SOURCE_PROXY_WEBSOCKET))
                .isEqualTo(3);
        assertThat(ExportStats.getTrafficToolTypeRetryQueueDrops("INTRUDER")).isEqualTo(4);
        assertThat(TrafficRouteBucket.resolveOpenSearchSourceRetryQueueDrops("PROXY_HISTORY")).isEqualTo(3);
        assertThat(TrafficRouteBucket.resolveOpenSearchSourceRetryQueueDrops("INTRUDER")).isEqualTo(4);
    }

    @Test
    void countQueuedForDisplaySource_attributesByRouteAndFoldsProxyFamily() {
        PreparedExportDocument proxyHistory = ExportDocumentIdentity.prepare(
                "tool-burp-traffic",
                "traffic",
                Map.of("burp", Map.of("reporting_tool", "Proxy History")));
        PreparedExportDocument proxyWs = ExportDocumentIdentity.prepare(
                "tool-burp-traffic",
                "traffic",
                Map.of("burp", Map.of("reporting_tool", "Proxy WebSocket")));
        PreparedExportDocument repeater = ExportDocumentIdentity.prepare(
                "tool-burp-traffic",
                "traffic",
                Map.of("burp", Map.of("reporting_tool", "Repeater")));

        assertThat(TrafficRouteBucket.countQueuedForDisplaySource(
                "PROXY_HISTORY", List.of(proxyHistory, proxyWs, repeater))).isEqualTo(2);
        assertThat(TrafficRouteBucket.countQueuedForDisplaySource(
                "REPEATER", List.of(proxyHistory, proxyWs, repeater))).isEqualTo(1);
        assertThat(TrafficRouteBucket.countQueuedForDisplaySource("INTRUDER", List.of(repeater))).isZero();
    }

    @Test
    void recordOpenSearchSuccess_routesSourceAndToolTypeSeparately() {
        resetStats();
        TrafficRouteBucket.recordOpenSearchSuccess(TrafficRouteBucket.proxyHistorySnapshot(), 3);
        TrafficRouteBucket.recordOpenSearchSuccess(TrafficRouteBucket.fromToolType("REPEATER_TABS"), 2);

        assertThat(ExportStats.getTrafficSourceSuccessCount(TrafficRouteBucket.SOURCE_PROXY_HISTORY_SNAPSHOT))
                .isEqualTo(3);
        assertThat(ExportStats.getTrafficToolTypeSuccessCount("REPEATER_TABS")).isEqualTo(2);
    }

    @Test
    void recordOpenSearchFailure_routesSourceAndToolTypeSeparately() {
        resetStats();
        TrafficRouteBucket.recordOpenSearchFailure(TrafficRouteBucket.proxyWebSocket(), 4);
        TrafficRouteBucket.recordOpenSearchFailure(TrafficRouteBucket.fromToolType("INTRUDER"), 1);

        assertThat(ExportStats.getTrafficSourceFailureCount(TrafficRouteBucket.SOURCE_PROXY_WEBSOCKET))
                .isEqualTo(4);
        assertThat(ExportStats.getTrafficToolTypeFailureCount("INTRUDER")).isEqualTo(1);
    }

    @Test
    void recordFileSuccessAndFailure_updateFileExportStats() {
        resetStats();
        TrafficRouteBucket.recordFileSuccess(TrafficRouteBucket.proxyHistorySnapshot(), 5);
        TrafficRouteBucket.recordFileFailure(TrafficRouteBucket.fromToolType("REPEATER"), 7);

        assertThat(FileExportStats.getTrafficSourceSuccessCount(TrafficRouteBucket.SOURCE_PROXY_HISTORY_SNAPSHOT))
                .isEqualTo(5);
        assertThat(FileExportStats.getTrafficToolTypeFailureCount("REPEATER")).isEqualTo(7);
    }

    @Test
    void resolveOpenSearchSourceSuccess_foldsSnapshotAndWebSocketUnderProxyHistoryRow() {
        resetStats();
        TrafficRouteBucket.recordOpenSearchSuccess(
                TrafficRouteBucket.fromToolType("PROXY_HISTORY"), 2); // proxy_history_snapshot
        TrafficRouteBucket.recordOpenSearchSuccess(TrafficRouteBucket.proxyWebSocket(), 3);
        // A plain PROXY_HISTORY tool-type value should never land in the tool-type map because
        // the route bucket always resolves PROXY_HISTORY -> SOURCE, but confirm the display path
        // is stable when the tool-type map is empty.
        assertThat(TrafficRouteBucket.resolveOpenSearchSourceSuccess("PROXY_HISTORY")).isEqualTo(5);
        assertThat(TrafficRouteBucket.resolveOpenSearchSourceFailure("PROXY_HISTORY")).isZero();
    }

    @Test
    void resolveFileSourceSuccess_foldsSnapshotAndWebSocketUnderProxyHistoryRow() {
        resetStats();
        TrafficRouteBucket.recordFileSuccess(TrafficRouteBucket.proxyHistorySnapshot(), 4);
        TrafficRouteBucket.recordFileSuccess(TrafficRouteBucket.proxyWebSocket(), 1);
        assertThat(TrafficRouteBucket.resolveFileSourceSuccess("PROXY_HISTORY")).isEqualTo(5);
    }

    @Test
    void recordBulkOutcome_fullSuccess_updatesTrafficAndRouteSuccessCounters() {
        resetStats();
        TrafficRouteBucket.Route route = TrafficRouteBucket.proxyWebSocket();
        TrafficRouteBucket.recordBulkOutcome(route, 4, 4, true, "Proxy WebSocket bulk push");

        assertThat(ExportStats.getSuccessCount("traffic")).isEqualTo(4);
        assertThat(ExportStats.getFailureCount("traffic")).isZero();
        assertThat(ExportStats.getTrafficSourceSuccessCount(TrafficRouteBucket.SOURCE_PROXY_WEBSOCKET))
                .isEqualTo(4);
        assertThat(ExportStats.getTrafficSourceFailureCount(TrafficRouteBucket.SOURCE_PROXY_WEBSOCKET))
                .isZero();
    }

    @Test
    void recordBulkOutcome_partialFailure_splitsSuccessAndFailure() {
        resetStats();
        TrafficRouteBucket.Route route = TrafficRouteBucket.proxyHistorySnapshot();
        TrafficRouteBucket.recordBulkOutcome(route, 5, 3, true, "Proxy history chunk");

        assertThat(ExportStats.getSuccessCount("traffic")).isEqualTo(3);
        assertThat(ExportStats.getFailureCount("traffic")).isEqualTo(2);
        assertThat(ExportStats.getTrafficSourceSuccessCount(TrafficRouteBucket.SOURCE_PROXY_HISTORY_SNAPSHOT))
                .isEqualTo(3);
        assertThat(ExportStats.getTrafficSourceFailureCount(TrafficRouteBucket.SOURCE_PROXY_HISTORY_SNAPSHOT))
                .isEqualTo(2);
    }

    @Test
    void recordBulkOutcome_stoppedPartial_countsRouteSuccessButSuppressesRouteFailure() {
        resetStats();
        RuntimeConfig.setExportRunning(false);
        TrafficRouteBucket.Route route = TrafficRouteBucket.proxyHistorySnapshot();

        TrafficRouteBucket.recordBulkOutcome(route, 5, 3, true, "Proxy history chunk");

        assertThat(ExportStats.getSuccessCount("traffic")).isEqualTo(3);
        assertThat(ExportStats.getFailureCount("traffic")).isZero();
        assertThat(ExportStats.getTrafficSourceSuccessCount(TrafficRouteBucket.SOURCE_PROXY_HISTORY_SNAPSHOT))
                .isEqualTo(3);
        assertThat(ExportStats.getTrafficSourceFailureCount(TrafficRouteBucket.SOURCE_PROXY_HISTORY_SNAPSHOT))
                .isZero();
    }

    @Test
    void recordBulkOutcome_openSearchInactive_isNoop() {
        resetStats();
        TrafficRouteBucket.Route route = TrafficRouteBucket.proxyWebSocket();
        TrafficRouteBucket.recordBulkOutcome(route, 4, 2, false, "label");

        assertThat(ExportStats.getSuccessCount("traffic")).isZero();
        assertThat(ExportStats.getFailureCount("traffic")).isZero();
        assertThat(ExportStats.getTrafficSourceSuccessCount(TrafficRouteBucket.SOURCE_PROXY_WEBSOCKET))
                .isZero();
        assertThat(ExportStats.getTrafficSourceFailureCount(TrafficRouteBucket.SOURCE_PROXY_WEBSOCKET))
                .isZero();
    }

    @Test
    void recordBulkOutcome_nullRoute_isNoop() {
        resetStats();
        TrafficRouteBucket.recordBulkOutcome(null, 3, 3, true, "label");
        assertThat(ExportStats.getSuccessCount("traffic")).isZero();
    }

    @Test
    void recordBulkOutcome_clampsSentAboveAttempted() {
        resetStats();
        TrafficRouteBucket.Route route = TrafficRouteBucket.proxyHistorySnapshot();
        TrafficRouteBucket.recordBulkOutcome(route, 5, 7, true, "Proxy history chunk");

        assertThat(ExportStats.getSuccessCount("traffic")).isEqualTo(5);
        assertThat(ExportStats.getFailureCount("traffic")).isZero();
        assertThat(ExportStats.getTrafficSourceSuccessCount(TrafficRouteBucket.SOURCE_PROXY_HISTORY_SNAPSHOT))
                .isEqualTo(5);
    }

    @Test
    void recordBulkOutcome_clampsNegativeAttemptedToZero() {
        resetStats();
        TrafficRouteBucket.Route route = TrafficRouteBucket.proxyWebSocket();
        TrafficRouteBucket.recordBulkOutcome(route, -3, 5, true, "label");

        assertThat(ExportStats.getSuccessCount("traffic")).isZero();
        assertThat(ExportStats.getFailureCount("traffic")).isZero();
        assertThat(ExportStats.getTrafficSourceSuccessCount(TrafficRouteBucket.SOURCE_PROXY_WEBSOCKET))
                .isZero();
    }

    @Test
    void trafficIndexName_delegatesToRuntimeConfig() {
        String name = TrafficRouteBucket.trafficIndexName();
        assertThat(name).isNotNull();
        assertThat(TrafficRouteBucket.INDEX_KEY).isEqualTo("traffic");
    }

    @Test
    void zeroOrNegativeCount_recordsNothing() {
        resetStats();
        TrafficRouteBucket.recordOpenSearchSuccess(TrafficRouteBucket.fromToolType("REPEATER"), 0);
        TrafficRouteBucket.recordOpenSearchFailure(TrafficRouteBucket.fromToolType("REPEATER"), -2);
        TrafficRouteBucket.recordFileSuccess(TrafficRouteBucket.fromToolType("REPEATER"), 0);
        TrafficRouteBucket.recordFileFailure(TrafficRouteBucket.fromToolType("REPEATER"), -9);

        assertThat(ExportStats.getTrafficToolTypeSuccessCount("REPEATER")).isZero();
        assertThat(ExportStats.getTrafficToolTypeFailureCount("REPEATER")).isZero();
        assertThat(FileExportStats.getTrafficToolTypeSuccessCount("REPEATER")).isZero();
        assertThat(FileExportStats.getTrafficToolTypeFailureCount("REPEATER")).isZero();
    }
}
