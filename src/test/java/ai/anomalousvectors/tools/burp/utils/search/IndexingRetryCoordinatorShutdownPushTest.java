package ai.anomalousvectors.tools.burp.utils.search;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;

import ai.anomalousvectors.tools.burp.testutils.OpenSearchReachable;
import ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

/**
 * Verifies shutdown push bypasses {@link RuntimeConfig#isExportReady()} while export is stopped.
 */
@Tag("integration")
@ResourceLock("exporter-opensearch-index")
class IndexingRetryCoordinatorShutdownPushTest {

    private final ConfigState.State previous = RuntimeConfig.getState();

    @AfterEach
    public void cleanup() {
        RuntimeConfig.updateState(previous);
        RuntimeConfig.setExportRunning(false);
        ExportStats.resetForTests();
        PartialFieldOpenSearchTestSupport.deleteIndex("exporter");
    }

    @Test
    void pushPreparedDocumentDuringShutdown_indexesWhenExportStopped() {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");
        PartialFieldOpenSearchTestSupport.createIndex("exporter");

        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_EXPORTER),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                PartialFieldOpenSearchTestSupport.openSearchSinks(),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                null));
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStarting(false);

        Map<String, Object> doc = new LinkedHashMap<>();
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("type", "shutdown_push_probe");
        doc.put("event", event);
        doc.put("meta", Map.of("schema_version", "1"));

        String indexName = IndexNaming.indexNameForShortName("exporter");
        PreparedExportDocument prepared = ExportDocumentIdentity.prepare(indexName, "exporter", doc);

        SearchClientWrapper.SingleDocPushResult blocked =
                IndexingRetryCoordinator.getInstance().pushPreparedDocumentWithResult(
                        PartialFieldOpenSearchTestSupport.baseUrl(), prepared);
        assertThat(blocked.success()).isFalse();

        SearchClientWrapper.SingleDocPushResult shutdown =
                IndexingRetryCoordinator.getInstance().pushPreparedDocumentDuringShutdown(
                        PartialFieldOpenSearchTestSupport.baseUrl(), prepared);
        assertThat(shutdown.success()).isTrue();
    }
}
