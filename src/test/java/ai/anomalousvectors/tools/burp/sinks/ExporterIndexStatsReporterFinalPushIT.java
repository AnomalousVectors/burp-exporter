package ai.anomalousvectors.tools.burp.sinks;

import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.createIndex;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.deleteIndex;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.openSearchSinks;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch._types.FieldValue;
import org.opensearch.client.opensearch.core.CountRequest;
import org.opensearch.client.opensearch.core.CountResponse;
import org.opensearch.client.opensearch.core.SearchRequest;
import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.indices.RefreshRequest;

import com.fasterxml.jackson.databind.JsonNode;

import ai.anomalousvectors.tools.burp.testutils.OpenSearchReachable;
import ai.anomalousvectors.tools.burp.testutils.OpenSearchTestConfig;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchConnector;

/**
 * Integration test: final exporter stats snapshot indexes with {@code running:false} after Stop.
 */
@Tag("integration")
@ResourceLock("exporter-opensearch-index")
class ExporterIndexStatsReporterFinalPushIT {

    private final ConfigState.State previous = RuntimeConfig.getState();

    @AfterEach
    public void cleanup() {
        ExporterIndexStatsReporter.stop();
        RuntimeConfig.updateState(previous);
        RuntimeConfig.setExportRunning(false);
        ExportStats.resetForTests();
        deleteIndex("exporter");
    }

    @Test
    void pushFinalSnapshotNow_writesRunningFalseAndStatsWhenExportStopped() throws Exception {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");
        deleteIndex("exporter");
        createIndex("exporter");

        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_EXPORTER),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                openSearchSinks(),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                null));
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStarting(false);

        long misgate = 3;
        long wireReplaced = 2;
        long supplementalRejected = 1;
        for (int i = 0; i < misgate; i++) {
            ExportStats.recordBodyEnumerationMisgateSuspect();
        }
        for (int i = 0; i < wireReplaced; i++) {
            ExportStats.recordWireBodyParamsReplaced();
        }
        for (int i = 0; i < supplementalRejected; i++) {
            ExportStats.recordSupplementalRejectedNonForm();
        }
        ExportStats.recordBodyParamsSkipReason("wire_replaced");
        ExportStats.recordBodyParamsSkipReason("wire_replaced");
        ExportStats.recordBodyParamsSkipReason("misgate_binary");
        ExportStats.recordBodyParamsSkipReason("misgate_binary");
        ExportStats.recordBodyParamsSkipReason("misgate_binary");

        ExporterStatsPushOutcome outcome = ExporterIndexStatsReporter.pushFinalSnapshotNow();

        assertThat(outcome.succeeded()).isTrue();

        OpenSearchTestConfig config = OpenSearchTestConfig.get();
        OpenSearchClient client = OpenSearchConnector.getClient(
                config.baseUrl(), config.username(), config.password());
        String indexName = IndexNaming.indexNameForShortName("exporter");
        client.indices().refresh(RefreshRequest.of(r -> r.index(indexName)));

        CountRequest countRequest = CountRequest.of(c -> c
                .index(indexName)
                .query(q -> q.bool(b -> b
                        .must(m -> m.term(t -> t.field("event.type").value(FieldValue.of("stats_snapshot"))))
                        .must(m -> m.term(t -> t
                                .field(ExporterIndexStatsReporter.EXPORTER_FINAL_RUNNING_FIELD)
                                .value(FieldValue.of(false)))))));
        CountResponse count = client.count(countRequest);
        assertThat(count.count()).isGreaterThanOrEqualTo(1);

        SearchRequest searchRequest = SearchRequest.of(s -> s
                .index(indexName)
                .size(1)
                .query(q -> q.bool(b -> b
                        .must(m -> m.term(t -> t.field("event.type").value(FieldValue.of("stats_snapshot"))))
                        .must(m -> m.term(t -> t
                                .field(ExporterIndexStatsReporter.EXPORTER_FINAL_RUNNING_FIELD)
                                .value(FieldValue.of(false)))))));
        SearchResponse<JsonNode> search = client.search(searchRequest, JsonNode.class);
        assertThat(search.hits().hits()).isNotEmpty();

        JsonNode source = java.util.Objects.requireNonNull(
                search.hits().hits().getFirst().source(),
                "indexed exporter stats document");
        assertThat(source.path("event").path("data").path("export").path("running").asBoolean()).isFalse();
        JsonNode stats = source.path("event").path("data").path("stats");
        JsonNode proxyCorrelation =
                source.path("event").path("data").path("traffic").path("proxy_correlation");
        assertThat(proxyCorrelation.isObject()).isTrue();
        for (String field : List.of(
                "proxy_request_callbacks",
                "http_proxy_requests",
                "http_marked_requests",
                "http_proxy_responses",
                "http_unmarked_tracked_responses",
                "http_unmarked_prerun_responses",
                "history_lookup_attempts",
                "history_lookup_matched_rows",
                "eligible_total",
                "bound_total",
                "pending_memory_count",
                "pending_memory_bytes",
                "pending_durable_count",
                "pending_durable_bytes",
                "durable_spooled_total",
                "lookup_failures",
                "cleanup_failures",
                "spool_failures",
                "explicit_failures")) {
            assertThat(proxyCorrelation.path(field).isNumber())
                    .as("numeric proxy correlation field %s", field)
                    .isTrue();
        }
        assertThat(stats.path("docs_body_enumeration_misgate_suspect_total").asLong()).isEqualTo(misgate);
        assertThat(stats.path("docs_wire_body_params_replaced_total").asLong()).isEqualTo(wireReplaced);
        assertThat(stats.path("docs_supplemental_rejected_non_form_total").asLong())
                .isEqualTo(supplementalRejected);
        assertThat(stats.path("body_params_skip_reason_counts").path("wire_replaced").asLong()).isEqualTo(2);
        assertThat(stats.path("body_params_skip_reason_counts").path("misgate_binary").asLong()).isEqualTo(3);
    }
}
