package ai.anomalousvectors.tools.burp.utils.export;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

class ExportDocumentIdentityTest {

    @Test
    void streamingIdentityIsIndependentOfSourceFields_andOrdinarySourceCannotEnableReplacement() {
        var previous = ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.getState();
        try {
            ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.updateState(
                    new ai.anomalousvectors.tools.burp.utils.config.ConfigState.State(
                            java.util.List.of("traffic"), "all", java.util.List.of(), null,
                            ai.anomalousvectors.tools.burp.utils.config.ConfigState.DEFAULT_SETTINGS_SUB,
                            ai.anomalousvectors.tools.burp.utils.config.ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                            ai.anomalousvectors.tools.burp.utils.config.ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                            ai.anomalousvectors.tools.burp.utils.config.ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                            ai.anomalousvectors.tools.burp.utils.config.ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                            Map.of("traffic", java.util.Set.of())));
            Map<String, Object> document = Map.of("meta", Map.of("schema_version", "1",
                    "capture", Map.of("id", "untrusted", "revision", 500)));
            var prepared = ExportDocumentIdentity.prepareStreaming("tool-burp-traffic", "traffic",
                    Map.of(), "proxy", new SearchDocumentRevision("trusted", 2));
            assertThat(prepared.document().toString()).doesNotContain("capture", "trusted", "untrusted");
            assertThat(prepared.searchRevision()).isEqualTo(new SearchDocumentRevision("trusted", 2));
            assertThat(ExportDocumentIdentity.prepare("tool-burp-traffic", "traffic", document).searchRevision())
                    .isNull();
        } finally {
            ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void streaming_reusesDatabaseIdentityButNotOperationIdentity_andPreservesDerivedMetadata() throws Exception {
        var first = ExportDocumentIdentity.prepareStreaming("tool-burp-traffic", "traffic",
                sampleDoc("one"), "proxy", new SearchDocumentRevision("capture-a", 1));
        var second = ExportDocumentIdentity.prepareStreaming("tool-burp-traffic", "traffic",
                sampleDoc("two"), "proxy", new SearchDocumentRevision("capture-a", 2));
        var independent = ExportDocumentIdentity.prepareStreaming("tool-burp-traffic", "traffic",
                sampleDoc("two"), "proxy", new SearchDocumentRevision("capture-b", 1));
        assertThat(first.operationId()).isNotEqualTo(second.operationId());
        assertThat(first.searchRevision().documentId()).isEqualTo(second.searchRevision().documentId());
        assertThat(independent.searchRevision().documentId()).isNotEqualTo(second.searchRevision().documentId());
        var derived = ExportDocumentIdentity.reprepareDerived(second, Map.of("meta", Map.of("schema_version", "1")));
        assertThat(derived.operationId()).isEqualTo(second.operationId());
        assertThat(derived.searchRevision()).isEqualTo(second.searchRevision());
        assertThat(derived.trafficRouteKey()).isEqualTo("proxy");
        var action = tools.jackson.databind.json.JsonMapper.builder().build()
                .readTree(ExportLineCodec.bulkNdjsonLines(derived).getFirst()).path("index");
        assertThat(action.path("_id").asString()).isEqualTo("capture-a");
        assertThat(action.path("version").asLong()).isEqualTo(2);
        assertThat(action.path("version_type").asString()).isEqualTo("external");
        assertThat(derived.document().toString()).doesNotContain("capture-a");
    }

    @Test
    void replacementMetadataRejectsBlankIdentityAndNonpositiveVersions() {
        assertThatThrownBy(() -> new SearchDocumentRevision("", 1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SearchDocumentRevision("capture", 0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SearchDocumentRevision("capture", -1)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void prepare_withBlankLogicalKey_rejectsCustomPhysicalIndexName() {
        assertThatThrownBy(() -> ExportDocumentIdentity.prepare(
                "custom-prefix-traffic", "", Map.of("message", "x")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("pass the logical index key explicitly");
    }

    @Test
    void prepare_recordsEstimatedBulkBytes() {
        Map<String, Object> doc = sampleDoc("hello");
        PreparedExportDocument prepared = ExportDocumentIdentity.prepare("attack-traffic", "traffic", doc);
        assertThat(prepared.estimatedBulkBytes()).isEqualTo(prepared.bulkNdjsonBytes().length);
    }

    @Test
    void prepare_recordsBulkNdjsonBytesMatchingExportLineCodec() throws Exception {
        Map<String, Object> doc = sampleDoc("hello");
        PreparedExportDocument prepared = ExportDocumentIdentity.prepare("attack-traffic", "traffic", doc);
        assertThat(prepared.bulkNdjsonBytes())
                .isEqualTo(ExportLineCodec.bulkNdjsonBytes(
                        prepared.operationId(), prepared.document()));
    }

    @Test
    void prepare_writesOperationIdOnlyToBulkActionMetadata() {
        PreparedExportDocument prepared = ExportDocumentIdentity.prepare(
                "attack-traffic", "traffic", sampleDoc("payload"));
        Map<?, ?> meta = (Map<?, ?>) prepared.document().get("meta");
        assertThat(meta.containsKey("export_id")).isFalse();
        assertThat(meta.containsKey("identity_key")).isFalse();
        assertThat(prepared.document().toString()).doesNotContain(prepared.operationId());
        assertThat(new String(prepared.bulkNdjsonBytes(), java.nio.charset.StandardCharsets.UTF_8))
                .startsWith("{\"index\":{\"_id\":\"" + prepared.operationId() + "\"}}\n");
    }

    @Test
    void prepareWithTrafficRoute_keepsRouteOutsideExportedSourceAndPreservesDerivedCopy() {
        String routeKey = "proxy_websocket_history";
        PreparedExportDocument prepared = ExportDocumentIdentity.prepareWithTrafficRoute(
                "attack-traffic", "traffic", sampleDoc("payload"), routeKey);

        assertThat(prepared.trafficRouteKey()).isEqualTo(routeKey);
        assertThat(prepared.document().toString()).doesNotContain(routeKey);
        assertThat(new String(prepared.bulkNdjsonBytes(), java.nio.charset.StandardCharsets.UTF_8))
                .doesNotContain(routeKey);

        PreparedExportDocument derived = ExportDocumentIdentity.reprepareDerived(
                prepared, prepared.document());
        assertThat(derived.trafficRouteKey()).isEqualTo(routeKey);
    }

    @Test
    void prepare_sameBodyTwice_producesIndependentPreparedDocuments() {
        Map<String, Object> doc = sampleDoc("same");
        PreparedExportDocument first = ExportDocumentIdentity.prepare("attack-traffic", "traffic", doc);
        PreparedExportDocument second = ExportDocumentIdentity.prepare("attack-traffic", "traffic", sampleDoc("same"));
        assertThat(first.document()).isNotSameAs(second.document());
        assertThat(first.operationId()).isNotEqualTo(second.operationId());
    }

    private static Map<String, Object> sampleDoc(String message) {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", "1");
        meta.put("indexed_at", "2026-01-01T00:00:00Z");

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("meta", meta);
        doc.put("message", message);
        return doc;
    }
}
