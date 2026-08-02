package ai.anomalousvectors.tools.burp.utils.export;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

class ExportDocumentIdentityTest {

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
