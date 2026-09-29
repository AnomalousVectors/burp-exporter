package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** Unit tests for {@link ParameterIntegrityDetailReporter}. */
class ParameterIntegrityDetailReporterTest {

    @Test
    void detailPointersUseReferenceWikiAnchors() {
        assertThat(ParameterIntegrityDetailReporter.detailPointer("url_params_truncated"))
                .endsWith("https://github.com/AnomalousVectors/burp-exporter/wiki/Reference#url_params_truncated");
        assertThat(ParameterIntegrityDetailReporter.compressedWireSummaryPointer())
                .endsWith("https://github.com/AnomalousVectors/burp-exporter/wiki/Reference#compressed_wire_body_params");
    }

    @Test
    void buildDetailDocs_chunksFullUrlLists() {
        Map<String, Integer> urls = new LinkedHashMap<>();
        for (int i = 0; i < 205; i++) {
            urls.put("https://example.test/" + i, 1);
        }

        List<Map<String, Object>> docs = ParameterIntegrityDetailReporter.buildDetailDocs(
                "startup_backlog",
                "misgate_binary",
                205,
                urls,
                Map.of("dropped_body_params", 17),
                "impact",
                ParameterIntegrityDetailReporter.UrlListPolicy.FULL);

        assertThat(docs).hasSize(3);
        assertThat(nestedMap(docs.getFirst(), "event").get("level")).isEqualTo("DEBUG");
        Map<?, ?> firstData = eventData(docs.getFirst());
        assertThat(firstData.get("category")).isEqualTo("misgate_binary");
        assertThat(firstData.get("doc_count")).isEqualTo(205);
        assertThat(firstData.get("unique_url_count")).isEqualTo(205);
        assertThat(firstData.get("chunk")).isEqualTo(1);
        assertThat(firstData.get("chunk_count")).isEqualTo(3);
        assertThat(firstData.get("log_truncated")).isEqualTo(true);
        assertThat(firstData.get("dropped_body_params")).isEqualTo(17);
        assertThat(listValue(firstData, "sample_urls")).hasSize(10);
        assertThat(listValue(firstData, "urls")).hasSize(ParameterIntegrityDetailReporter.URL_CHUNK_SIZE);
        assertThat(nestedMap(firstData, "query_hints").get("lucene"))
                .isEqualTo("event.type:parameter_integrity_detail AND event.data.category:misgate_binary");
    }

    @Test
    void buildDetailDocs_sampleOnlyOmitsFullUrls() {
        Map<String, Integer> urls = new LinkedHashMap<>();
        for (int i = 0; i < 12; i++) {
            urls.put("https://example.test/supplemental/" + i, 1);
        }

        List<Map<String, Object>> docs = ParameterIntegrityDetailReporter.buildDetailDocs(
                "live",
                "supplemental_added",
                12,
                urls,
                Map.of(),
                "impact",
                ParameterIntegrityDetailReporter.UrlListPolicy.SAMPLE_ONLY);

        assertThat(docs).hasSize(1);
        Map<?, ?> data = eventData(docs.getFirst());
        assertThat(data.get("category")).isEqualTo("supplemental_added");
        assertThat(listValue(data, "sample_urls")).hasSize(10);
        assertThat(data.containsKey("urls")).isFalse();
        assertThat(data.get("log_truncated")).isEqualTo(true);
    }

    private static Map<?, ?> eventData(Map<String, Object> doc) {
        return nestedMap(nestedMap(doc, "event"), "data");
    }

    private static Map<?, ?> nestedMap(Map<?, ?> parent, String key) {
        assertThat(parent.get(key)).isInstanceOf(Map.class);
        return (Map<?, ?>) parent.get(key);
    }

    private static List<?> listValue(Map<?, ?> parent, String key) {
        assertThat(parent.get(key)).isInstanceOf(List.class);
        return (List<?>) parent.get(key);
    }
}
