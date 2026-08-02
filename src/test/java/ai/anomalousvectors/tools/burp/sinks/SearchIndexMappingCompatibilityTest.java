package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class SearchIndexMappingCompatibilityTest {

    @Test
    void liveMappingMayContainDynamicExtras() throws Exception {
        String expected = """
                {"mappings":{"dynamic":true,"properties":{
                  "meta":{"enabled":true,"properties":{
                    "schema_version":{"type":"keyword","ignore_above":8191}}},
                  "data":{"type":"object","enabled":true,"properties":{"count":{"type":"long"}}},
                  "wire":{"type":"binary","doc_values":false}}}}
                """;
        String live = """
                {"tool-burp-traffic":{"mappings":{"dynamic":"true","properties":{
                  "meta":{"properties":{"schema_version":{"type":"keyword","ignore_above":8191}}},
                  "data":{"properties":{"count":{"type":"long"}}},
                  "wire":{"type":"binary"},
                  "dynamic_extra":{"type":"text"}}}}}
                """;

        assertThat(SearchIndexMappingCompatibility.incompatibilityDetail(
                expected, live, "tool-burp-traffic")).isNull();
    }

    @Test
    void missingOrChangedRequiredMappingReturnsActionablePath() throws Exception {
        String expected = """
                {"mappings":{"properties":{"request":{"properties":{
                  "body":{"properties":{"b64":{"type":"binary","doc_values":false}}}}}}}}
                """;
        String missing = """
                {"tool-burp-traffic":{"mappings":{"properties":{"request":{"properties":{}}}}}}
                """;
        String changed = """
                {"tool-burp-traffic":{"mappings":{"properties":{"request":{"properties":{
                  "body":{"properties":{"b64":{"type":"keyword","doc_values":false}}}}}}}}}
                """;

        assertThat(SearchIndexMappingCompatibility.incompatibilityDetail(
                expected, missing, "tool-burp-traffic"))
                .contains("mappings.properties.request.properties.body");
        assertThat(SearchIndexMappingCompatibility.incompatibilityDetail(
                expected, changed, "tool-burp-traffic"))
                .contains("mappings.properties.request.properties.body.properties.b64.type")
                .contains("binary")
                .contains("keyword");
    }
}
