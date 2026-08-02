package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class SearchIndexSettingsCompatibilityTest {

    @Test
    void settingsReadPermissionDenialsAllowUnverifiedExistingIndex() {
        assertThat(SearchIndexSettingsCompatibility.isSettingsReadPermissionDenied(401)).isTrue();
        assertThat(SearchIndexSettingsCompatibility.isSettingsReadPermissionDenied(403)).isTrue();
        assertThat(SearchIndexSettingsCompatibility.isSettingsReadPermissionDenied(404)).isFalse();
        assertThat(SearchIndexSettingsCompatibility.isSettingsReadPermissionDenied(500)).isFalse();
    }

    @Test
    void compatibleFlatSettingsReturnNoDetail() {
        String expected = """
                {"settings":{
                  "number_of_shards":1,
                  "auto_expand_replicas":"0-1",
                  "refresh_interval":"5s"
                },"mappings":{}}
                """;
        String live = """
                {"tool-burp-exporter":{"settings":{
                  "index.number_of_shards":"1",
                  "index.auto_expand_replicas":"0-1",
                  "index.refresh_interval":"5s",
                  "index.creation_date":"123"
                }}}
                """;

        assertThat(SearchIndexSettingsCompatibility.incompatibilityDetail(
                expected, live, "tool-burp-exporter")).isNull();
    }

    @Test
    void legacyShardAndReplicaSettingsReturnActionableDetail() {
        String expected = """
                {"settings":{
                  "number_of_shards":1,
                  "auto_expand_replicas":"0-1",
                  "refresh_interval":"5s"
                },"mappings":{}}
                """;
        String live = """
                {"tool-burp-exporter":{"settings":{
                  "index.number_of_shards":"5",
                  "index.number_of_replicas":"1",
                  "index.refresh_interval":"1s"
                }}}
                """;

        assertThat(SearchIndexSettingsCompatibility.incompatibilityDetail(
                expected, live, "tool-burp-exporter"))
                .contains("index.number_of_shards=5 (expected 1)")
                .contains("index.auto_expand_replicas=<missing> (expected 0-1)")
                .contains("index.refresh_interval=1s (expected 5s)")
                .contains("Delete/recreate");
    }

    @Test
    void deploymentAdaptedSettingsIgnoreRemovedShardKeys() {
        String expected = """
                {"settings":{"refresh_interval":"5s"},"mappings":{}}
                """;
        String live = """
                {"tool-burp-traffic":{"settings":{
                  "index.number_of_shards":"3",
                  "index.number_of_replicas":"2",
                  "index.refresh_interval":"5s"
                }}}
                """;

        assertThat(SearchIndexSettingsCompatibility.incompatibilityDetail(
                expected, live, "tool-burp-traffic")).isNull();
    }
}
