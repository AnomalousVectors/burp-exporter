package ai.anomalousvectors.tools.burp.utils.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.util.Set;

import org.junit.jupiter.api.Test;

class ConfigImportResilienceTest {

    @Test
    void parse_reportsUnknownValues_butAppliesRecognizedSettings() throws IOException {
        String json = """
                {
                  "version": "test",
                  "dataSources": ["traffic", "legacy_source"],
                  "dataSourceOptions": {
                    "traffic": ["proxy", "unknown_tool"],
                    "findings": ["high"]
                  },
                  "scope": ["all"],
                  "sinks": {
                    "files": { "enabled": false },
                    "database": {
                      "enabled": false,
                      "type": "openSearch",
                      "openSearch": { "auth": { "type": "None" } }
                    },
                    "legacySinkFlag": true
                  },
                  "exportFields": {
                    "traffic": ["request.url.raw", "request.body.removed"],
                    "legacy_index": ["meta.export_id"]
                  },
                  "removedTopLevel": true
                }
                """;

        ConfigParseResult result = ConfigJsonMapper.parse(json);

        assertThat(result.state().dataSources()).contains("traffic");
        assertThat(result.state().dataSources()).doesNotContain("legacy_source");
        assertThat(result.state().trafficToolTypes()).containsExactly("proxy");
        assertThat(result.state().findingsSeverities()).containsExactly("high");
        assertThat(result.state().enabledExportFieldsByIndex())
                .containsKey("traffic")
                .satisfies(map -> assertThat(map.get("traffic")).isEqualTo(Set.of("request.url.raw")));

        ConfigImportReport report = result.report();
        assertThat(report.warningCount()).isGreaterThanOrEqualTo(6);
        assertThat(report.warnings())
                .anyMatch(w -> w.jsonPath().equals("dataSources") && w.rejectedValue().equals("legacy_source"))
                .anyMatch(w -> w.jsonPath().equals("dataSourceOptions.traffic")
                        && w.rejectedValue().equals("unknown_tool"))
                .anyMatch(w -> w.jsonPath().equals("exportFields.traffic")
                        && w.rejectedValue().equals("request.body.removed"))
                .anyMatch(w -> w.jsonPath().startsWith("exportFields.legacy_index")
                        || w.jsonPath().equals("exportFields.legacy_index"))
                .anyMatch(w -> w.jsonPath().equals("removedTopLevel"))
                .anyMatch(w -> w.jsonPath().equals("legacySinkFlag")
                        || w.jsonPath().equals("sinks.legacySinkFlag"));
    }

    @Test
    void parse_stillFailsOnLegacyFlatSinkKeys() {
        String json = """
                {
                  "dataSources": ["exporter"],
                  "sinks": {
                    "filesEnabled": true
                  }
                }
                """;

        assertThatThrownBy(() -> ConfigJsonMapper.parse(json))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("sinks.database");
    }

    @Test
    void parse_stillFailsOnInvalidOpenSearchAuthType() {
        String json = """
                {
                  "dataSources": ["exporter"],
                  "sinks": {
                    "database": {
                      "enabled": true,
                      "type": "openSearch",
                      "openSearch": {
                        "url": "https://example:9200",
                        "auth": { "type": "NotARealAuth" }
                      }
                    }
                  }
                }
                """;

        assertThatThrownBy(() -> ConfigJsonMapper.parse(json))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("sinks.database.openSearch.auth.type");
    }

    @Test
    void parse_reportsUnsupportedFileFormat() throws IOException {
        String json = """
                {
                  "dataSources": ["exporter"],
                  "sinks": {
                    "files": {
                      "enabled": true,
                      "path": "/tmp",
                      "formats": ["bulkNdjson", "xml"]
                    },
                    "database": {
                      "enabled": false,
                      "type": "openSearch",
                      "openSearch": { "auth": { "type": "None" } }
                    }
                  }
                }
                """;

        ConfigParseResult result = ConfigJsonMapper.parse(json);

        assertThat(result.state().sinks().fileBulkNdjsonEnabled()).isTrue();
        assertThat(result.state().sinks().fileJsonlEnabled()).isFalse();
        assertThat(result.report().warnings())
                .anyMatch(w -> w.kind() == ConfigImportReport.Kind.UNSUPPORTED_FORMAT
                        && "xml".equals(w.rejectedValue()));
    }

    @Test
    void parse_reportsUnrecognizedScopeShorthand() throws IOException {
        String json = """
                {
                  "dataSources": ["exporter"],
                  "scope": ["custom_only"],
                  "sinks": {
                    "database": {
                      "enabled": false,
                      "type": "openSearch",
                      "openSearch": { "auth": { "type": "None" } }
                    }
                  }
                }
                """;

        ConfigParseResult result = ConfigJsonMapper.parse(json);

        assertThat(result.state().scopeType()).isEqualTo("custom");
        assertThat(result.report().warnings())
                .anyMatch(w -> w.kind() == ConfigImportReport.Kind.UNRECOGNIZED_SCOPE
                        && w.rejectedValue().equals("custom_only"));
    }
}
