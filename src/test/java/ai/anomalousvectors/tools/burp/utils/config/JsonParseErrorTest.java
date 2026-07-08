package ai.anomalousvectors.tools.burp.utils.config;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Verifies error surfacing: invalid JSON should propagate an IOException.
 */
class JsonParseErrorTest {

    @Test
    void parse_invalid_json_throwsIOException() {
        String invalid = "{";
        assertThatThrownBy(() -> Json.parseConfigJson(invalid))
                .isInstanceOf(IOException.class);
    }

    @Test
    void parse_flat_sinks_shape_throwsIOException() {
        String invalid = """
            {
              "sinks": {
                "filesEnabled": true,
                "files": "/tmp/exports"
              }
            }
            """;
        assertThatThrownBy(() -> Json.parseConfigJson(invalid))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("sinks.database");
    }

    @Test
    void parse_unknown_sinks_field_reportsWarningAndContinues() throws IOException {
        String json = """
            {
              "dataSources": ["exporter"],
              "sinks": {
                "files": {
                  "enabled": true
                },
                "database": {
                  "enabled": false,
                  "type": "openSearch",
                  "openSearch": { "auth": { "type": "None" } }
                },
                "unexpected": {}
              }
            }
            """;
        ConfigParseResult result = ConfigJsonMapper.parse(json);
        assertThat(result.state().dataSources()).containsExactly("exporter");
        assertThat(result.report().warnings())
                .anyMatch(w -> w.jsonPath().equals("unexpected") || w.jsonPath().equals("sinks.unexpected"));
    }

    @Test
    void parse_unknown_files_format_reportsWarningAndContinues() throws IOException {
        String json = """
            {
              "dataSources": ["exporter"],
              "sinks": {
                "files": {
                  "formats": [ "ndjson" ]
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
        assertThat(result.report().warnings())
                .anyMatch(w -> w.kind() == ConfigImportReport.Kind.UNSUPPORTED_FORMAT
                        && "ndjson".equals(w.rejectedValue()));
    }

    @Test
    void parse_nonObject_nested_sink_throwsIOException() {
        String invalid = """
            {
              "sinks": {
                "files": ""
              }
            }
            """;
        assertThatThrownBy(() -> Json.parseConfigJson(invalid))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("sinks.files")
                .hasMessageContaining("must be an object");
    }

    @Test
    void parse_unknown_files_limits_field_reportsWarningAndContinues() throws IOException {
        String json = """
            {
              "dataSources": ["exporter"],
              "sinks": {
                "files": {
                  "limits": {
                    "totalEnabled": true,
                    "maxDiskPercent": 90
                  }
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
        assertThat(result.state().sinks().fileTotalCapEnabled()).isTrue();
        assertThat(result.report().warnings())
                .anyMatch(w -> w.jsonPath().equals("sinks.files.limits.maxDiskPercent"));
    }

    @Test
    void parse_unknown_openSearch_auth_field_reportsWarningAndContinues() throws IOException {
        String json = """
            {
              "dataSources": ["exporter"],
              "sinks": {
                "database": {
                  "enabled": true,
                  "type": "openSearch",
                  "openSearch": {
                    "url": "https://example:9200",
                    "auth": {
                      "type": "Basic",
                      "username": "admin",
                      "password": "secret"
                    }
                  }
                }
              }
            }
            """;
        ConfigParseResult result = ConfigJsonMapper.parse(json);
        assertThat(result.state().sinks().openSearchUser()).isEqualTo("admin");
        assertThat(result.report().warnings())
                .anyMatch(w -> w.jsonPath().equals("sinks.database.openSearch.auth.password"));
    }

    @Test
    void parse_unknown_database_type_throwsIOException() {
        String invalid = """
            {
              "sinks": {
                "database": {
                  "enabled": true,
                  "type": "solr",
                  "openSearch": { "auth": { "type": "None" } }
                }
              }
            }
            """;
        assertThatThrownBy(() -> Json.parseConfigJson(invalid))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("sinks.database.type")
                .hasMessageContaining("solr");
    }

    @Test
    void parse_basic_auth_with_apiKeyId_throwsIOException() {
        assertInvalidAuthFieldCombination("Basic", "apiKeyId", "kid-1");
    }

    @Test
    void parse_certificate_auth_with_username_throwsIOException() {
        assertInvalidAuthFieldCombination("Certificate", "username", "ops-user");
    }

    @Test
    void parse_none_auth_with_certPath_throwsIOException() {
        assertInvalidAuthFieldCombination("None", "certPath", "client.pem");
    }

    @Test
    void parse_unknown_pinned_certificate_field_reportsWarningAndContinues() throws IOException {
        String json = """
            {
              "dataSources": ["exporter"],
              "sinks": {
                "database": {
                  "enabled": false,
                  "type": "openSearch",
                  "openSearch": {
                    "auth": { "type": "None" },
                    "pinnedTlsCertificate": {
                      "sourcePath": "cert.pem",
                      "sha256": "abc123"
                    }
                  }
                }
              }
            }
            """;
        ConfigParseResult result = ConfigJsonMapper.parse(json);
        assertThat(result.state().sinks().openSearchOptions().pinnedTlsCertificateSourcePath()).isEqualTo("cert.pem");
        assertThat(result.report().warnings())
                .anyMatch(w -> w.jsonPath().equals("sinks.database.openSearch.pinnedTlsCertificate.sha256"));
    }

    private static void assertInvalidAuthFieldCombination(String authType, String fieldName, String fieldValue) {
        String invalid = """
            {
              "sinks": {
                "database": {
                  "type": "openSearch",
                  "openSearch": {
                    "auth": {
                      "type": "%s",
                      "%s": "%s"
                    }
                  }
                }
              }
            }
            """.formatted(authType, fieldName, fieldValue);
        assertThatThrownBy(() -> Json.parseConfigJson(invalid))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("sinks.database.openSearch.auth." + fieldName)
                .hasMessageContaining("sinks.database.openSearch.auth.type")
                .hasMessageContaining(authType);
    }
}
