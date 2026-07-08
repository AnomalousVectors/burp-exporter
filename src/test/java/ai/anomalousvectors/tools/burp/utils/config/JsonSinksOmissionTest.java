package ai.anomalousvectors.tools.burp.utils.config;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

class JsonSinksOmissionTest {

    private static final String FILES_ROOT = "/path/to/directory";
    private static final String OS_URL = "https://opensearch.url:9200";

    @Test
    void build_omits_blank_sinks_fields() throws IOException {
        var state = new ConfigState.State(
                null, "all", null,
                new ConfigState.Sinks(false, "", false, "", "", "", ConfigState.OPEN_SEARCH_TLS_VERIFY),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        );

        String json = ConfigJsonMapper.build(state);
        assertThat(json).contains("\"sinks\" : {");
        assertThat(json).contains("\"files\" : {");
        assertThat(json).contains("\"enabled\" : false");
        assertThat(json).contains("\"formats\" : [ ]");
        assertThat(json).contains("\"limits\" : {");
        assertThat(json).contains("\"database\" : {");
        assertThat(json).contains("\"type\" : \"openSearch\"");
        assertThat(json).contains("\"openSearch\" : {");
        assertThat(json).contains("\"tlsMode\" : \"verify\"");
        assertThat(json).contains("\"auth\" : {");

        Json.ImportedConfig cfg = Json.parseConfigJson(json);
        assertThat(cfg.filesEnabled()).isFalse();
        assertThat(cfg.filesPath()).isNull();
        assertThat(cfg.fileJsonlEnabled()).isFalse();
        assertThat(cfg.fileBulkNdjsonEnabled()).isFalse();
        assertThat(cfg.fileTotalCapEnabled()).isTrue();
        assertThat(cfg.fileTotalCapGb()).isEqualTo(ConfigState.DEFAULT_FILE_TOTAL_CAP_GB);
        assertThat(cfg.fileDiskUsagePercentEnabled()).isTrue();
        assertThat(cfg.fileDiskUsagePercent()).isEqualTo(ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT);
        assertThat(cfg.openSearchEnabled()).isFalse();
        assertThat(cfg.openSearchUrl()).isNull();
        assertThat(cfg.searchDestination()).isEqualTo(ConfigState.SearchDestination.OPEN_SEARCH.configKey());
        assertThat(cfg.openSearchTlsMode()).isEqualTo(ConfigState.OPEN_SEARCH_TLS_VERIFY);
        assertThat(cfg.openSearchOptions().authType()).isEqualTo(ConfigState.DEFAULT_OPEN_SEARCH_AUTH_TYPE);
    }

    @Test
    void build_includes_nonEmpty_sinks_fields() throws IOException {
        var state = new ConfigState.State(
                null, "all", null,
                new ConfigState.Sinks(true, FILES_ROOT, true, true,
                        true, 9d,
                        true, 92,
                        true, OS_URL, "admin", "admin", ConfigState.OPEN_SEARCH_TLS_PINNED),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        );

        String json = ConfigJsonMapper.build(state);
        assertThat(json).doesNotContain("openSearchPassword");
        assertThat(json).doesNotContain("\"fileFormats\"");
        assertThat(json).doesNotContain("\"filesEnabled\"");
        assertThat(json).doesNotContain("\"openSearchEnabled\"");
        assertThat(json).doesNotContain("\"openSearchTlsMode\"");
        assertThat(json).contains("\"files\" : {");
        assertThat(json).contains("\"enabled\" : true");
        assertThat(json).contains("\"path\" : \"" + FILES_ROOT + "\"");
        assertThat(json).contains("\"formats\" : [ \"jsonl\", \"bulkNdjson\" ]");
        assertThat(json).contains("\"limits\" : {");
        assertThat(json).contains("\"enabled\" : true");
        assertThat(json).contains("\"type\" : \"openSearch\"");
        assertThat(json).contains("\"openSearch\" : {");
        assertThat(json).contains("\"url\" : \"" + OS_URL + "\"");
        assertThat(json).contains("\"tlsMode\" : \"pinned\"");
        assertThat(json).contains("\"auth\" : {");
        assertThat(json).contains("\"type\" : \"Basic\"");
        assertThat(json).contains("\"username\" : \"admin\"");

        Json.ImportedConfig cfg = Json.parseConfigJson(json);
        assertThat(cfg.filesEnabled()).isTrue();
        assertThat(cfg.filesPath()).isEqualTo(FILES_ROOT);
        assertThat(cfg.fileJsonlEnabled()).isTrue();
        assertThat(cfg.fileBulkNdjsonEnabled()).isTrue();
        assertThat(cfg.fileTotalCapEnabled()).isTrue();
        assertThat(cfg.fileTotalCapGb()).isEqualTo(9d);
        assertThat(cfg.fileDiskUsagePercentEnabled()).isTrue();
        assertThat(cfg.fileDiskUsagePercent()).isEqualTo(92);
        assertThat(cfg.openSearchEnabled()).isTrue();
        assertThat(cfg.openSearchUrl()).isEqualTo(OS_URL);
        assertThat(cfg.openSearchUser()).isEqualTo("admin");
        assertThat(cfg.openSearchPassword()).isBlank();
        assertThat(cfg.openSearchTlsMode()).isEqualTo(ConfigState.OPEN_SEARCH_TLS_PINNED);
        assertThat(cfg.openSearchOptions().authType()).isEqualTo("Basic");
    }

    @Test
    void build_preserves_disabled_destinations_and_nonSecret_openSearch_settings() throws IOException {
        ConfigState.OpenSearchOptions options = new ConfigState.OpenSearchOptions(
                "Certificate",
                "key-id-1",
                "client-cert.pem",
                "client-key.pem",
                "/tmp/opensearch-cert.pem",
                "abc123",
                "ZmFrZWNlcnQ=");
        var state = new ConfigState.State(
                null, "all", null,
                new ConfigState.Sinks(false, FILES_ROOT, true, false,
                        false, 7d,
                        false, 88,
                        false, OS_URL, "alice", "", ConfigState.OPEN_SEARCH_TLS_PINNED, options),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        );

        String json = ConfigJsonMapper.build(state);
        assertThat(json).contains("\"files\" : {");
        assertThat(json).contains("\"enabled\" : false");
        assertThat(json).contains("\"path\" : \"" + FILES_ROOT + "\"");
        assertThat(json).contains("\"formats\" : [ \"jsonl\" ]");
        assertThat(json).contains("\"limits\" : {");
        assertThat(json).contains("\"totalEnabled\" : false");
        assertThat(json).contains("\"diskUsedPercentEnabled\" : false");
        assertThat(json).contains("\"enabled\" : false");
        assertThat(json).contains("\"database\" : {");
        assertThat(json).contains("\"type\" : \"openSearch\"");
        assertThat(json).contains("\"openSearch\" : {");
        assertThat(json).contains("\"url\" : \"" + OS_URL + "\"");
        assertThat(json).contains("\"tlsMode\" : \"pinned\"");
        assertThat(json).contains("\"auth\" : {");
        assertThat(json).contains("\"type\" : \"Certificate\"");
        assertThat(json).doesNotContain("\"username\" : \"alice\"");
        assertThat(json).doesNotContain("\"apiKeyId\" : \"key-id-1\"");
        assertThat(json).contains("\"certPath\" : \"client-cert.pem\"");
        assertThat(json).contains("\"certKeyPath\" : \"client-key.pem\"");
        assertThat(json).contains("\"pinnedTlsCertificate\" : {");
        Json.ImportedConfig cfg = Json.parseConfigJson(json);

        assertThat(cfg.filesEnabled()).isFalse();
        assertThat(cfg.filesPath()).isEqualTo(FILES_ROOT);
        assertThat(cfg.fileJsonlEnabled()).isTrue();
        assertThat(cfg.fileBulkNdjsonEnabled()).isFalse();
        assertThat(cfg.fileTotalCapEnabled()).isFalse();
        assertThat(cfg.fileDiskUsagePercentEnabled()).isFalse();
        assertThat(cfg.openSearchEnabled()).isFalse();
        assertThat(cfg.openSearchUrl()).isEqualTo(OS_URL);
        assertThat(cfg.openSearchUser()).isBlank();
        assertThat(cfg.openSearchOptions().authType()).isEqualTo("Certificate");
        assertThat(cfg.openSearchOptions().apiKeyId()).isBlank();
        assertThat(cfg.openSearchOptions().certPath()).isEqualTo("client-cert.pem");
        assertThat(cfg.openSearchOptions().certKeyPath()).isEqualTo("client-key.pem");
        assertThat(cfg.openSearchOptions().pinnedTlsCertificateSourcePath()).isEqualTo("/tmp/opensearch-cert.pem");
        assertThat(cfg.openSearchOptions().pinnedTlsCertificateFingerprintSha256()).isEqualTo("abc123");
        assertThat(cfg.openSearchOptions().pinnedTlsCertificateEncodedBase64()).isEqualTo("ZmFrZWNlcnQ=");
    }

    @Test
    void parse_blank_strings_are_treated_as_null() throws IOException {
        String json = """
            {
              "sinks": {
                "files": {
                  "path": ""
                },
                "database": {
                  "type": "openSearch",
                  "openSearch": {
                    "url": ""
                  }
                }
              }
            }
            """;

        Json.ImportedConfig cfg = Json.parseConfigJson(json);
        assertThat(cfg.filesPath()).isNull();
        assertThat(cfg.fileJsonlEnabled()).isFalse();
        assertThat(cfg.fileBulkNdjsonEnabled()).isFalse();
        assertThat(cfg.fileTotalCapEnabled()).isTrue();
        assertThat(cfg.fileDiskUsagePercentEnabled()).isTrue();
        assertThat(cfg.openSearchUrl()).isNull();
        assertThat(cfg.openSearchTlsMode()).isEqualTo(ConfigState.OPEN_SEARCH_TLS_VERIFY);
    }

    @Test
    void parse_nested_openSearch_apiKey_auth_preserves_nonSecret_apiKeyId() throws IOException {
        String json = """
            {
              "sinks": {
                "database": {
                  "enabled": true,
                  "type": "openSearch",
                  "openSearch": {
                    "url": "https://opensearch.url:9200",
                    "auth": {
                      "type": "API key",
                      "apiKeyId": "kid-1"
                    }
                  }
                }
              }
            }
            """;

        Json.ImportedConfig cfg = Json.parseConfigJson(json);
        assertThat(cfg.openSearchOptions().apiKeyId()).isEqualTo("kid-1");
    }
}
