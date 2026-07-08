package ai.anomalousvectors.tools.burp.utils.config;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class JsonTypedRoundTripTest {

    @Test
    void build_and_parse_typed_custom_scope_preserves_order_and_kinds() throws IOException {
        List<String> sources = List.of("settings", "traffic");

        var state = new ConfigState.State(
                sources, "custom",
                List.of(
                        new ConfigState.ScopeEntry("x", ConfigState.Kind.REGEX),
                        new ConfigState.ScopeEntry("y", ConfigState.Kind.STRING)
                ),
                new ConfigState.Sinks(true, "/path/to/directory", true, true,
                        true, 7d,
                        true, 91,
                        true, "https://opensearch.url:9200", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS, ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                null
        );

        String json = ConfigJsonMapper.build(state);
        Json.ImportedConfig parsed = Json.parseConfigJson(json);

        assertThat(json).contains("\"totalGb\" : 7.0");
        assertThat(json).doesNotContain("totalBytes");
        assertThat(parsed.dataSources()).containsExactlyElementsOf(sources);
        assertThat(parsed.scopeType()).isEqualTo("custom");
        assertThat(parsed.scopeRegexes()).containsExactly("x", "y");
        assertThat(parsed.filesPath()).isEqualTo("/path/to/directory");
        assertThat(parsed.fileJsonlEnabled()).isTrue();
        assertThat(parsed.fileBulkNdjsonEnabled()).isTrue();
        assertThat(parsed.fileTotalCapEnabled()).isTrue();
        assertThat(parsed.fileTotalCapGb()).isEqualTo(7d);
        assertThat(parsed.fileDiskUsagePercentEnabled()).isTrue();
        assertThat(parsed.fileDiskUsagePercent()).isEqualTo(91);
        assertThat(parsed.openSearchUrl()).isEqualTo("https://opensearch.url:9200");
        assertThat(parsed.indexNameBaseTemplate()).isEqualTo(ConfigState.DEFAULT_INDEX_NAME_BASE_TEMPLATE);
    }

    @Test
    void build_all_scope_sets_flag_only() throws IOException {
        var state = new ConfigState.State(
                List.of("settings"), "all", null,
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        );

        String json = ConfigJsonMapper.build(state);
        Json.ImportedConfig parsed = Json.parseConfigJson(json);

        assertThat(parsed.scopeType()).isEqualTo("all");
        assertThat(parsed.scopeRegexes()).isEmpty();
    }

    @Test
    void build_burp_scope_sets_flag_only() throws IOException {
        var state = new ConfigState.State(
                List.of("traffic"), "burp", null,
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        );

        String json = ConfigJsonMapper.build(state);
        Json.ImportedConfig parsed = Json.parseConfigJson(json);

        assertThat(parsed.scopeType()).isEqualTo("burp");
        assertThat(parsed.scopeRegexes()).isEmpty();
    }

    @Test
    void build_and_parse_preserves_data_source_sub_options() throws IOException {
        var state = new ConfigState.State(
                List.of("settings", "traffic", "findings"), "all", List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                List.of(ConfigKeys.SRC_SETTINGS_PROJECT),
                List.of("proxy", "repeater"),
                List.of("high", "critical"),
                List.of(ConfigKeys.SRC_EXPORTER_INFO, ConfigKeys.SRC_EXPORTER_STATS),
                45,
                null
        );

        String json = ConfigJsonMapper.build(state);
        ConfigState.State parsed = ConfigJsonMapper.parseState(json);

        assertThat(json).contains("\"traffic\"");
        assertThat(json).contains("\"proxy\"");
        assertThat(json).contains("\"repeater\"");
        assertThat(json).contains("\"findings\"");
        assertThat(json).contains("\"high\"");
        assertThat(json).contains("\"critical\"");
        assertThat(json).contains("\"exporter\"");
        assertThat(json).contains("\"exporterStatsIntervalSeconds\" : 45");
        assertThat(parsed.settingsSub()).containsExactly(ConfigKeys.SRC_SETTINGS_PROJECT);
        assertThat(parsed.trafficToolTypes()).containsExactly("proxy", "repeater");
        assertThat(parsed.findingsSeverities()).containsExactlyInAnyOrder("high", "critical");
        assertThat(parsed.exporterSubOptions()).containsExactly(ConfigKeys.SRC_EXPORTER_INFO, ConfigKeys.SRC_EXPORTER_STATS);
        assertThat(parsed.exporterStatsIntervalSeconds()).isEqualTo(45);
    }

    @Test
    void build_and_parse_preserves_proxy_history_in_traffic_tool_types() throws IOException {
        var state = new ConfigState.State(
                List.of("traffic"), "all", List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy", "proxy_history", "repeater", "repeater_tabs"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                null
        );
        String json = ConfigJsonMapper.build(state);
        ConfigState.State parsed = ConfigJsonMapper.parseState(json);
        assertThat(parsed.trafficToolTypes()).containsExactlyInAnyOrder("proxy", "proxy_history", "repeater", "repeater_tabs");
    }

    @Test
    void build_and_parse_preserves_index_naming_base_template() throws IOException {
        var state = new ConfigState.State(
                List.of("exporter", "traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                "${now:yyyyMMdd}-tool-burp",
                null);

        String json = ConfigJsonMapper.build(state);
        ConfigState.State parsed = ConfigJsonMapper.parseState(json);

        assertThat(json).contains("\"indexNames\"");
        assertThat(json).contains("\"baseTemplate\" : \"${now:yyyyMMdd}-tool-burp\"");
        assertThat(parsed.indexNameBaseTemplate()).isEqualTo("${now:yyyyMMdd}-tool-burp");
    }

    @Test
    void build_and_parse_preserves_nonSecret_openSearch_auth_and_pinned_tls_settings() throws IOException {
        ConfigState.OpenSearchOptions openSearchOptions = new ConfigState.OpenSearchOptions(
                "Certificate",
                "kid-1",
                "client-cert.pem",
                "client-key.pem",
                "c:/tls/opensearch.pem",
                "fingerprint-123",
                "ZmFrZWNlcnQ=");
        var state = new ConfigState.State(
                List.of("settings"),
                "all",
                List.of(),
                new ConfigState.Sinks(
                        false,
                        "/path/to/directory",
                        true,
                        false,
                        false,
                        4d,
                        false,
                        90,
                        false,
                        "https://opensearch.url:9200",
                        "alice",
                        "",
                        ConfigState.OPEN_SEARCH_TLS_PINNED,
                        openSearchOptions),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                null);

        String json = ConfigJsonMapper.build(state);
        ConfigState.State parsed = ConfigJsonMapper.parseState(json);

        assertThat(json).contains("\"sinks\" : {");
        assertThat(json).contains("\"files\" : {");
        assertThat(json).contains("\"path\" : \"/path/to/directory\"");
        assertThat(json).contains("\"formats\" : [ \"jsonl\" ]");
        assertThat(json).contains("\"limits\" : {");
        assertThat(json).contains("\"database\" : {");
        assertThat(json).contains("\"type\" : \"openSearch\"");
        assertThat(json).contains("\"openSearch\" : {");
        assertThat(json).contains("\"url\" : \"https://opensearch.url:9200\"");
        assertThat(json).contains("\"tlsMode\" : \"pinned\"");
        assertThat(json).contains("\"auth\" : {");
        assertThat(json).contains("\"type\" : \"Certificate\"");
        assertThat(json).doesNotContain("\"username\" : \"alice\"");
        assertThat(json).contains("\"certPath\" : \"client-cert.pem\"");
        assertThat(json).contains("\"certKeyPath\" : \"client-key.pem\"");
        assertThat(json).contains("\"pinnedTlsCertificate\" : {");
        assertThat(json).doesNotContain("\"filesEnabled\"");
        assertThat(json).doesNotContain("\"fileFormats\"");
        assertThat(json).doesNotContain("\"openSearchEnabled\"");
        assertThat(json).doesNotContain("\"openSearchTlsMode\"");

        assertThat(parsed.sinks().filesEnabled()).isFalse();
        assertThat(parsed.sinks().filesPath()).isEqualTo("/path/to/directory");
        assertThat(parsed.sinks().fileJsonlEnabled()).isTrue();
        assertThat(parsed.sinks().fileBulkNdjsonEnabled()).isFalse();
        assertThat(parsed.sinks().osEnabled()).isFalse();
        assertThat(parsed.sinks().openSearchUrl()).isEqualTo("https://opensearch.url:9200");
        assertThat(parsed.sinks().openSearchUser()).isBlank();
        assertThat(parsed.sinks().openSearchOptions().authType()).isEqualTo("Certificate");
        assertThat(parsed.sinks().openSearchOptions().apiKeyId()).isBlank();
        assertThat(parsed.sinks().openSearchOptions().certPath()).isEqualTo("client-cert.pem");
        assertThat(parsed.sinks().openSearchOptions().certKeyPath()).isEqualTo("client-key.pem");
        assertThat(parsed.sinks().openSearchOptions().pinnedTlsCertificateSourcePath()).isEqualTo("c:/tls/opensearch.pem");
        assertThat(parsed.sinks().openSearchOptions().pinnedTlsCertificateFingerprintSha256()).isEqualTo("fingerprint-123");
        assertThat(parsed.sinks().openSearchOptions().pinnedTlsCertificateEncodedBase64()).isEqualTo("ZmFrZWNlcnQ=");
    }

    @Test
    void parse_json_without_dataSourceOptions_uses_current_defaults() throws IOException {
        String legacy = """
            {"version":"1.0","dataSources":["traffic"],"scope":["burp"],"sinks":{}}
            """;
        ConfigState.State parsed = ConfigJsonMapper.parseState(legacy);
        assertThat(parsed.dataSources()).contains("traffic", ConfigKeys.SRC_EXPORTER);
        assertThat(parsed.trafficToolTypes()).containsExactly(
                "burp_ai", "extensions", "intruder", "proxy",
                "proxy_history", "repeater", "repeater_tabs", "scanner", "sequencer");
        assertThat(parsed.settingsSub()).containsExactlyInAnyOrder(ConfigKeys.SRC_SETTINGS_PROJECT, ConfigKeys.SRC_SETTINGS_USER);
        assertThat(parsed.findingsSeverities()).containsExactlyInAnyOrder("critical", "high", "medium", "low", "informational");
        assertThat(parsed.exporterSubOptions()).containsExactlyElementsOf(ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS);
        assertThat(parsed.exporterStatsIntervalSeconds()).isEqualTo(ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS);
    }

    @Test
    void parse_json_dropsRemovedCollaboratorTrafficToolType() throws IOException {
        String json = """
            {
              "version": "1.0",
              "dataSources": ["traffic"],
              "scope": ["all"],
              "sinks": {},
              "dataSourceOptions": {
                "traffic": ["proxy", "collaborator", "repeater"]
              }
            }
            """;

        ConfigState.State parsed = ConfigJsonMapper.parseState(json);

        assertThat(parsed.trafficToolTypes()).containsExactly("proxy", "repeater");
    }

    @Test
    void parse_json_with_explicit_empty_exporter_options_preserves_disabled_exporter_sub_options() throws IOException {
        String json = """
            {
              "version": "1.0",
              "dataSources": ["exporter"],
              "scope": ["all"],
              "sinks": {},
              "dataSourceOptions": {
                "settings": ["project", "user"],
                "traffic": [],
                "findings": ["critical", "high", "medium", "low", "informational"],
                "exporter": [],
                "exporterStatsIntervalSeconds": 15
              }
            }
            """;

        ConfigState.State parsed = ConfigJsonMapper.parseState(json);

        assertThat(parsed.dataSources()).containsExactly(ConfigKeys.SRC_EXPORTER);
        assertThat(parsed.exporterSubOptions()).isEmpty();
        assertThat(parsed.exporterStatsIntervalSeconds()).isEqualTo(15);
    }

    @Test
    void build_omitsDataSourceOptionsExceptTrafficWhenOnlyIntruderDisabled() throws IOException {
        List<String> trafficWithoutIntruder = ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES.stream()
                .filter(tool -> !"intruder".equals(tool))
                .toList();
        var state = new ConfigState.State(
                ConfigImportCatalog.allDataSourcesForEdition(false),
                ConfigKeys.SCOPE_BURP,
                List.of(),
                new ConfigState.Sinks(false, "/path/to/directory", false, false, true,
                        "https://opensearch.url:9200", "", "", ConfigState.OPEN_SEARCH_TLS_VERIFY),
                ConfigState.DEFAULT_SETTINGS_SUB,
                trafficWithoutIntruder,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                Map.of("settings", Set.of("project", "user", "burp.version")),
                ConfigState.defaultUiPreferences());

        String json = ConfigJsonMapper.build(state);

        assertThat(json).contains("\"dataSourceOptions\"");
        assertThat(json).doesNotContain("exporterStatsIntervalSeconds");
        assertThat(json).doesNotContain("intruder");
        assertThat(json).doesNotContain("\"dataSourceOptions\" : {\n    \"settings\"");
        assertThat(json).doesNotContain("\"dataSourceOptions\" : {\n    \"findings\"");

        ConfigState.State parsed = ConfigJsonMapper.parseState(json);
        assertThat(parsed.trafficToolTypes()).containsExactlyElementsOf(trafficWithoutIntruder);
        assertThat(parsed.settingsSub()).containsExactlyInAnyOrder("project", "user");
    }

    @Test
    void build_omitsDataSourcesWhenAllKnownSourcesSelected() throws IOException {
        List<String> allSources = ConfigImportCatalog.allDataSourcesForEdition(false);
        var state = new ConfigState.State(
                allSources,
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                null);

        String json = ConfigJsonMapper.build(state);

        assertThat(json).doesNotContain("\"dataSources\"");
        assertThat(ConfigJsonMapper.parseState(json).dataSources()).containsExactlyElementsOf(allSources);
    }

    @Test
    void parse_missingDataSources_defaultsToAllKnownSources() throws IOException {
        String json = """
            {
              "version": "1.0",
              "scope": ["all"],
              "sinks": {
                "database": {
                  "enabled": false,
                  "type": "openSearch",
                  "openSearch": { "auth": { "type": "None" } }
                }
              }
            }
            """;

        assertThat(ConfigJsonMapper.parseState(json).dataSources())
                .containsExactlyElementsOf(ConfigImportCatalog.allDataSourcesForEdition(false));
    }

    @Test
    void build_omitsExportFieldsEntriesForIndexesWithAllToggleablesSelected() throws IOException {
        String trafficField = ExportFieldRegistry.getToggleableFields("traffic").getFirst();
        Map<String, Set<String>> enabledByIndex = Map.of(
                "traffic", Set.of(trafficField),
                "settings", Set.copyOf(ExportFieldRegistry.getToggleableFields("settings")));

        var state = new ConfigState.State(
                List.of("settings", "traffic"), "all", List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS, ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                enabledByIndex);

        ConfigState.State parsed = ConfigJsonMapper.parseState(ConfigJsonMapper.build(state));

        assertThat(parsed.enabledExportFieldsByIndex()).isNotNull();
        assertThat(parsed.enabledExportFieldsByIndex()).containsOnlyKeys("traffic");
        assertThat(parsed.enabledExportFieldsByIndex().get("traffic")).containsExactly(trafficField);
    }

    @Test
    void build_and_parse_preserves_exportFields_when_present() throws IOException {
        Map<String, Set<String>> enabledByIndex = Map.of(
                "traffic", Set.of("request.url.raw", "request.url.port", "request.method"),
                "settings", Set.of("burp.project_id")
        );
        var state = new ConfigState.State(
                List.of("settings", "traffic"), "all", List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS, ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                enabledByIndex
        );
        String json = ConfigJsonMapper.build(state);
        assertThat(json).contains("exportFields");
        ConfigState.State parsed = ConfigJsonMapper.parseState(json);
        assertThat(parsed.enabledExportFieldsByIndex()).isNotNull();
        assertThat(parsed.enabledExportFieldsByIndex().get("traffic"))
                .containsExactlyInAnyOrder("request.url.raw", "request.url.port", "request.method");
        assertThat(parsed.enabledExportFieldsByIndex().get("settings")).containsExactly("burp.project_id");
    }

    @Test
    void build_and_parse_preserves_empty_exportFields_selection() throws IOException {
        Map<String, Set<String>> enabledByIndex = Map.of("traffic", Set.of());
        var state = new ConfigState.State(
                List.of("traffic"), "all", List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS, ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                enabledByIndex
        );

        String json = ConfigJsonMapper.build(state);
        ConfigState.State parsed = ConfigJsonMapper.parseState(json);

        assertThat(json).contains("\"traffic\" : [ ]");
        assertThat(parsed.enabledExportFieldsByIndex()).isNotNull();
        assertThat(parsed.enabledExportFieldsByIndex().get("traffic")).isEmpty();
    }

    @Test
    void parse_exportFields_acceptsOnlyCurrentFieldKeys() throws IOException {
        String json = """
            {
              "version":"1.0",
              "dataSources":["settings","traffic","sitemap"],
              "scope":["all"],
              "sinks":{},
              "exportFields":{
                "traffic":["tool","burp.reporting_tool","response.headers.name",
                  "response.mime_type.inferred_body"],
                "settings":["settings_project","project"],
                "sitemap":["status","response.status.code","request.url.raw"]
              }
            }
            """;

        ConfigState.State parsed = ConfigJsonMapper.parseState(json);

        assertThat(parsed.enabledExportFieldsByIndex()).isNotNull();
        assertThat(parsed.enabledExportFieldsByIndex().get("traffic"))
                .containsExactlyInAnyOrder(
                        "burp.reporting_tool",
                        "response.headers.name",
                        "response.mime_type.inferred_body");
        assertThat(parsed.enabledExportFieldsByIndex().get("settings"))
                .containsExactly("project");
        assertThat(parsed.enabledExportFieldsByIndex().get("sitemap"))
                .containsExactlyInAnyOrder("response.status.code", "request.url.raw");
    }

    @Test
    void parse_exportFields_withOnlyUnknownNonEmptySelection_usesDefaults() throws IOException {
        String json = """
            {
              "version":"1.0",
              "dataSources":["traffic"],
              "scope":["all"],
              "sinks":{},
              "exportFields":{
                "traffic":["unknown_field"]
              }
            }
            """;

        ConfigParseResult result = ConfigJsonMapper.parse(json);

        assertThat(result.state().enabledExportFieldsByIndex()).isNull();
        assertThat(result.report().warnings())
                .anyMatch(w -> w.jsonPath().equals("exportFields.traffic")
                        && w.rejectedValue().equals("unknown_field"));
    }

    @Test
    void parse_json_without_exportFields_returns_null_enabledExportFieldsByIndex() throws IOException {
        String json = """
            {"version":"1.0","dataSources":["settings"],"scope":["all"],"sinks":{},"dataSourceOptions":{"settings":["project","user"],"traffic":[],"findings":["critical","high","medium","low","informational"]}}
            """;
        ConfigState.State parsed = ConfigJsonMapper.parseState(json);
        assertThat(parsed.enabledExportFieldsByIndex()).isNull();
    }

    @Test
    void build_and_parse_preserves_ui_preferences_for_stats_and_log_panel() throws IOException {
        var state = new ConfigState.State(
                List.of("settings"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                null,
                new ConfigState.UiPreferences(
                        2,
                        new ConfigState.LogPanelPreferences("warn", true, "", true, false, false, "", false, true)));

        String json = ConfigJsonMapper.build(state);
        ConfigState.State parsed = ConfigJsonMapper.parseState(json);

        assertThat(json).contains("\"minLevel\" : \"warn\"");
        assertThat(parsed.uiPreferences().statsChartStyle()).isEqualTo(2);
        assertThat(parsed.uiPreferences().logPanel().minLevel()).isEqualTo("warn");
        assertThat(parsed.uiPreferences().logPanel().pauseAutoscroll()).isTrue();
        assertThat(parsed.uiPreferences().logPanel().filterText()).isEmpty();
        assertThat(parsed.uiPreferences().logPanel().filterCase()).isTrue();
        assertThat(parsed.uiPreferences().logPanel().filterRegex()).isFalse();
        assertThat(parsed.uiPreferences().logPanel().filterNegative()).isFalse();
        assertThat(parsed.uiPreferences().logPanel().searchText()).isEmpty();
        assertThat(parsed.uiPreferences().logPanel().searchCase()).isFalse();
        assertThat(parsed.uiPreferences().logPanel().searchRegex()).isTrue();
    }

    @Test
    void build_and_parse_preserves_log_panel_filterNegative() throws IOException {
        var state = new ConfigState.State(
                List.of("settings"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null,
                new ConfigState.UiPreferences(
                        ConfigState.DEFAULT_STATS_CHART_STYLE,
                        new ConfigState.LogPanelPreferences(
                                "info", false, "", false, false, true, "", false, false)));

        String json = ConfigJsonMapper.build(state);
        ConfigState.State parsed = ConfigJsonMapper.parseState(json);

        assertThat(json).contains("\"filterNegative\" : true");
        assertThat(parsed.uiPreferences().logPanel().filterNegative()).isTrue();
    }
}
