package ai.anomalousvectors.tools.burp.utils.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

class ExportFieldFilterTest {

    @Test
    void omissionLeavesPreserveEvidenceWithoutCreatingEmptySparseContainers() {
        ConfigState.State original = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(new ConfigState.State(List.of("traffic", "findings"), "all",
                    List.of(), null, ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES, ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    Map.of("traffic", Set.of(), "findings", Set.of())));
            Map<String, Object> emptyResponse = new LinkedHashMap<>();
            emptyResponse.put("response", null);
            emptyResponse.put("meta", Map.of("schema_version", "1"));
            assertThat(ExportFieldFilter.filterDocument(emptyResponse, "traffic")).containsOnlyKeys("meta");
            Map<String, Object> finding = new LinkedHashMap<>();
            finding.put("requests_responses", List.of());
            finding.put("collaborator", List.of());
            finding.put("meta", Map.of("schema_version", "1"));
            assertThat(ExportFieldFilter.filterDocument(finding, "findings")).containsOnlyKeys("meta");
            Map<String, Object> policy = Map.of("omitted", true, "omission_reason", "video_response_body_disabled");
            finding.put("requests_responses", List.of(Map.of("response", Map.of("body", policy))));
            assertThat(ExportFieldFilter.filterDocument(finding, "findings"))
                    .containsEntry("requests_responses", finding.get("requests_responses"))
                    .doesNotContainKey("collaborator");
        } finally {
            RuntimeConfig.updateState(original);
        }
    }

    @Test
    void filterDocument_copiesEnabledNestedFields_withoutWholeParent() {
        ConfigState.State original = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    null,
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    Map.of("settings", Set.of("burp.project_id", "project"))
            ));

            Map<String, Object> document = new LinkedHashMap<>();
            document.put("burp", Map.of("project_id", "project-1", "version", "2026.4"));
            document.put("meta", Map.of("schema_version", "1"));
            document.put("project", Map.of("project_options", Map.of("test_key", "project_value")));
            document.put("user", Map.of("user_options", Map.of("test_key", "user_value")));

            Map<String, Object> filtered = ExportFieldFilter.filterDocument(document, "settings");

            assertThat(filtered).containsKeys("burp", "meta", "project");
            assertThat(filtered.get("burp")).isEqualTo(Map.of("project_id", "project-1"));
            assertThat(filtered).doesNotContainKey("user");
        } finally {
            RuntimeConfig.updateState(original);
        }
    }

    @Test
    void filterDocument_emptyEnabledSetMeansNoOptionalFields() {
        ConfigState.State original = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    null,
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    Map.of("settings", Set.of())
            ));

            Map<String, Object> document = new LinkedHashMap<>();
            document.put("burp", Map.of("project_id", "project-1"));
            document.put("meta", Map.of("schema_version", "1"));
            document.put("project", Map.of("project_options", Map.of("test_key", "project_value")));

            Map<String, Object> filtered = ExportFieldFilter.filterDocument(document, "settings");

            assertThat(filtered).containsOnlyKeys("meta");
        } finally {
            RuntimeConfig.updateState(original);
        }
    }
}
