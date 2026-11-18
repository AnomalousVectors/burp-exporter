package ai.anomalousvectors.tools.burp.utils.config;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ExportFieldRegistry}: Fields panel order, toggleable/required lists, and allowed-keys logic.
 */
class ExportFieldRegistryTest {

    @Test
    void index_order_for_fields_panel_includes_tool_and_matches_config_sources_order() {
        assertThat(ExportFieldRegistry.INDEX_ORDER_FOR_FIELDS_PANEL)
                .containsExactly("settings", "sitemap", "findings", "traffic", "exporter");
    }

    @Test
    void get_toggleable_fields_returns_non_empty_for_each_fields_panel_index() {
        for (String index : ExportFieldRegistry.INDEX_ORDER_FOR_FIELDS_PANEL) {
            assertThat(ExportFieldRegistry.getToggleableFields(index))
                    .as("toggleable for " + index)
                    .isNotEmpty();
        }
    }

    @Test
    void exporter_event_fields_are_toggleable_as_nested_leaf_fields() {
        assertThat(ExportFieldRegistry.getToggleableFields("exporter"))
                .contains("event.data", "event.level", "event.source", "event.summary", "event.thread", "event.type")
                .doesNotContain("event", "message", "message.data", "message.summary", "message_text");
    }

    @Test
    void settings_burp_fields_are_toggleable_as_nested_leaf_fields() {
        assertThat(ExportFieldRegistry.getToggleableFields("settings"))
                .contains("burp.project_id", "burp.version")
                .doesNotContain("project_id", "burp");
    }

    @Test
    void traffic_shows_burp_leaf_fields_not_burp_directory() {
        assertThat(ExportFieldRegistry.getToggleableFields("traffic"))
                .contains("burp.reporting_tool", "burp.is_in_scope")
                .doesNotContain("burp", "request", "response", "protocol", "websocket", "meta");
    }

    @Test
    void get_allowed_keys_does_not_include_nested_parent_when_descendant_enabled() {
        Set<String> allowed = ExportFieldRegistry.getAllowedKeys(
                "findings", Set.of("requests_responses.request.method"));
        assertThat(allowed).contains("requests_responses.request.method")
                .doesNotContain("requests_responses");
    }

    @Test
    void exporter_does_not_include_burp_context_fields() {
        assertThat(ExportFieldRegistry.getToggleableFields("exporter"))
                .doesNotContain("burp.project_id", "burp.version", "project_id", "burp_version");
    }

    @Test
    void meta_leaf_paths_are_required_display_fields_for_every_index() {
        for (String index : ExportFieldRegistry.INDEX_ORDER_FOR_FIELDS_PANEL) {
            assertThat(ExportFieldRegistry.getRequiredDisplayFields(index))
                    .containsAll(ExportFieldRegistry.META_LEAF_PATHS);
            if ("traffic".equals(index)) {
                assertThat(ExportFieldRegistry.getRequiredDisplayFields(index))
                        .containsAll(ExportFieldRegistry.TRAFFIC_CAPTURE_LEAF_PATHS);
            } else if ("settings".equals(index) || "exporter".equals(index)) {
                assertThat(ExportFieldRegistry.getRequiredDisplayFields(index))
                        .containsExactlyElementsOf(ExportFieldRegistry.META_LEAF_PATHS);
            }
        }
    }

    @Test
    void omissionSemanticsAreRequiredAndCannotBeHiddenByOptionalFieldSelection() {
        for (String index : List.of("traffic", "sitemap")) {
            assertThat(ExportFieldRegistry.getRequiredDisplayFields(index))
                    .contains("response.body.omitted", "response.body.omission_reason");
            assertThat(ExportFieldRegistry.getAllowedKeys(index, Set.of()))
                    .contains("response.body.omitted", "response.body.omission_reason");
            assertThat(ExportFieldRegistry.getToggleableFields(index))
                    .doesNotContain("response.body.omitted", "response.body.omission_reason");
        }
        assertThat(ExportFieldRegistry.getAllowedKeys("findings", Set.of()))
                .contains("requests_responses.response.body.omitted", "collaborator.http.response.body.omission_reason");
    }

    @Test
    void is_meta_leaf_path_matches_meta_prefix_only() {
        assertThat(ExportFieldRegistry.isMetaLeafPath("meta.schema_version")).isTrue();
        assertThat(ExportFieldRegistry.isMetaLeafPath("meta")).isFalse();
        assertThat(ExportFieldRegistry.isMetaLeafPath("burp.reporting_tool")).isFalse();
    }

    @Test
    void get_allowed_keys_with_null_enabled_returns_system_meta_plus_all_toggleable() {
        String index = "traffic";
        Set<String> allowed = ExportFieldRegistry.getAllowedKeys(index, null);
        assertThat(allowed).contains("meta");
        assertThat(allowed).containsAll(ExportFieldRegistry.getToggleableFields(index));
    }

    @Test
    void compactEnabledFieldsForExport_null_whenGloballyAllOn() {
        Map<String, Set<String>> full = new LinkedHashMap<>();
        for (String index : ExportFieldRegistry.INDEX_ORDER) {
            full.put(index, Set.copyOf(ExportFieldRegistry.getToggleableFields(index)));
        }
        assertThat(ExportFieldRegistry.compactEnabledFieldsForExport(full)).isNull();
        assertThat(ExportFieldRegistry.compactEnabledFieldsForExport(null)).isNull();
    }

    @Test
    void compactEnabledFieldsForExport_keepsOnlyIndexesWithPartialOrEmptySelection() {
        String index = "traffic";
        List<String> toggleable = ExportFieldRegistry.getToggleableFields(index);
        assertThat(toggleable).isNotEmpty();

        Map<String, Set<String>> partialOnly = Map.of(index, Set.of(toggleable.getFirst()));
        Map<String, Set<String>> compacted = ExportFieldRegistry.compactEnabledFieldsForExport(partialOnly);

        assertThat(compacted).containsOnlyKeys(index);
        assertThat(compacted.get(index)).containsExactly(toggleable.getFirst());

        Map<String, Set<String>> fat = new LinkedHashMap<>();
        fat.put(index, Set.of(toggleable.getFirst()));
        fat.put("settings", Set.copyOf(ExportFieldRegistry.getToggleableFields("settings")));
        assertThat(ExportFieldRegistry.compactEnabledFieldsForExport(fat)).containsOnlyKeys(index);
    }

    @Test
    void compactEnabledFieldsForExport_preservesExplicitEmptyIndex() {
        Map<String, Set<String>> compacted =
                ExportFieldRegistry.compactEnabledFieldsForExport(Map.of("traffic", Set.of()));
        assertThat(compacted).containsEntry("traffic", Set.of());
    }

    @Test
    void get_allowed_keys_with_partial_enabled_returns_system_meta_plus_only_those_toggleable() {
        String index = "settings";
        Set<String> enabledToggleable = Set.of("burp.project_id");
        Set<String> allowed = ExportFieldRegistry.getAllowedKeys(index, enabledToggleable);
        assertThat(allowed).contains("meta");
        assertThat(allowed).contains("burp.project_id");
        assertThat(allowed).doesNotContain("project").doesNotContain("user");
    }
}
