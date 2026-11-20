package ai.anomalousvectors.tools.burp.utils.config;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JsonKeyOrderTest {

    private static final ObjectMapper M = JsonMapper.builderWithJackson2Defaults().build();

    @Test
    void top_level_keys_are_in_deterministic_order() throws Exception {
        var state = new ConfigState.State(
                List.of("settings", "sitemap"),
                "custom",
                List.of(
                        new ConfigState.ScopeEntry("^foo$", ConfigState.Kind.REGEX),
                        new ConfigState.ScopeEntry("aaa",   ConfigState.Kind.STRING),
                        new ConfigState.ScopeEntry("bar.*", ConfigState.Kind.REGEX)
                ),
                new ConfigState.Sinks(true, "/path/to/directory", true, "https://opensearch.url:9200", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        );

        String json = ConfigJsonMapper.build(state);

        JsonNode root = M.readTree(json);
        List<String> keys = new ArrayList<>();
        root.propertyNames().iterator().forEachRemaining(keys::add);

        assertThat(keys).containsExactly("version", "dataSources", "scope", "sinks", "indexNames", "ui");
    }

    @Test
    void custom_scope_preserves_insertion_order_of_typed_entries() throws Exception {
        var state = new ConfigState.State(
                List.of("settings"),
                "custom",
                List.of(
                        new ConfigState.ScopeEntry("^foo$", ConfigState.Kind.REGEX),
                        new ConfigState.ScopeEntry("aaa",   ConfigState.Kind.STRING),
                        new ConfigState.ScopeEntry("bar.*", ConfigState.Kind.REGEX)
                ),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        );

        String json = ConfigJsonMapper.build(state);

        JsonNode custom = M.readTree(json).path("scope").path("custom");
        List<String> keys = new ArrayList<>();
        custom.propertyNames().iterator().forEachRemaining(keys::add);

        // Keys reflect insertion order with counters applied at build time.
        assertThat(keys).containsExactly("regex1", "string1", "regex2");
    }
}
