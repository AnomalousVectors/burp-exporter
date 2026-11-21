package ai.anomalousvectors.tools.burp.utils.search;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

class IndexingRetryCoordinatorRuntimeConfigTest {

    @Test
    void resolveBaseUrlForOperation_prefersLiveRuntimeValue_andTracksUpdates() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(stateWithUrl("https://runtime-a.example:9200"));
            assertThat(IndexingRetryCoordinator.resolveBaseUrlForOperation("https://fallback.example:9200"))
                    .isEqualTo("https://runtime-a.example:9200");

            RuntimeConfig.updateState(stateWithUrl("https://runtime-b.example:9200"));
            assertThat(IndexingRetryCoordinator.resolveBaseUrlForOperation("https://fallback.example:9200"))
                    .isEqualTo("https://runtime-b.example:9200");
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void resolveBaseUrlForOperation_fallsBackWhenRuntimeValueBlank() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(stateWithUrl("   "));
            assertThat(IndexingRetryCoordinator.resolveBaseUrlForOperation("https://fallback.example:9200"))
                    .isEqualTo("https://fallback.example:9200");
            assertThat(IndexingRetryCoordinator.resolveBaseUrlForOperation(null)).isEmpty();
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    private static ConfigState.State stateWithUrl(String url) {
        return new ConfigState.State(
                List.of(),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, "", true, url, "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);
    }
}
