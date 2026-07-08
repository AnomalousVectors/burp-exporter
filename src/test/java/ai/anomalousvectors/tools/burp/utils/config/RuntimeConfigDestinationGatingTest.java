package ai.anomalousvectors.tools.burp.utils.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

class RuntimeConfigDestinationGatingTest {

    private final ConfigState.State previous = RuntimeConfig.getState();

    private void restoreRuntimeState() {
        RuntimeConfig.updateState(previous);
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStarting(false);
    }

    @Test
    void openSearchUrl_returnsBlank_whenDestinationDisabledEvenIfUrlIsSaved() {
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, "/path/to/directory", false, true,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));

            assertThat(RuntimeConfig.isAnyFileExportEnabled()).isTrue();
            assertThat(RuntimeConfig.isAnySinkEnabled()).isTrue();
            assertThat(RuntimeConfig.isOpenSearchExportEnabled()).isFalse();
            assertThat(RuntimeConfig.openSearchUrl()).isEmpty();
        } finally {
            restoreRuntimeState();
        }
    }

    @Test
    void isOpenSearchTrafficEnabled_isFalse_whenOnlyFileTrafficExportIsConfigured() {
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, "/path/to/directory", false, true,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    List.of("proxy"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));

            assertThat(RuntimeConfig.isAnyTrafficExportEnabled()).isTrue();
            assertThat(RuntimeConfig.isOpenSearchTrafficEnabled()).isFalse();
        } finally {
            restoreRuntimeState();
        }
    }

    @Test
    void trafficExportGate_tracksRunningStateAndToolSelection() {
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, "/path/to/directory", false, true,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    List.of("repeater"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));

            RuntimeConfig.TrafficExportGate stoppedGate = RuntimeConfig.trafficExportGate();
            assertThat(stoppedGate.anyTrafficExportEnabled()).isTrue();
            assertThat(stoppedGate.allowsToolType("repeater")).isFalse();

            RuntimeConfig.setExportRunning(true);
            RuntimeConfig.TrafficExportGate runningGate = RuntimeConfig.trafficExportGate();
            assertThat(runningGate.allowsToolType("repeater")).isTrue();
            assertThat(runningGate.allowsToolType("proxy")).isFalse();

            RuntimeConfig.setExportStarting(true);
            RuntimeConfig.TrafficExportGate startingGate = RuntimeConfig.trafficExportGate();
            assertThat(startingGate.includesToolType("repeater")).isTrue();
            assertThat(startingGate.allowsToolType("repeater")).isFalse();
            RuntimeConfig.setExportStarting(false);

            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, "/path/to/directory", false, true,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    List.of("intruder"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));
            RuntimeConfig.TrafficExportGate updatedGate = RuntimeConfig.trafficExportGate();
            assertThat(updatedGate.allowsToolType("repeater")).isFalse();
            assertThat(updatedGate.allowsToolType("intruder")).isTrue();
        } finally {
            restoreRuntimeState();
        }
    }

    @Test
    void isOpenSearchExportEnabled_isTrue_whenDestinationAndUrlAreConfigured() {
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(false, "", true, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));

            assertThat(RuntimeConfig.isOpenSearchExportEnabled()).isTrue();
            assertThat(RuntimeConfig.openSearchUrl()).isEqualTo("https://opensearch.url:9200");
        } finally {
            restoreRuntimeState();
        }
    }

    @Test
    void searchExportEnabled_supportsElasticsearchDestination() {
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(false, "", false, true,
                            true, ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                            true, ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                            true, "https://opensearch.url:9200", "", "",
                            ConfigState.OPEN_SEARCH_TLS_VERIFY,
                            ConfigState.defaultOpenSearchOptions(),
                            ConfigState.SearchDestination.ELASTICSEARCH.configKey(),
                            "https://opensearch.url:9200",
                            ConfigState.defaultOpenSearchAmazonOptions(),
                            "http://localhost:9201",
                            ConfigState.defaultElasticsearchOptions()),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));

            assertThat(RuntimeConfig.searchDestinationKind()).isEqualTo(ConfigState.SearchDestination.ELASTICSEARCH);
            assertThat(RuntimeConfig.isSearchExportEnabled()).isTrue();
            assertThat(RuntimeConfig.isOpenSearchExportEnabled()).isTrue();
            assertThat(RuntimeConfig.searchBaseUrl()).isEqualTo("http://localhost:9201");
            assertThat(RuntimeConfig.openSearchUrl()).isEqualTo("http://localhost:9201");
            assertThat(RuntimeConfig.activeSinkSummary()).isEqualTo("Elasticsearch");
        } finally {
            restoreRuntimeState();
        }
    }

    @Test
    void searchExportEnabled_keepsAmazonOpenSearchUnwiredForNow() {
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(false, "", false, true,
                            true, ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                            true, ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                            true, "https://opensearch.url:9200", "", "",
                            ConfigState.OPEN_SEARCH_TLS_VERIFY,
                            ConfigState.defaultOpenSearchOptions(),
                            ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey(),
                            "https://amazon-opensearch.example:443",
                            ConfigState.defaultOpenSearchAmazonOptions(),
                            "http://localhost:9201",
                            ConfigState.defaultElasticsearchOptions()),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));

            assertThat(RuntimeConfig.searchDestinationKind())
                    .isEqualTo(ConfigState.SearchDestination.OPEN_SEARCH_AMAZON);
            assertThat(RuntimeConfig.isSearchDestinationExportWired(RuntimeConfig.searchDestinationKind())).isFalse();
            assertThat(RuntimeConfig.isSearchExportEnabled()).isFalse();
            assertThat(RuntimeConfig.searchBaseUrl()).isEmpty();
        } finally {
            restoreRuntimeState();
        }
    }

    @Test
    void activeSinkSummary_reportsEnabledDestinations() {
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, "/path/to/directory", false, true,
                            true, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));
            assertThat(RuntimeConfig.activeSinkSummary()).isEqualTo("Files and OpenSearch");

            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, "/path/to/directory", false, true,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));
            assertThat(RuntimeConfig.activeSinkSummary()).isEqualTo("Files");

            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(false, "", true, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));
            assertThat(RuntimeConfig.activeSinkSummary()).isEqualTo("OpenSearch");
        } finally {
            restoreRuntimeState();
        }
    }

    @Test
    void disableOpenSearchDestination_staysStickyUntilExportStops() {
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, "/path/to/directory", false, true,
                            true, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));
            RuntimeConfig.setExportRunning(true);
            RuntimeConfig.setExportStarting(false);

            assertThat(RuntimeConfig.disableOpenSearchDestination()).isTrue();
            assertThat(RuntimeConfig.isOpenSearchExportEnabled()).isFalse();
            assertThat(RuntimeConfig.isOpenSearchDisabledForCurrentRun()).isTrue();
            assertThat(RuntimeConfig.activeSinkSummary()).isEqualTo("Files");

            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, "/path/to/directory", false, true,
                            true, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));

            assertThat(RuntimeConfig.isOpenSearchExportEnabled()).isFalse();
            assertThat(RuntimeConfig.openSearchUrl()).isEmpty();

            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, "/path/to/directory", false, true,
                            true, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));

            assertThat(RuntimeConfig.isOpenSearchDisabledForCurrentRun()).isFalse();
            assertThat(RuntimeConfig.isOpenSearchExportEnabled()).isTrue();
            assertThat(RuntimeConfig.activeSinkSummary()).isEqualTo("Files and OpenSearch");
        } finally {
            restoreRuntimeState();
        }
    }

    @Test
    void prepareIndexNamesForCurrentRun_keepsResolvedNamesStable_untilExportStops() {
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_EXPORTER, ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(false, "", false, false, false, "", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    "${now:yyyyMMdd}-tool-burp",
                    null));
            RuntimeConfig.setExportRunning(true);
            RuntimeConfig.setExportStarting(false);

            assertThat(RuntimeConfig.prepareIndexNamesForCurrentRun().valid()).isTrue();
            String exporterDuringRun = RuntimeConfig.indexNameForKey("exporter");
            String trafficDuringRun = RuntimeConfig.indexNameForKey("traffic");
            Instant resolvedAt = RuntimeConfig.resolvedIndexNamesAt();

            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_EXPORTER, ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(false, "", false, false, false, "", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    "changed-base",
                    null));

            assertThat(RuntimeConfig.indexNameForKey("exporter")).isEqualTo(exporterDuringRun);
            assertThat(RuntimeConfig.indexNameForKey("traffic")).isEqualTo(trafficDuringRun);
            assertThat(RuntimeConfig.resolvedIndexNamesAt()).isEqualTo(resolvedAt);

            RuntimeConfig.setExportRunning(false);
            assertThat(RuntimeConfig.indexNameForKey("exporter")).isEqualTo("changed-base-exporter");
            assertThat(RuntimeConfig.indexNameForKey("traffic")).isEqualTo("changed-base-traffic");
        } finally {
            restoreRuntimeState();
        }
    }
}
