package ai.anomalousvectors.tools.burp.ui;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

class ExportStartupStatusTest {

    @Test
    void initialStartingMessage_filesOnly() {
        ExportStartupStatus.Snapshot snapshot = new ExportStartupStatus.Snapshot(true, false);

        assertThat(ExportStartupStatus.initialStartingMessage(snapshot))
                .isEqualTo("Starting: preparing Files export …");
    }

    @Test
    void initialStartingMessage_bothDestinations() {
        ExportStartupStatus.Snapshot snapshot = new ExportStartupStatus.Snapshot(true, true);

        assertThat(ExportStartupStatus.initialStartingMessage(snapshot))
                .isEqualTo("Starting: preparing Files and OpenSearch export …");
    }

    @Test
    void initialStartingMessage_usesSelectedDatabaseDestination() {
        ConfigState.State previous = RuntimeConfig.getState();
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
                            "",
                            ConfigState.defaultOpenSearchAmazonOptions(),
                            "http://localhost:9201",
                            ConfigState.defaultElasticsearchOptions()),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));

            ExportStartupStatus.Snapshot snapshot = new ExportStartupStatus.Snapshot(true, true);

            assertThat(ExportStartupStatus.initialStartingMessage(snapshot))
                    .isEqualTo("Starting: preparing Files and Elasticsearch export …");
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void initializingFilesMessage_usesStartingPrefix() {
        assertThat(ExportStartupStatus.initializingFilesMessage())
                .isEqualTo("Starting: initializing file export …");
    }

    @Test
    void creatingOpenSearchIndexesMessage_usesStartingPrefix() {
        assertThat(ExportStartupStatus.creatingOpenSearchIndexesMessage())
                .isEqualTo("Starting: creating OpenSearch indexes …");
    }
}
