package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

class OpenSearchPushCancellationTest {

    @AfterEach
    public void resetRuntime() {
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStarting(false);
    }

    @Test
    void isBenignShutdownCause_recognizesInterruptedAndConnectorShutdownMessages() {
        assertThat(OpenSearchPushCancellation.isBenignShutdownCause(
                new InterruptedException("thread waiting for the response was interrupted"))).isTrue();
        assertThat(OpenSearchPushCancellation.isBenignShutdownCause(
                new IOException("I/O reactor has been shut down"))).isTrue();
        assertThat(OpenSearchPushCancellation.isBenignShutdownCause(
                new IOException("Connection is closed"))).isTrue();
    }

    @Test
    void shouldSuppressFailureAccounting_whenExportStopped() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        RuntimeConfig.setExportRunning(false);

        assertThat(OpenSearchPushCancellation.shouldSuppressFailureAccounting()).isTrue();
        assertThat(OpenSearchPushCancellation.shouldSuppressPushFailure(
                new IOException("Connection is closed"))).isTrue();
        assertThat(OpenSearchPushCancellation.shouldSuppressPushFailure(
                new IOException("burp-exporter-hosted-test.us-east-1.es.amazonaws.com:443 failed to respond")))
                .isFalse();
        assertThat(OpenSearchPushCancellation.cancelledPushLogSuffix(
                new IOException("target server failed to respond")))
                .contains("failed to respond");
    }
}
