package ai.anomalousvectors.tools.burp.utils.opensearch;

import ai.anomalousvectors.tools.burp.testutils.OpenSearchTestConfig;
import ai.anomalousvectors.tools.burp.testutils.Reflect;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.SecureCredentialStore;
import ai.anomalousvectors.tools.burp.utils.Logger;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;

import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that {@link OpenSearchClientWrapper#testConnection(String)} emits log events
 * to the {@link Logger} listener bus so {@code LogPanel} can display connection attempts.
 * For client-side failures (no HTTP exchanged), only the error is logged — no reconstructed request/response.
 */
class OpenSearchClientWrapperLoggingTest {

    private final List<LoggerEvent> events = new CopyOnWriteArrayList<>();
    private final CountDownLatch latch = new CountDownLatch(1);
    private final Logger.LogListener listener = (level, message) -> {
        events.add(new LoggerEvent(level, message));
        latch.countDown();
    };

    private void cleanUp() {
        Logger.unregisterListener(listener);
        Logger.resetState();
        SecureCredentialStore.clearAll();
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStarting(false);
        RuntimeConfig.setExportStopping(false);
        IndexingRetryCoordinator.getInstance().stopDrainThread();
        IndexingRetryCoordinator.getInstance().clearPendingWork();
        RuntimeConfig.updateState(null);
        events.clear();
        while (latch.getCount() > 0) {
            latch.countDown();
        }
    }

    @Test
    void testConnection_withInvalidUrl_emitsLogEvent() throws Exception {
        Logger.resetState();
        Logger.registerListener(listener);
        try {
            // Run on EDT so Logger listener is invoked synchronously (Logger dispatches to EDT when off it).
            SwingUtilities.invokeAndWait(() ->
                    OpenSearchClientWrapper.testConnection("http://127.0.0.1:1"));

            // Client-side failure (connection refused): we log the error only, no fake request/response.
            assertThat(events)
                    .anySatisfy(e -> {
                        assertThat(e.level()).isNotEmpty();
                        assertThat(e.message()).contains("[OpenSearch]").contains("Connection failed");
                    });
            assertThat(events).noneMatch(e -> e.message().contains("Request:"));
        } finally {
            cleanUp();
        }
    }

    @Test
    void logPushOutcome_whenExportStopped_benignShutdown_emitsTraceWithCause() throws Exception {
        Logger.resetState();
        Logger.registerListener(listener);
        RuntimeConfig.setExportRunning(false);
        try {
            invokeLogPushOutcomeOnEdt(
                    "tool-burp-traffic",
                    "doPushBulk",
                    new IOException("Connection is closed"));

            assertThat(events).anySatisfy(e -> {
                assertThat(e.level()).isEqualTo("TRACE");
                assertThat(e.message())
                        .contains("[OpenSearch]")
                        .contains("doPushBulk cancelled")
                        .contains("Connection is closed");
            });
            assertThat(events).noneMatch(e -> e.message().contains("failed for"));
        } finally {
            cleanUp();
        }
    }

    @Test
    void logPushOutcome_whenExportStopped_realTransportFailure_emitsWarnWithCause() throws Exception {
        Logger.resetState();
        Logger.registerListener(listener);
        RuntimeConfig.setExportRunning(false);
        try {
            invokeLogPushOutcomeOnEdt(
                    "tool-burp-traffic",
                    "doPushBulk",
                    new IOException("target server failed to respond"));

            assertThat(events).anySatisfy(e -> {
                assertThat(e.level()).isEqualTo("WARN");
                assertThat(e.message())
                        .contains("[OpenSearch]")
                        .contains("doPushBulk failed")
                        .contains("failed to respond");
            });
            assertThat(events).noneMatch(e -> e.message().contains("cancelled"));
        } finally {
            cleanUp();
        }
    }

    @Test
    void logPushOutcome_whenExportRunning_emitsWarnWithOpenSearchPrefix() throws Exception {
        Logger.resetState();
        Logger.registerListener(listener);
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, OpenSearchTestConfig.get().baseUrl(), null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        RuntimeConfig.setExportRunning(true);
        try {
            invokeLogPushOutcomeOnEdt(
                    "tool-burp-traffic",
                    "doPushDocument",
                    new IOException("mapper parsing exception"));

            assertThat(events).anySatisfy(e -> {
                assertThat(e.level()).isEqualTo("WARN");
                assertThat(e.message())
                        .contains("[OpenSearch]")
                        .contains("doPushDocument failed")
                        .contains("mapper parsing exception");
            });
            assertThat(events).noneMatch(e -> e.message().contains("cancelled"));
        } finally {
            cleanUp();
        }
    }

    /**
     * Invokes {@code logPushOutcome} on the EDT so {@link Logger} listener delivery is synchronous.
     */
    private void invokeLogPushOutcomeOnEdt(String indexName, String operation, Exception failure) throws Exception {
        SwingUtilities.invokeAndWait(() -> Reflect.callStatic(
                OpenSearchClientWrapper.class,
                "logPushOutcome",
                indexName,
                operation,
                failure));
    }

    @Test
    void testConnection_withPinnedModeButNoImportedCertificate_emitsTlsLogEvents() throws Exception {
        String originalInsecure = System.getProperty("OPENSEARCH_INSECURE");
        Logger.resetState();
        SecureCredentialStore.clearAll();
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, "", false, false,
                        true, ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                        true, ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                        true, OpenSearchTestConfig.get().baseUrl(), "", "", ConfigState.OPEN_SEARCH_TLS_PINNED),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        ));
        System.clearProperty("OPENSEARCH_INSECURE");
        Logger.registerListener(listener);
        try {
            SwingUtilities.invokeAndWait(() ->
                    OpenSearchClientWrapper.testConnection(OpenSearchTestConfig.get().baseUrl()));

            assertThat(events).anySatisfy(e -> assertThat(e.message())
                    .contains("Testing connection: url=" + OpenSearchTestConfig.get().baseUrl())
                    .contains("tlsMode=pinned")
                    .contains("pinnedCertificateLoaded=false"));
            assertThat(events).anySatisfy(e -> assertThat(e.message())
                    .contains("TLS mode requires a pinned certificate, but none is imported"));
            assertThat(events).anySatisfy(e -> assertThat(e.message())
                    .contains("Connection failed for " + OpenSearchTestConfig.get().baseUrl())
                    .contains("trust=Pinned certificate not imported"));
        } finally {
            if (originalInsecure == null) {
                System.clearProperty("OPENSEARCH_INSECURE");
            } else {
                System.setProperty("OPENSEARCH_INSECURE", originalInsecure);
            }
            cleanUp();
        }
    }

    private record LoggerEvent(String level, String message) {
        LoggerEvent {
            level = level == null ? "" : level;
            message = message == null ? "" : message;
        }
    }
}
