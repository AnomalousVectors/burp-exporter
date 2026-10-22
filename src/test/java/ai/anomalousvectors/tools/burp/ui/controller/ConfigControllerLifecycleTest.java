package ai.anomalousvectors.tools.burp.ui.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.WholeFileSave;
import ai.anomalousvectors.tools.burp.utils.config.ConfigImportReport;
import ai.anomalousvectors.tools.burp.utils.config.ConfigParseResult;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.search.SearchConnectionStatus;

class ConfigControllerLifecycleTest {

    @ParameterizedTest
    @EnumSource(ConfigState.SearchDestination.class)
    void testConnection_successLogsOneLine_withoutChangingPanelStatus(
            ConfigState.SearchDestination destination) throws Exception {
        SearchConnectionStatus result = new SearchConnectionStatus(
                destination.displayName(), true, "", "3.7.0", "Connection successful",
                "Success", "Successful", "Verified");
        assertConnectionResult(
                destination,
                (selected, url) -> result,
                result.formattedStatus(),
                "INFO",
                "Connection: Success; Authentication: Successful; Trust: Verified; "
                        + destination.displayName() + " version: 3.7.0; Details: Connection successful");
    }

    @ParameterizedTest
    @EnumSource(ConfigState.SearchDestination.class)
    void testConnection_authFailureKeepsHintOnOneLogLine_withoutChangingPanelStatus(
            ConfigState.SearchDestination destination) throws Exception {
        SearchConnectionStatus result = new SearchConnectionStatus(
                destination.displayName(), false, "", "", "HTTP 401 Unauthorized",
                "Failed", "Failed", "Verified");
        assertConnectionResult(
                destination,
                (selected, url) -> result,
                result.formattedStatus(),
                "WARN",
                "Connection: Failed; Authentication: Failed; Trust: Verified; "
                        + destination.displayName() + " version: unknown; Details: HTTP 401 Unauthorized; "
                        + "Hint: Check credentials (bearer/API key/session token may have expired). "
                        + "Update Config, then re-test or Stop and Start.");
    }

    @ParameterizedTest
    @EnumSource(ConfigState.SearchDestination.class)
    void testConnection_thrownProbeNormalizesAllLineBreaksInLogOnly(
            ConfigState.SearchDestination destination) throws Exception {
        String detail = "first\r\nsecond\rthird\nfourth\u2028fifth";
        String panelStatus = "Connection: Failed\nAuthentication: Not tested\nTrust: Not tested\n"
                + destination.displayName() + " version: unknown\nDetails: " + detail;
        assertConnectionResult(
                destination,
                (selected, url) -> { throw new IllegalStateException(detail); },
                panelStatus,
                "WARN",
                "Connection: Failed; Authentication: Not tested; Trust: Not tested; "
                        + destination.displayName() + " version: unknown; Details: first; second; third; fourth; fifth");
    }

    /** Await the owned worker before checking both EDT status and synchronous log publication. */
    private static void assertConnectionResult(
            ConfigState.SearchDestination destination,
            ConfigController.ConnectionProbe probe,
            String panelStatus,
            String level,
            String logStatus) throws Exception {
        TestUi ui = new TestUi();
        ExecutorService executor = Executors.newSingleThreadExecutor();
        ConfigController controller = new ConfigController(
                ui, executor,
                path -> emptyImport(mock(ConfigState.State.class)),
                (path, json, replacement) -> {},
                probe);
        List<String> resultLogs = new CopyOnWriteArrayList<>();
        Logger.LogListener listener = (eventLevel, message) -> {
            if (message.contains("Test connection result")) {
                resultLogs.add(eventLevel + ":" + message);
            }
        };
        try {
            Logger.registerListener(listener);
            controller.testConnectionAsync(destination, "https://opensearch.url:9200");
            awaitWorkerCompletions(executor);

            assertThat(ui.databaseUpdates).containsExactly(panelStatus);
            assertThat(ui.databaseStatus).contains("\n");
            assertThat(resultLogs).containsExactly(
                    level + ":[" + destination.displayName() + "] Test connection result: " + logStatus);
            assertThat(resultLogs.getFirst()).doesNotContain("\r", "\n", "\u0085", "\u2028", "\u2029");
        } finally {
            controller.close();
            try {
                awaitWorkerCompletions(executor);
            } finally {
                Logger.unregisterListener(listener);
            }
        }
    }

    @Test
    void testConnection_newerCompletionOwnsStatusWhenOlderProbeFinishesLast() throws Exception {
        TestUi ui = new TestUi();
        CountDownLatch firstStarted = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(3);
        ConfigController controller = new ConfigController(
                ui,
                executor,
                path -> emptyImport(mock(ConfigState.State.class)),
                (path, json, replacement) -> { },
                (destination, url) -> {
                    if (url.contains("first")) {
                        firstStarted.countDown();
                        awaitIgnoringInterrupt(releaseFirst);
                        return connectionStatus("first");
                    }
                    return connectionStatus("second");
                });
        try {
            controller.testConnectionAsync(ConfigState.SearchDestination.OPEN_SEARCH, "https://first.example");
            assertThat(firstStarted.await(2, TimeUnit.SECONDS)).isTrue();

            controller.testConnectionAsync(ConfigState.SearchDestination.OPEN_SEARCH, "https://second.example");
            assertThat(ui.databaseUpdated.await(2, TimeUnit.SECONDS)).isTrue();
            assertThat(ui.databaseStatus).contains("second");

            releaseFirst.countDown();
            awaitWorkerCompletions(executor);

            assertThat(ui.databaseStatus).contains("second");
            assertThat(ui.databaseUpdates).containsExactly(ui.databaseStatus);
        } finally {
            releaseFirst.countDown();
            controller.close();
            awaitWorkerCompletions(executor);
        }
    }

    @Test
    void import_newerCompletionOwnsStateWhenOlderReadFinishesLast() throws Exception {
        TestUi ui = new TestUi();
        ConfigState.State firstState = mock(ConfigState.State.class);
        ConfigState.State secondState = mock(ConfigState.State.class);
        CountDownLatch firstStarted = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(3);
        ConfigController controller = new ConfigController(
                ui,
                executor,
                path -> {
                    if (path.getFileName().toString().startsWith("first")) {
                        firstStarted.countDown();
                        awaitIgnoringInterrupt(releaseFirst);
                        return emptyImport(firstState);
                    }
                    return emptyImport(secondState);
                },
                (path, json, replacement) -> { },
                (destination, url) -> connectionStatus("unused"));
        try {
            controller.importConfigAsync(Path.of("first.json"));
            assertThat(firstStarted.await(2, TimeUnit.SECONDS)).isTrue();

            controller.importConfigAsync(Path.of("second.json"));
            assertThat(ui.importApplied.await(2, TimeUnit.SECONDS)).isTrue();
            assertThat(ui.importedStates).containsExactly(secondState);

            releaseFirst.countDown();
            awaitWorkerCompletions(executor);

            assertThat(ui.importedStates).containsExactly(secondState);
            assertThat(ui.controlStatus).contains("second.json");
        } finally {
            releaseFirst.countDown();
            controller.close();
            awaitWorkerCompletions(executor);
        }
    }

    @Test
    void close_fencesCompletionFromTransportThatIgnoresInterruption() throws Exception {
        TestUi ui = new TestUi();
        CountDownLatch probeStarted = new CountDownLatch(1);
        CountDownLatch releaseProbe = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(3);
        ConfigController controller = new ConfigController(
                ui,
                executor,
                path -> emptyImport(mock(ConfigState.State.class)),
                (path, json, replacement) -> { },
                (destination, url) -> {
                    probeStarted.countDown();
                    awaitIgnoringInterrupt(releaseProbe);
                    return connectionStatus("after-close");
                });

        try {
            controller.testConnectionAsync(ConfigState.SearchDestination.OPEN_SEARCH, "https://example.com");
            assertThat(probeStarted.await(2, TimeUnit.SECONDS)).isTrue();
            controller.close();
            releaseProbe.countDown();
            awaitWorkerCompletions(executor);

            assertThat(ui.databaseUpdates).isEmpty();
        } finally {
            releaseProbe.countDown();
            controller.close();
            awaitWorkerCompletions(executor);
        }
    }

    @Test
    void export_completionDoesNotOverwriteNewerImportStatus() throws Exception {
        TestUi ui = new TestUi();
        ConfigState.State importedState = mock(ConfigState.State.class);
        CountDownLatch exportStarted = new CountDownLatch(1);
        CountDownLatch releaseExport = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(3);
        ConfigController controller = new ConfigController(
                ui,
                executor,
                path -> emptyImport(importedState),
                (path, json, replacement) -> {
                    exportStarted.countDown();
                    awaitIgnoringInterrupt(releaseExport);
                },
                (destination, url) -> connectionStatus("unused"));
        try {
            controller.exportConfigAsync(
                    Path.of("export.json"),
                    "{}",
                    WholeFileSave.Replacement.CREATE_NEW);
            assertThat(exportStarted.await(2, TimeUnit.SECONDS)).isTrue();

            controller.importConfigAsync(Path.of("newer.json"));
            assertThat(ui.importApplied.await(2, TimeUnit.SECONDS)).isTrue();
            assertThat(ui.controlStatus).contains("newer.json");

            releaseExport.countDown();
            awaitWorkerCompletions(executor);

            assertThat(ui.controlStatus).contains("newer.json");
        } finally {
            releaseExport.countDown();
            controller.close();
            awaitWorkerCompletions(executor);
        }
    }

    private static ConfigParseResult emptyImport(ConfigState.State state) {
        return new ConfigParseResult(state, new ConfigImportReport());
    }

    private static SearchConnectionStatus connectionStatus(String detail) {
        return new SearchConnectionStatus(
                "OpenSearch", true, "", "1.0", detail, "Success", "Not used", "Verified");
    }

    private static void awaitIgnoringInterrupt(CountDownLatch latch) {
        boolean complete = false;
        while (!complete) {
            try {
                complete = latch.await(2, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
                // Simulates a third-party transport that does not honor Future cancellation.
            }
        }
    }

    /** Stub return precedes EDT submission; cancelled Futures also need not mean worker exit. */
    private static void awaitWorkerCompletions(ExecutorService executor) throws Exception {
        // Graceful shutdown lets stale completions reach their real fences before controller.close().
        executor.shutdown();
        assertThat(executor.awaitTermination(2, TimeUnit.SECONDS)).isTrue();
        SwingUtilities.invokeAndWait(() -> { });
    }

    private static final class TestUi implements ConfigController.Ui {
        private final CountDownLatch databaseUpdated = new CountDownLatch(1);
        private final CountDownLatch importApplied = new CountDownLatch(1);
        private final List<String> databaseUpdates = new CopyOnWriteArrayList<>();
        private final List<ConfigState.State> importedStates = new CopyOnWriteArrayList<>();
        private volatile String databaseStatus;
        private volatile String controlStatus;

        @Override
        public void onFileStatus(String message) {
            // File status is outside these controller ordering scenarios.
        }

        @Override
        public void onDatabaseStatus(String message) {
            databaseStatus = message;
            databaseUpdates.add(message);
            databaseUpdated.countDown();
        }

        @Override
        public void onControlStatus(String message) {
            controlStatus = message;
        }

        @Override
        public void onImportResult(ConfigState.State state) {
            importedStates.add(state);
            importApplied.countDown();
        }
    }
}
