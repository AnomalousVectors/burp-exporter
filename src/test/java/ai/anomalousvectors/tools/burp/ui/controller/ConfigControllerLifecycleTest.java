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

import ai.anomalousvectors.tools.burp.utils.WholeFileSave;
import ai.anomalousvectors.tools.burp.utils.config.ConfigImportReport;
import ai.anomalousvectors.tools.burp.utils.config.ConfigParseResult;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.search.SearchConnectionStatus;

class ConfigControllerLifecycleTest {

    @Test
    void testConnection_newerCompletionOwnsStatusWhenOlderProbeFinishesLast() throws Exception {
        TestUi ui = new TestUi();
        CountDownLatch firstStarted = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        CountDownLatch firstFinished = new CountDownLatch(1);
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
                        firstFinished.countDown();
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
            assertThat(firstFinished.await(2, TimeUnit.SECONDS)).isTrue();
            flushEdt();

            assertThat(ui.databaseStatus).contains("second");
            assertThat(ui.databaseUpdates).containsExactly(ui.databaseStatus);
        } finally {
            releaseFirst.countDown();
            controller.close();
        }
    }

    @Test
    void import_newerCompletionOwnsStateWhenOlderReadFinishesLast() throws Exception {
        TestUi ui = new TestUi();
        ConfigState.State firstState = mock(ConfigState.State.class);
        ConfigState.State secondState = mock(ConfigState.State.class);
        CountDownLatch firstStarted = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        CountDownLatch firstFinished = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(3);
        ConfigController controller = new ConfigController(
                ui,
                executor,
                path -> {
                    if (path.getFileName().toString().startsWith("first")) {
                        firstStarted.countDown();
                        awaitIgnoringInterrupt(releaseFirst);
                        firstFinished.countDown();
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
            assertThat(firstFinished.await(2, TimeUnit.SECONDS)).isTrue();
            flushEdt();

            assertThat(ui.importedStates).containsExactly(secondState);
            assertThat(ui.controlStatus).contains("second.json");
        } finally {
            releaseFirst.countDown();
            controller.close();
        }
    }

    @Test
    void close_fencesCompletionFromTransportThatIgnoresInterruption() throws Exception {
        TestUi ui = new TestUi();
        CountDownLatch probeStarted = new CountDownLatch(1);
        CountDownLatch releaseProbe = new CountDownLatch(1);
        CountDownLatch probeFinished = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(3);
        ConfigController controller = new ConfigController(
                ui,
                executor,
                path -> emptyImport(mock(ConfigState.State.class)),
                (path, json, replacement) -> { },
                (destination, url) -> {
                    probeStarted.countDown();
                    awaitIgnoringInterrupt(releaseProbe);
                    probeFinished.countDown();
                    return connectionStatus("after-close");
                });

        controller.testConnectionAsync(ConfigState.SearchDestination.OPEN_SEARCH, "https://example.com");
        assertThat(probeStarted.await(2, TimeUnit.SECONDS)).isTrue();
        controller.close();
        releaseProbe.countDown();
        assertThat(probeFinished.await(2, TimeUnit.SECONDS)).isTrue();
        flushEdt();

        assertThat(ui.databaseUpdates).isEmpty();
    }

    @Test
    void export_completionDoesNotOverwriteNewerImportStatus() throws Exception {
        TestUi ui = new TestUi();
        ConfigState.State importedState = mock(ConfigState.State.class);
        CountDownLatch exportStarted = new CountDownLatch(1);
        CountDownLatch releaseExport = new CountDownLatch(1);
        CountDownLatch exportFinished = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(3);
        ConfigController controller = new ConfigController(
                ui,
                executor,
                path -> emptyImport(importedState),
                (path, json, replacement) -> {
                    exportStarted.countDown();
                    awaitIgnoringInterrupt(releaseExport);
                    exportFinished.countDown();
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
            assertThat(exportFinished.await(2, TimeUnit.SECONDS)).isTrue();
            flushEdt();

            assertThat(ui.controlStatus).contains("newer.json");
        } finally {
            releaseExport.countDown();
            controller.close();
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

    private static void flushEdt() throws Exception {
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
