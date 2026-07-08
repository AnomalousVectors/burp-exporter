package ai.anomalousvectors.tools.burp.ui;

import static ai.anomalousvectors.tools.burp.testutils.LazySchedulers.peek;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.get;
import static org.assertj.core.api.Assertions.assertThat;

import java.awt.Component;
import java.awt.Container;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.sinks.ExportReporterLifecycle;
import ai.anomalousvectors.tools.burp.sinks.FindingsIndexReporter;
import ai.anomalousvectors.tools.burp.sinks.ProxyWebSocketIndexReporter;
import ai.anomalousvectors.tools.burp.sinks.SettingsIndexReporter;
import ai.anomalousvectors.tools.burp.sinks.SitemapIndexReporter;
import ai.anomalousvectors.tools.burp.sinks.ExporterIndexStatsReporter;
import ai.anomalousvectors.tools.burp.testutils.TestPathSupport;
import ai.anomalousvectors.tools.burp.ui.controller.ConfigController;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

class ConfigPanelStopLifecycleHeadlessTest {

    @Test
    void stopButton_quiescesBackgroundReporters() throws Exception {
        try {
            RuntimeConfig.setExportRunning(true);
            ExporterIndexStatsReporter.start();
            SettingsIndexReporter.start();
            FindingsIndexReporter.start();
            SitemapIndexReporter.start();
            ProxyWebSocketIndexReporter.startLivePoll();

            ConfigPanel panel = newPanelOnEdt();
            JButton stopButton = (JButton) findByName(panel, "control.startStop");
            assertThat(stopButton).isNotNull();

            runEdt(stopButton::doClick);
            waitUntilExportNotRunning();
            waitUntilBackgroundReportersStopped();

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(peek(ExporterIndexStatsReporter.class, "SCHEDULER")).isNull();
            assertThat(peek(SettingsIndexReporter.class, "SCHEDULER")).isNull();
            assertThat(peek(FindingsIndexReporter.class, "SCHEDULER")).isNull();
            assertThat(peek(SitemapIndexReporter.class, "SCHEDULER")).isNull();
            assertThat(peek(ProxyWebSocketIndexReporter.class, "SCHEDULER")).isNull();
        } finally {
            ExportReporterLifecycle.resetForTests();
            ConfigPanel.shutdownStartupExecutor();
        }
    }

    @Test
    void startThenStop_updatesVisibleControlStatusThroughConfigPanelFlow() throws Exception {
        Path exportRoot = TestPathSupport.createDirectory("af-stop-lifecycle-root");
        Path exportRootAbs = exportRoot.toAbsolutePath().normalize();
        List<String> infoMessages = new CopyOnWriteArrayList<>();
        Logger.LogListener listener = (level, message) -> {
            if ("INFO".equals(level)) {
                infoMessages.add(message);
            }
        };
        Logger.registerListener(listener);
        try {
            RuntimeConfig.setExportRunning(false);
            ConfigPanel panel = newPanelOnEdt();
            JButton startStop = (JButton) findByName(panel, "control.startStop");
            JTextArea controlStatus = findByName(panel, "control.status", JTextArea.class);
            JCheckBox filesEnabled = findByName(panel, "files.enable", JCheckBox.class);
            javax.swing.AbstractButton awsDestination =
                    javax.swing.AbstractButton.class.cast(get(panel, "openSearchAmazonDestinationRadio"));
            JTextField filePathField = JTextField.class.cast(get(panel, "filePathField"));
            assertThat(startStop).isNotNull();
            assertThat(controlStatus).isNotNull();

            runEdt(() -> {
                if (!awsDestination.isSelected()) {
                    awsDestination.doClick();
                }
                if (!filesEnabled.isSelected()) {
                    filesEnabled.doClick();
                }
                filePathField.setText(exportRootAbs.toString());
            });

            runEdt(startStop::doClick);
            String expectedRunning = "Files: Running -> " + exportRootAbs;
            waitForControlStatus(controlStatus, expectedRunning);

            assertThat(RuntimeConfig.isExportRunning()).isTrue();
            assertThat(startStop.getText()).isEqualTo("Stop");
            assertThat(controlStatus.getText()).isEqualTo(expectedRunning);

            runEdt(startStop::doClick);
            waitForControlStatus(controlStatus, "Stopped");

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(controlStatus.getText()).isEqualTo("Stopped");
            flushLogListeners();
            assertThat(infoMessages)
                    .contains("[Export] Stopping: waiting for in-flight traffic batch …")
                    .contains("[Export] Stopping: clearing queued traffic …")
                    .contains("[Export] Stopping: pushing final exporter stats …")
                    .contains("[Export] Stopping: closing OpenSearch connections …");
            assertThat(infoMessages)
                    .noneMatch(message -> message.contains("collecting final OpenSearch counts"));
        } finally {
            Logger.unregisterListener(listener);
            TestPathSupport.cleanupExportArtifacts(exportRoot);
            ExportReporterLifecycle.resetForTests();
            ConfigPanel.shutdownStartupExecutor();
        }
    }

    private static ConfigPanel newPanelOnEdt() throws Exception {
        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ConfigPanel panel = new ConfigPanel(new ConfigController(new ConfigController.Ui() {
                @Override public void onFileStatus(String message) { }
                @Override public void onDatabaseStatus(String message) { }
                @Override public void onControlStatus(String message) { }
            }));
            panel.setSize(1000, 700);
            panel.doLayout();
            ref.set(panel);
        });
        return ref.get();
    }

    private static void waitUntilExportNotRunning() throws Exception {
        long deadline = System.currentTimeMillis() + 10_000L;
        while (RuntimeConfig.isExportRunning() && System.currentTimeMillis() < deadline) {
            runEdt(() -> { });
            java.util.concurrent.locks.LockSupport.parkNanos(50_000_000L);
        }
        if (RuntimeConfig.isExportRunning()) {
            throw new AssertionError("Export still running after Stop");
        }
    }

    private static void waitUntilBackgroundReportersStopped() throws Exception {
        long deadline = System.currentTimeMillis() + 30_000L;
        while (System.currentTimeMillis() < deadline) {
            if (peek(ExporterIndexStatsReporter.class, "SCHEDULER") == null
                    && peek(SettingsIndexReporter.class, "SCHEDULER") == null
                    && peek(FindingsIndexReporter.class, "SCHEDULER") == null
                    && peek(SitemapIndexReporter.class, "SCHEDULER") == null
                    && peek(ProxyWebSocketIndexReporter.class, "SCHEDULER") == null) {
                return;
            }
            runEdt(() -> { });
            java.util.concurrent.locks.LockSupport.parkNanos(100_000_000L);
        }
        throw new AssertionError("Background reporters still running after Stop");
    }

    private static void runEdt(Runnable runnable) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            runnable.run();
        } else {
            SwingUtilities.invokeAndWait(runnable);
        }
    }

    private static void waitForControlStatus(JTextArea controlStatus, String expected) {
        long deadline = System.currentTimeMillis() + 10_000;
        while (System.currentTimeMillis() < deadline) {
            try {
                SwingUtilities.invokeAndWait(() -> { });
            } catch (java.lang.InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(e);
            } catch (java.lang.reflect.InvocationTargetException e) {
                throw new RuntimeException(e);
            }
            if (expected.equals(controlStatus.getText())) {
                return;
            }
            java.util.concurrent.locks.LockSupport.parkNanos(100_000_000L);
        }
        throw new AssertionError("Control status did not reach expected value: " + expected);
    }

    private static void flushLogListeners() throws Exception {
        runEdt(() -> { });
    }

    private static Component findByName(Container root, String name) {
        if (name.equals(root.getName())) {
            return root;
        }
        for (Component child : root.getComponents()) {
            if (name.equals(child.getName())) {
                return child;
            }
            if (child instanceof Container nested) {
                Component found = findByName(nested, name);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static <T extends Component> T findByName(Container root, String name, Class<T> type) {
        Component found = findByName(root, name);
        if (found == null) {
            return null;
        }
        if (!type.isInstance(found)) {
            throw new AssertionError("Component found for " + name + " but was not a " + type.getSimpleName());
        }
        return type.cast(found);
    }
}
