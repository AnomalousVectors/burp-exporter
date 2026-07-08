package ai.anomalousvectors.tools.burp.ui;

import static ai.anomalousvectors.tools.burp.testutils.Reflect.get;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.getComboBox;
import static org.assertj.core.api.Assertions.assertThat;

import java.awt.Component;
import java.awt.Container;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.sinks.ExportReporterLifecycle;
import ai.anomalousvectors.tools.burp.sinks.TrafficExportQueue;
import ai.anomalousvectors.tools.burp.testutils.OpenSearchReachable;
import ai.anomalousvectors.tools.burp.testutils.OpenSearchTestConfig;
import ai.anomalousvectors.tools.burp.testutils.TestPathSupport;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

@Tag("integration")
class ConfigPanelStartFailureAuthIT {

    private ConfigPanel panel;

    @Test
    void start_withInvalidAuth_revertsUi_and_clearsQueuedExportWork() throws Exception {
        try {
            Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

            AtomicReference<ConfigPanel> ref = new AtomicReference<>();
            SwingUtilities.invokeAndWait(() -> {
                ConfigPanel p = new ConfigPanel();
                p.setSize(1000, 700);
                p.doLayout();

                javax.swing.AbstractButton openSearchEnabled = javax.swing.AbstractButton.class.cast(get(p, "openSearchSinkCheckbox"));
                if (!openSearchEnabled.isSelected()) {
                    openSearchEnabled.doClick();
                }

                JTextField openSearchUrlField = JTextField.class.cast(get(p, "openSearchUrlField"));
                openSearchUrlField.setText(OpenSearchReachable.BASE_URL);

                JComboBox<?> authCombo = getComboBox(p, "openSearchAuthTypeCombo");
                authCombo.setSelectedItem("Basic");

                JTextField userField = JTextField.class.cast(get(p, "openSearchUserField"));
                JPasswordField passwordField = JPasswordField.class.cast(get(p, "openSearchPasswordField"));
                userField.setText("definitely-wrong");
                passwordField.setText("definitely-wrong");

                ref.set(p);
            });
            panel = Objects.requireNonNull(ref.get());

            JButton startStop = Objects.requireNonNull(findByName(panel, "control.startStop", JButton.class));
            JTextArea controlStatus = Objects.requireNonNull(JTextArea.class.cast(get(panel, "controlStatus")));

            SwingUtilities.invokeAndWait(startStop::doClick);
            waitForStoppedUi(startStop);

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(controlStatus.getText()).contains("Start aborted");
            assertThat(controlStatus.getText()).contains("401");

            // Give any late worker transitions a brief chance to enqueue if cleanup is incomplete.
            LockSupport.parkNanos(1_500_000_000L);

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(ExportStats.getQueueSize("exporter")).isZero();
            assertThat(ExportStats.getQueueSize("traffic")).isZero();
            assertThat(ExportStats.getQueueSize("settings")).isZero();
            assertThat(ExportStats.getQueueSize("sitemap")).isZero();
            assertThat(ExportStats.getQueueSize("findings")).isZero();
            assertThat(TrafficExportQueue.getCurrentSize()).isZero();
            assertThat(TrafficExportQueue.getCurrentSpillSize()).isZero();
        } finally {
            ExportReporterLifecycle.resetForTests();
            Logger.resetState();
        }
    }

    @Test
    void start_withFilesPreflightFailure_butValidOpenSearch_keepsOpenSearchRunning() throws Exception {
        Path invalidFileRoot = TestPathSupport.createFile("af-files-partial-start-not-dir", ".tmp");
        OpenSearchTestConfig config = OpenSearchTestConfig.get();
        Logger.resetState();
        List<String> events = new CopyOnWriteArrayList<>();
        Logger.LogListener listener = (level, message) -> events.add(level + "|" + message);
        Logger.registerListener(listener);
        try {
            Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

            AtomicReference<ConfigPanel> ref = new AtomicReference<>();
            SwingUtilities.invokeAndWait(() -> {
                ConfigPanel p = new ConfigPanel();
                p.setSize(1000, 700);
                p.doLayout();

                JCheckBox filesEnabled = JCheckBox.class.cast(get(p, "fileSinkCheckbox"));
                if (!filesEnabled.isSelected()) {
                    filesEnabled.doClick();
                }
                JRadioButton bulkNdjsonEnabled = JRadioButton.class.cast(get(p, "fileBulkNdjsonCheckbox"));
                if (!bulkNdjsonEnabled.isSelected()) {
                    bulkNdjsonEnabled.doClick();
                }
                JTextField filePathField = JTextField.class.cast(get(p, "filePathField"));
                filePathField.setText(invalidFileRoot.toAbsolutePath().normalize().toString());

                javax.swing.AbstractButton openSearchEnabled = javax.swing.AbstractButton.class.cast(get(p, "openSearchSinkCheckbox"));
                if (!openSearchEnabled.isSelected()) {
                    openSearchEnabled.doClick();
                }
                JTextField openSearchUrlField = JTextField.class.cast(get(p, "openSearchUrlField"));
                openSearchUrlField.setText(config.baseUrl());

                JComboBox<?> authCombo = getComboBox(p, "openSearchAuthTypeCombo");
                JTextField userField = JTextField.class.cast(get(p, "openSearchUserField"));
                JPasswordField passwordField = JPasswordField.class.cast(get(p, "openSearchPasswordField"));
                if (config.hasCredentials()) {
                    authCombo.setSelectedItem("Basic");
                    userField.setText(config.username());
                    passwordField.setText(config.password());
                } else {
                    authCombo.setSelectedItem("None");
                    userField.setText("");
                    passwordField.setText("");
                }

                ref.set(p);
            });
            panel = Objects.requireNonNull(ref.get());

            JButton startStop = Objects.requireNonNull(findByName(panel, "control.startStop", JButton.class));
            JTextArea controlStatus = Objects.requireNonNull(JTextArea.class.cast(get(panel, "controlStatus")));

            SwingUtilities.invokeAndWait(startStop::doClick);
            waitForStartedUi(startStop);
            waitForLogMessage(events, "Files failed during start: File export preflight failed:");
            waitForLogMessage(events, "OpenSearch export will continue.");
            waitForLogMessage(events, "[OpenSearch] Initializing indexes for selected sources.");
            waitForLogMessage(events, "[Export] Started. Destinations: OpenSearch.");

            assertThat(RuntimeConfig.isExportRunning()).isTrue();
            assertThat(RuntimeConfig.isAnyFileExportEnabled()).isFalse();
            assertThat(RuntimeConfig.isOpenSearchExportEnabled()).isTrue();
            assertThat(controlStatus.getText()).contains("Files: Start failed (");
            assertThat(controlStatus.getText()).contains("OpenSearch: Running -> " + config.baseUrl());

            SwingUtilities.invokeAndWait(startStop::doClick);
            waitForStoppedUi(startStop);
        } finally {
            Logger.unregisterListener(listener);
            ExportReporterLifecycle.resetForTests();
            Logger.resetState();
        }
    }

    private static void waitForStoppedUi(JButton startStop) {
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
            if (!RuntimeConfig.isExportRunning() && "Start".equals(startStop.getText())) {
                return;
            }
            LockSupport.parkNanos(100_000_000L);
        }
        throw new AssertionError("Start button did not revert to stopped state within timeout");
    }

    private static void waitForStartedUi(JButton startStop) {
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
            if (RuntimeConfig.isExportRunning() && "Stop".equals(startStop.getText())) {
                return;
            }
            LockSupport.parkNanos(100_000_000L);
        }
        throw new AssertionError("Start button did not reach running state within timeout");
    }

    private static void waitForLogMessage(List<String> events, String snippet) {
        long deadline = System.currentTimeMillis() + 10_000;
        while (System.currentTimeMillis() < deadline) {
            if (events.stream().anyMatch(message -> message.contains(snippet))) {
                return;
            }
            LockSupport.parkNanos(100_000_000L);
        }
        throw new AssertionError("Expected log message containing: " + snippet);
    }

    private static <T extends Component> T findByName(Container root, String name, Class<T> type) {
        for (Component component : root.getComponents()) {
            String componentName = component.getName();
            if (type.isInstance(component) && componentName != null && name.equals(componentName)) {
                return type.cast(component);
            }
            if (component instanceof Container child) {
                T nested = findByName(child, name, type);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }
}
