package ai.anomalousvectors.tools.burp.ui;

import static ai.anomalousvectors.tools.burp.testutils.Reflect.get;
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
import javax.swing.ButtonGroup;
import javax.swing.JCheckBox;
import javax.swing.JRadioButton;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.sinks.ExportReporterLifecycle;
import ai.anomalousvectors.tools.burp.testutils.TestPathSupport;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

class ConfigPanelStartFailureFilesHeadlessTest {

    @Test
    void start_withPlaceholderSearchDestinationOnly_revertsUi_and_reportsStatus() throws Exception {
        Logger.resetState();
        List<String> events = new CopyOnWriteArrayList<>();
        Logger.LogListener listener = (level, message) -> events.add(level + "|" + message);
        Logger.registerListener(listener);
        try {
            AtomicReference<ConfigPanel> ref = new AtomicReference<>();
            SwingUtilities.invokeAndWait(() -> {
                ConfigPanel p = new ConfigPanel();
                p.setSize(1000, 700);
                p.doLayout();

                javax.swing.AbstractButton awsDestination = javax.swing.AbstractButton.class.cast(get(p, "openSearchAmazonDestinationRadio"));
                if (!awsDestination.isSelected()) {
                    awsDestination.doClick();
                }

                JCheckBox filesEnabled = JCheckBox.class.cast(get(p, "fileSinkCheckbox"));
                if (filesEnabled.isSelected()) {
                    filesEnabled.doClick();
                }
                ref.set(p);
            });
            ConfigPanel panel = Objects.requireNonNull(ref.get());

            JButton startStop = Objects.requireNonNull(findByName(panel, "control.startStop", JButton.class));
            JTextArea controlStatus = Objects.requireNonNull(JTextArea.class.cast(get(panel, "controlStatus")));

            SwingUtilities.invokeAndWait(startStop::doClick);
            waitForStoppedUi(startStop);

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(controlStatus.getText()).contains("Start aborted");
            assertThat(controlStatus.getText())
                    .contains("Amazon OpenSearch is not wired for Start/export yet.");
            waitForLogMessage(events, "Amazon OpenSearch is not wired for Start/export yet.");
        } finally {
            Logger.unregisterListener(listener);
            ExportReporterLifecycle.resetForTests();
            Logger.resetState();
        }
    }

    @Test
    void start_withFilesOnly_logsDestinationSummary() throws Exception {
        Path exportRoot = TestPathSupport.createDirectory("af-file-root");
        Path exportRootAbs = exportRoot.toAbsolutePath().normalize();
        Logger.resetState();
        List<String> events = new CopyOnWriteArrayList<>();
        Logger.LogListener listener = (level, message) -> events.add(level + "|" + message);
        Logger.registerListener(listener);
        try {
            AtomicReference<ConfigPanel> ref = new AtomicReference<>();
            SwingUtilities.invokeAndWait(() -> {
                ConfigPanel p = new ConfigPanel();
                p.setSize(1000, 700);
                p.doLayout();

                javax.swing.AbstractButton awsDestination = javax.swing.AbstractButton.class.cast(get(p, "openSearchAmazonDestinationRadio"));
                if (!awsDestination.isSelected()) {
                    awsDestination.doClick();
                }

                JCheckBox filesEnabled = JCheckBox.class.cast(get(p, "fileSinkCheckbox"));
                if (!filesEnabled.isSelected()) {
                    filesEnabled.doClick();
                }
                JRadioButton bulkNdjsonEnabled = JRadioButton.class.cast(get(p, "fileBulkNdjsonCheckbox"));
                if (!bulkNdjsonEnabled.isSelected()) {
                    bulkNdjsonEnabled.doClick();
                }

                JTextField filePathField = JTextField.class.cast(get(p, "filePathField"));
                filePathField.setText(exportRootAbs.toString());
                ref.set(p);
            });
            ConfigPanel panel = Objects.requireNonNull(ref.get());

            JButton startStop = Objects.requireNonNull(findByName(panel, "control.startStop", JButton.class));
            SwingUtilities.invokeAndWait(startStop::doClick);
            waitForStartedUi(startStop);
            waitForLogMessage(events, "[Files] Initializing files for selected sources.");
            waitForLogMessage(events, "[Files] Creating file for Exporter (.ndjson).");
            waitForLogMessage(events, "[Files] File result for Exporter (.ndjson):");
            waitForLogMessage(events, "[Export] Started. Destinations: Files.");

            assertThat(RuntimeConfig.isExportRunning()).isTrue();
            assertThat(startStop.getText()).isEqualTo("Stop");
            assertThat(get(panel, "controlStatus", JTextArea.class).getText())
                    .isEqualTo("Files: Running -> " + exportRootAbs);

            SwingUtilities.invokeAndWait(startStop::doClick);
            waitForStoppedUi(startStop);
        } finally {
            Logger.unregisterListener(listener);
            TestPathSupport.cleanupExportArtifacts(exportRoot);
            ExportReporterLifecycle.resetForTests();
            Logger.resetState();
        }
    }

    @Test
    void start_withFilesSelectedButBlankRoot_logsAndAborts() throws Exception {
        Logger.resetState();
        List<String> events = new CopyOnWriteArrayList<>();
        Logger.LogListener listener = (level, message) -> events.add(level + "|" + message);
        Logger.registerListener(listener);
        try {
            AtomicReference<ConfigPanel> ref = new AtomicReference<>();
            SwingUtilities.invokeAndWait(() -> {
                ConfigPanel p = new ConfigPanel();
                p.setSize(1000, 700);
                p.doLayout();

                javax.swing.AbstractButton awsDestination = javax.swing.AbstractButton.class.cast(get(p, "openSearchAmazonDestinationRadio"));
                if (!awsDestination.isSelected()) {
                    awsDestination.doClick();
                }

                JCheckBox filesEnabled = JCheckBox.class.cast(get(p, "fileSinkCheckbox"));
                if (!filesEnabled.isSelected()) {
                    filesEnabled.doClick();
                }
                JRadioButton bulkNdjsonEnabled = JRadioButton.class.cast(get(p, "fileBulkNdjsonCheckbox"));
                if (!bulkNdjsonEnabled.isSelected()) {
                    bulkNdjsonEnabled.doClick();
                }

                JTextField filePathField = JTextField.class.cast(get(p, "filePathField"));
                filePathField.setText("   ");
                ref.set(p);
            });
            ConfigPanel panel = Objects.requireNonNull(ref.get());

            JButton startStop = Objects.requireNonNull(findByName(panel, "control.startStop", JButton.class));
            JTextArea controlStatus = Objects.requireNonNull(JTextArea.class.cast(get(panel, "controlStatus")));

            SwingUtilities.invokeAndWait(startStop::doClick);
            waitForStoppedUi(startStop);
            waitForLogMessage(events, "Files not started: root directory is blank.");

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(controlStatus.getText()).contains("Start aborted");
            assertThat(controlStatus.getText()).contains("Files not started: root directory is blank.");
        } finally {
            Logger.unregisterListener(listener);
            ExportReporterLifecycle.resetForTests();
            Logger.resetState();
        }
    }

    @Test
    void start_withFilesConfiguredAndBlankOpenSearchUrl_reportsFailureAndWhatIsRunning() throws Exception {
        Path exportRoot = TestPathSupport.createDirectory("af-file-root-os-blank");
        Path exportRootAbs = exportRoot.toAbsolutePath().normalize();
        Logger.resetState();
        List<String> events = new CopyOnWriteArrayList<>();
        Logger.LogListener listener = (level, message) -> events.add(level + "|" + message);
        Logger.registerListener(listener);
        try {
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
                filePathField.setText(exportRootAbs.toString());

                javax.swing.AbstractButton openSearchEnabled = javax.swing.AbstractButton.class.cast(get(p, "openSearchSinkCheckbox"));
                if (!openSearchEnabled.isSelected()) {
                    openSearchEnabled.doClick();
                }
                JTextField openSearchUrlField = JTextField.class.cast(get(p, "openSearchUrlField"));
                openSearchUrlField.setText("");
                ref.set(p);
            });
            ConfigPanel panel = Objects.requireNonNull(ref.get());

            JButton startStop = Objects.requireNonNull(findByName(panel, "control.startStop", JButton.class));
            JTextArea controlStatus = Objects.requireNonNull(JTextArea.class.cast(get(panel, "controlStatus")));

            SwingUtilities.invokeAndWait(startStop::doClick);
            waitForStartedUi(startStop);
            waitForLogMessage(events, "[Files] Initializing files for selected sources.");
            waitForLogMessage(events, "[Files] Creating file for Exporter (.ndjson).");
            waitForLogMessage(events, "[Files] File result for Exporter (.ndjson):");
            waitForLogMessage(events, "OpenSearch not started: base URL is blank.");
            waitForLogMessage(events, "[Export] Started. Destinations: Files.");

            assertThat(RuntimeConfig.isExportRunning()).isTrue();
            assertThat(startStop.getText()).isEqualTo("Stop");
            assertThat(controlStatus.getText())
                    .isEqualTo("Files: Running -> " + exportRootAbs
                            + "\nOpenSearch: Not started (base URL is blank.)");

            SwingUtilities.invokeAndWait(startStop::doClick);
            waitForStoppedUi(startStop);
        } finally {
            Logger.unregisterListener(listener);
            TestPathSupport.cleanupExportArtifacts(exportRoot);
            ExportReporterLifecycle.resetForTests();
            Logger.resetState();
        }
    }

    @Test
    void start_withOpenSearchPreflightFailure_keepsOpenSearchDisabledForCurrentRunAfterFurtherUiChanges() throws Exception {
        ExportReporterLifecycle.resetForTests();
        Path exportRoot = TestPathSupport.createDirectory("af-file-root-os-preflight-fail");
        Path exportRootAbs = exportRoot.toAbsolutePath().normalize();
        Logger.resetState();
        List<String> events = new CopyOnWriteArrayList<>();
        Logger.LogListener listener = (level, message) -> events.add(level + "|" + message);
        Logger.registerListener(listener);
        try {
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
                filePathField.setText(exportRootAbs.toString());

                javax.swing.AbstractButton openSearchEnabled = javax.swing.AbstractButton.class.cast(get(p, "openSearchSinkCheckbox"));
                if (!openSearchEnabled.isSelected()) {
                    openSearchEnabled.doClick();
                }
                JTextField openSearchUrlField = JTextField.class.cast(get(p, "openSearchUrlField"));
                openSearchUrlField.setText("https://[");
                ref.set(p);
            });
            ConfigPanel panel = Objects.requireNonNull(ref.get());

            JButton startStop = Objects.requireNonNull(findByName(panel, "control.startStop", JButton.class));
            JTextArea controlStatus = Objects.requireNonNull(JTextArea.class.cast(get(panel, "controlStatus")));
            JTextField openSearchUrlField = JTextField.class.cast(get(panel, "openSearchUrlField"));

            SwingUtilities.invokeAndWait(startStop::doClick);
            waitForStartedUi(startStop);
            waitForLogMessage(events, "OpenSearch failed during start:");
            waitForLogMessage(events, "Files export will continue.");

            assertThat(RuntimeConfig.isExportRunning()).isTrue();
            assertThat(RuntimeConfig.isOpenSearchExportEnabled()).isFalse();
            assertThat(RuntimeConfig.isOpenSearchDisabledForCurrentRun()).isTrue();
            assertThat(RuntimeConfig.activeSinkSummary()).isEqualTo("Files");
            assertThat(controlStatus.getText()).contains("Files: Running -> " + exportRootAbs);
            assertThat(controlStatus.getText()).contains("OpenSearch: Start failed (");

            SwingUtilities.invokeAndWait(() -> openSearchUrlField.setText("https://opensearch.url:9200"));
            waitForLogMessage(events, "[Export] Started. Destinations: Files.");

            assertThat(RuntimeConfig.isOpenSearchExportEnabled()).isFalse();
            assertThat(RuntimeConfig.isOpenSearchDisabledForCurrentRun()).isTrue();
            assertThat(RuntimeConfig.openSearchUrl()).isEmpty();
            assertThat(RuntimeConfig.activeSinkSummary()).isEqualTo("Files");

            SwingUtilities.invokeAndWait(startStop::doClick);
            waitForStoppedUi(startStop);
        } finally {
            Logger.unregisterListener(listener);
            TestPathSupport.cleanupExportArtifacts(exportRoot);
            ExportReporterLifecycle.resetForTests();
            Logger.resetState();
        }
    }

    @Test
    void start_withFileRootThatIsNotWritableDirectory_revertsUi_and_reportsStatus() throws Exception {
        Path notADirectory = TestPathSupport.createFile("af-file-root-not-dir", ".tmp");
        try {
            AtomicReference<ConfigPanel> ref = new AtomicReference<>();
            SwingUtilities.invokeAndWait(() -> {
                ConfigPanel p = new ConfigPanel();
                p.setSize(1000, 700);
                p.doLayout();

                javax.swing.AbstractButton awsDestination = javax.swing.AbstractButton.class.cast(get(p, "openSearchAmazonDestinationRadio"));
                if (!awsDestination.isSelected()) {
                    awsDestination.doClick();
                }

                JCheckBox filesEnabled = JCheckBox.class.cast(get(p, "fileSinkCheckbox"));
                if (!filesEnabled.isSelected()) {
                    filesEnabled.doClick();
                }
                JRadioButton bulkNdjsonEnabled = JRadioButton.class.cast(get(p, "fileBulkNdjsonCheckbox"));
                if (!bulkNdjsonEnabled.isSelected()) {
                    bulkNdjsonEnabled.doClick();
                }

                JTextField filePathField = JTextField.class.cast(get(p, "filePathField"));
                filePathField.setText(notADirectory.toString());
                ref.set(p);
            });
            ConfigPanel panel = Objects.requireNonNull(ref.get());

            JButton startStop = Objects.requireNonNull(findByName(panel, "control.startStop", JButton.class));
            JTextArea controlStatus = Objects.requireNonNull(JTextArea.class.cast(get(panel, "controlStatus")));

            SwingUtilities.invokeAndWait(startStop::doClick);
            waitForStoppedUi(startStop);

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(controlStatus.getText()).contains("Start aborted");
            assertThat(controlStatus.getText()).contains("File export preflight failed");
        } finally {
            ExportReporterLifecycle.resetForTests();
            Logger.resetState();
        }
    }

    @Test
    void start_withRelativeFileRoot_logsAndAborts() throws Exception {
        Logger.resetState();
        List<String> events = new CopyOnWriteArrayList<>();
        Logger.LogListener listener = (level, message) -> events.add(level + "|" + message);
        Logger.registerListener(listener);
        try {
            AtomicReference<ConfigPanel> ref = new AtomicReference<>();
            SwingUtilities.invokeAndWait(() -> {
                ConfigPanel p = new ConfigPanel();
                p.setSize(1000, 700);
                p.doLayout();

                javax.swing.AbstractButton awsDestination = javax.swing.AbstractButton.class.cast(get(p, "openSearchAmazonDestinationRadio"));
                if (!awsDestination.isSelected()) {
                    awsDestination.doClick();
                }

                JCheckBox filesEnabled = JCheckBox.class.cast(get(p, "fileSinkCheckbox"));
                if (!filesEnabled.isSelected()) {
                    filesEnabled.doClick();
                }
                JRadioButton bulkNdjsonEnabled = JRadioButton.class.cast(get(p, "fileBulkNdjsonCheckbox"));
                if (!bulkNdjsonEnabled.isSelected()) {
                    bulkNdjsonEnabled.doClick();
                }

                JTextField filePathField = JTextField.class.cast(get(p, "filePathField"));
                filePathField.setText("%^&%^&");
                ref.set(p);
            });
            ConfigPanel panel = Objects.requireNonNull(ref.get());

            JButton startStop = Objects.requireNonNull(findByName(panel, "control.startStop", JButton.class));
            JTextArea controlStatus = Objects.requireNonNull(JTextArea.class.cast(get(panel, "controlStatus")));

            SwingUtilities.invokeAndWait(startStop::doClick);
            waitForStoppedUi(startStop);
            waitForLogMessage(events, "file export root must be an absolute path");

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(controlStatus.getText()).contains("Start aborted");
            assertThat(controlStatus.getText()).contains("file export root must be an absolute path");
        } finally {
            Logger.unregisterListener(listener);
            ExportReporterLifecycle.resetForTests();
            Logger.resetState();
        }
    }

    @Test
    void start_withFilesEnabledButNoFormatSelected_revertsUi_and_reportsStatus() throws Exception {
        try {
            AtomicReference<ConfigPanel> ref = new AtomicReference<>();
            SwingUtilities.invokeAndWait(() -> {
                ConfigPanel p = new ConfigPanel();
                p.setSize(1000, 700);
                p.doLayout();

                javax.swing.AbstractButton awsDestination = javax.swing.AbstractButton.class.cast(get(p, "openSearchAmazonDestinationRadio"));
                if (!awsDestination.isSelected()) {
                    awsDestination.doClick();
                }

                JCheckBox filesEnabled = JCheckBox.class.cast(get(p, "fileSinkCheckbox"));
                if (!filesEnabled.isSelected()) {
                    filesEnabled.doClick();
                }
                ButtonGroup fileFormatGroup = ButtonGroup.class.cast(get(p, "fileFormatGroup"));
                fileFormatGroup.clearSelection();

                JTextField filePathField = JTextField.class.cast(get(p, "filePathField"));
                filePathField.setText(TestPathSupport.defaultUiFileRoot().toString());
                ref.set(p);
            });
            ConfigPanel panel = Objects.requireNonNull(ref.get());

            JButton startStop = Objects.requireNonNull(findByName(panel, "control.startStop", JButton.class));
            JTextArea controlStatus = Objects.requireNonNull(JTextArea.class.cast(get(panel, "controlStatus")));

            SwingUtilities.invokeAndWait(startStop::doClick);
            waitForStoppedUi(startStop);

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(controlStatus.getText()).contains("Start aborted");
            assertThat(controlStatus.getText()).contains("select at least one file format");
        } finally {
            ExportReporterLifecycle.resetForTests();
            Logger.resetState();
        }
    }

    @Test
    void start_withInvalidResolvedIndexNames_revertsUi_and_reportsStatus() throws Exception {
        Path exportRoot = TestPathSupport.createDirectory("af-file-root-invalid-index-name");
        Path exportRootAbs = exportRoot.toAbsolutePath().normalize();
        try {
            AtomicReference<ConfigPanel> ref = new AtomicReference<>();
            SwingUtilities.invokeAndWait(() -> {
                ConfigPanel p = new ConfigPanel();
                p.setSize(1000, 700);
                p.doLayout();

                javax.swing.AbstractButton awsDestination = javax.swing.AbstractButton.class.cast(get(p, "openSearchAmazonDestinationRadio"));
                if (!awsDestination.isSelected()) {
                    awsDestination.doClick();
                }

                JCheckBox filesEnabled = JCheckBox.class.cast(get(p, "fileSinkCheckbox"));
                if (!filesEnabled.isSelected()) {
                    filesEnabled.doClick();
                }
                JRadioButton bulkNdjsonEnabled = JRadioButton.class.cast(get(p, "fileBulkNdjsonCheckbox"));
                if (!bulkNdjsonEnabled.isSelected()) {
                    bulkNdjsonEnabled.doClick();
                }

                JTextField filePathField = JTextField.class.cast(get(p, "filePathField"));
                filePathField.setText(exportRootAbs.toString());
                JTextField baseTemplateField = Objects.requireNonNull(findByName(p, "indexNaming.baseTemplate", JTextField.class));
                baseTemplateField.setText("Invalid Base");
                ref.set(p);
            });
            ConfigPanel panel = Objects.requireNonNull(ref.get());

            JButton startStop = Objects.requireNonNull(findByName(panel, "control.startStop", JButton.class));
            JTextArea controlStatus = Objects.requireNonNull(JTextArea.class.cast(get(panel, "controlStatus")));

            SwingUtilities.invokeAndWait(startStop::doClick);
            waitForStoppedUi(startStop);

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(controlStatus.getText()).contains("Start aborted");
            assertThat(controlStatus.getText()).contains("fix index naming before Start");
            assertThat(controlStatus.getText()).contains("must be lowercase");
        } finally {
            TestPathSupport.cleanupExportArtifacts(exportRoot);
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

    private static void waitForLogMessage(List<String> events, String snippet) throws Exception {
        long deadline = System.currentTimeMillis() + 60_000;
        while (System.currentTimeMillis() < deadline) {
            SwingUtilities.invokeAndWait(() -> {});
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
