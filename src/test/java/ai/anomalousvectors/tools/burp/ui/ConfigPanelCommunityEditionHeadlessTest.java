package ai.anomalousvectors.tools.burp.ui;

import java.awt.Component;
import java.awt.Container;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.sinks.ExportReporterLifecycle;
import ai.anomalousvectors.tools.burp.testutils.Reflect;
import ai.anomalousvectors.tools.burp.ui.controller.ConfigController;
import ai.anomalousvectors.tools.burp.ui.primitives.TriStateCheckBox;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.Version;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ConfigPanelCommunityEditionHeadlessTest {

    private static void cleanupState() {
        MontoyaApiProvider.set(null);
        RuntimeConfig.updateState(null);
    }

    @Test
    void communityEdition_disables_findings_and_limited_traffic_options_and_shows_notices() throws Exception {
        try {
            ConfigPanel panel = createPanel(BurpSuiteEdition.COMMUNITY_EDITION);

            TriStateCheckBox issuesCheckbox = Reflect.get(panel, "issuesCheckbox", TriStateCheckBox.class);
            JButton issuesExpandButton = Reflect.get(panel, "issuesExpandButton", JButton.class);
            JCheckBox issuesCriticalCheckbox = Reflect.get(panel, "issuesCriticalCheckbox", JCheckBox.class);
            JCheckBox issuesHighCheckbox = Reflect.get(panel, "issuesHighCheckbox", JCheckBox.class);
            JCheckBox issuesMediumCheckbox = Reflect.get(panel, "issuesMediumCheckbox", JCheckBox.class);
            JCheckBox issuesLowCheckbox = Reflect.get(panel, "issuesLowCheckbox", JCheckBox.class);
            JCheckBox issuesInformationalCheckbox = Reflect.get(panel, "issuesInformationalCheckbox", JCheckBox.class);
            JCheckBox trafficBurpAiCheckbox = Reflect.get(panel, "trafficBurpAiCheckbox", JCheckBox.class);
            JCheckBox trafficExtensionsCheckbox = Reflect.get(panel, "trafficExtensionsCheckbox", JCheckBox.class);
            JCheckBox trafficIntruderCheckbox = Reflect.get(panel, "trafficIntruderCheckbox", JCheckBox.class);
            JCheckBox trafficProxyCheckbox = Reflect.get(panel, "trafficProxyCheckbox", JCheckBox.class);
            JCheckBox trafficProxyHistoryCheckbox = Reflect.get(panel, "trafficProxyHistoryCheckbox", JCheckBox.class);
            JCheckBox trafficRepeaterCheckbox = Reflect.get(panel, "trafficRepeaterCheckbox", JCheckBox.class);
            JCheckBox trafficRepeaterTabsCheckbox = Reflect.get(panel, "trafficRepeaterTabsCheckbox", JCheckBox.class);
            JCheckBox trafficScannerCheckbox = Reflect.get(panel, "trafficScannerCheckbox", JCheckBox.class);
            JCheckBox trafficSequencerCheckbox = Reflect.get(panel, "trafficSequencerCheckbox", JCheckBox.class);
            TriStateCheckBox trafficCheckbox = Reflect.get(panel, "trafficCheckbox", TriStateCheckBox.class);
            Map<?, ?> fieldsExpandButtons = Reflect.get(panel, "fieldsExpandButtons", Map.class);
            JButton findingsExpandButton = (JButton) fieldsExpandButtons.get("findings");
            Map<?, ?> fieldCheckboxesByIndexRaw = Reflect.get(panel, "fieldCheckboxesByIndex", Map.class);
            Map<?, ?> findingsFieldCheckboxes = fieldCheckboxesByIndexRaw.get("findings") instanceof Map<?, ?> findingsMap ? findingsMap : null;
            JCheckBox findingsSeverityField = findingsFieldCheckboxes != null
                    ? (JCheckBox) findingsFieldCheckboxes.get("issue.severity")
                    : null;
            JLabel findingsLabel = findLabelByText(panel, "Findings");
            JPanel issuesNotice = findByName(panel, "src.issues.communityNotice", JPanel.class);
            JLabel issuesNoticeIcon = findByName(panel, "src.issues.communityNotice.icon", JLabel.class);
            JPanel trafficBurpAiNotice = findByName(panel, "src.traffic.burp_ai.communityNotice", JPanel.class);
            JLabel trafficBurpAiNoticeIcon = findByName(panel, "src.traffic.burp_ai.communityNotice.icon", JLabel.class);
            JPanel trafficScannerNotice = findByName(panel, "src.traffic.scanner.communityNotice", JPanel.class);
            JLabel trafficScannerNoticeIcon = findByName(panel, "src.traffic.scanner.communityNotice.icon", JLabel.class);
            Map<String, JPanel> headerRows = Reflect.stringKeyedMap(panel, "fieldsSectionHeaderRows", JPanel.class);
            Map<String, JPanel> subPanels = Reflect.stringKeyedMap(panel, "fieldsSubPanels", JPanel.class);
            Map<String, Map<String, JCheckBox>> fieldCheckboxesByIndex = Reflect.stringKeyedNestedMap(panel, "fieldCheckboxesByIndex", JCheckBox.class);

            runEdt(() -> {
                assertThat(issuesCheckbox.isEnabled()).isFalse();
                assertThat(issuesCheckbox.isSelected()).isFalse();
                assertThat(issuesExpandButton.isEnabled()).isFalse();
                assertThat(issuesCheckbox.getToolTipText()).isEqualTo("<html>Unsupported in Community Edition.</html>");

                for (JCheckBox checkbox : List.of(
                        issuesCriticalCheckbox,
                        issuesHighCheckbox,
                        issuesMediumCheckbox,
                        issuesLowCheckbox,
                        issuesInformationalCheckbox)) {
                    assertThat(checkbox.isEnabled()).isFalse();
                    assertThat(checkbox.isSelected()).isFalse();
                }

                assertThat(trafficBurpAiCheckbox.isEnabled()).isFalse();
                assertThat(trafficBurpAiCheckbox.isSelected()).isFalse();
                assertThat(trafficExtensionsCheckbox.isSelected()).isTrue();
                assertThat(trafficIntruderCheckbox.isSelected()).isTrue();
                assertThat(trafficProxyCheckbox.isSelected()).isTrue();
                assertThat(trafficProxyHistoryCheckbox.isSelected()).isTrue();
                assertThat(trafficRepeaterCheckbox.isSelected()).isTrue();
                assertThat(trafficRepeaterTabsCheckbox.isSelected()).isTrue();
                assertThat(trafficScannerCheckbox.isEnabled()).isFalse();
                assertThat(trafficScannerCheckbox.isSelected()).isFalse();
                assertThat(trafficSequencerCheckbox.isSelected()).isTrue();
                assertThat(trafficCheckbox.getState()).isEqualTo(TriStateCheckBox.State.SELECTED);
                JLabel findingsLabelRef = java.util.Objects.requireNonNull(findingsLabel);
                assertThat(findingsLabelRef.getToolTipText()).isEqualTo("<html>Unsupported in Community Edition.</html>");
                JButton findingsExpandButtonRef = java.util.Objects.requireNonNull(findingsExpandButton);
                assertThat(findingsExpandButtonRef.isEnabled()).isFalse();
                assertThat(findingsExpandButtonRef.getToolTipText()).isEqualTo("<html>Unsupported in Community Edition.</html>");
                JCheckBox findingsSeverityFieldRef = java.util.Objects.requireNonNull(findingsSeverityField);
                assertThat(findingsSeverityFieldRef.isEnabled()).isFalse();
                assertThat(findingsSeverityFieldRef.isSelected()).isFalse();

                assertThat(issuesNotice.isVisible()).isTrue();
                assertThat(issuesNoticeIcon.getToolTipText()).isEqualTo("<html>Unsupported in Community Edition.</html>");
                assertThat(trafficBurpAiNotice.isVisible()).isTrue();
                assertThat(trafficBurpAiNoticeIcon.getToolTipText()).isEqualTo("<html>Unsupported in Community Edition.</html>");
                assertThat(trafficScannerNotice.isVisible()).isTrue();
                assertThat(trafficScannerNoticeIcon.getToolTipText()).isEqualTo("<html>Unsupported in Community Edition.</html>");
            });

            assertThat(sectionEnabled("findings", headerRows, subPanels, fieldCheckboxesByIndex)).isFalse();
        } finally {
            cleanupState();
        }
    }

    @Test
    void professionalEdition_keeps_controls_enabled_and_hides_community_notices() throws Exception {
        try {
            ConfigPanel panel = createPanel(BurpSuiteEdition.PROFESSIONAL);

            TriStateCheckBox issuesCheckbox = Reflect.get(panel, "issuesCheckbox", TriStateCheckBox.class);
            JButton issuesExpandButton = Reflect.get(panel, "issuesExpandButton", JButton.class);
            TriStateCheckBox trafficCheckbox = Reflect.get(panel, "trafficCheckbox", TriStateCheckBox.class);
            JCheckBox trafficBurpAiCheckbox = Reflect.get(panel, "trafficBurpAiCheckbox", JCheckBox.class);
            JCheckBox trafficExtensionsCheckbox = Reflect.get(panel, "trafficExtensionsCheckbox", JCheckBox.class);
            JCheckBox trafficIntruderCheckbox = Reflect.get(panel, "trafficIntruderCheckbox", JCheckBox.class);
            JCheckBox trafficProxyCheckbox = Reflect.get(panel, "trafficProxyCheckbox", JCheckBox.class);
            JCheckBox trafficProxyHistoryCheckbox = Reflect.get(panel, "trafficProxyHistoryCheckbox", JCheckBox.class);
            JCheckBox trafficRepeaterCheckbox = Reflect.get(panel, "trafficRepeaterCheckbox", JCheckBox.class);
            JCheckBox trafficRepeaterTabsCheckbox = Reflect.get(panel, "trafficRepeaterTabsCheckbox", JCheckBox.class);
            JCheckBox trafficScannerCheckbox = Reflect.get(panel, "trafficScannerCheckbox", JCheckBox.class);
            JCheckBox trafficSequencerCheckbox = Reflect.get(panel, "trafficSequencerCheckbox", JCheckBox.class);
            JPanel issuesNotice = findByName(panel, "src.issues.communityNotice", JPanel.class);
            JPanel trafficBurpAiNotice = findByName(panel, "src.traffic.burp_ai.communityNotice", JPanel.class);
            JPanel trafficScannerNotice = findByName(panel, "src.traffic.scanner.communityNotice", JPanel.class);

            runEdt(() -> {
                assertThat(issuesCheckbox.isEnabled()).isTrue();
                assertThat(issuesExpandButton.isEnabled()).isTrue();
                assertThat(issuesCheckbox.getToolTipText()).isEqualTo("<html>All findings (aka issues).</html>");
                assertThat(trafficCheckbox.getState()).isEqualTo(TriStateCheckBox.State.SELECTED);
                assertThat(trafficBurpAiCheckbox.isEnabled()).isTrue();
                assertThat(trafficBurpAiCheckbox.isSelected()).isTrue();
                assertThat(trafficExtensionsCheckbox.isSelected()).isTrue();
                assertThat(trafficIntruderCheckbox.isSelected()).isTrue();
                assertThat(trafficProxyCheckbox.isSelected()).isTrue();
                assertThat(trafficProxyHistoryCheckbox.isSelected()).isTrue();
                assertThat(trafficRepeaterCheckbox.isSelected()).isTrue();
                assertThat(trafficRepeaterTabsCheckbox.isSelected()).isTrue();
                assertThat(trafficScannerCheckbox.isEnabled()).isTrue();
                assertThat(trafficScannerCheckbox.isSelected()).isTrue();
                assertThat(trafficSequencerCheckbox.isSelected()).isTrue();
                assertThat(issuesNotice.isVisible()).isFalse();
                assertThat(trafficBurpAiNotice.isVisible()).isFalse();
                assertThat(trafficScannerNotice.isVisible()).isFalse();
            });
        } finally {
            cleanupState();
        }
    }

    @Test
    void importing_config_in_community_reapplies_source_restrictions() throws Exception {
        try {
            ConfigPanel panel = createPanel(BurpSuiteEdition.COMMUNITY_EDITION);
            TriStateCheckBox issuesCheckbox = Reflect.get(panel, "issuesCheckbox", TriStateCheckBox.class);
            TriStateCheckBox trafficCheckbox = Reflect.get(panel, "trafficCheckbox", TriStateCheckBox.class);
            JCheckBox issuesCriticalCheckbox = Reflect.get(panel, "issuesCriticalCheckbox", JCheckBox.class);
            JCheckBox trafficBurpAiCheckbox = Reflect.get(panel, "trafficBurpAiCheckbox", JCheckBox.class);
            JCheckBox trafficScannerCheckbox = Reflect.get(panel, "trafficScannerCheckbox", JCheckBox.class);
            JCheckBox trafficProxyCheckbox = Reflect.get(panel, "trafficProxyCheckbox", JCheckBox.class);
            Map<?, ?> fieldsExpandButtons = Reflect.get(panel, "fieldsExpandButtons", Map.class);
            JButton findingsExpandButton = (JButton) fieldsExpandButtons.get("findings");
            Map<?, ?> fieldCheckboxesByIndexRaw = Reflect.get(panel, "fieldCheckboxesByIndex", Map.class);
            Map<?, ?> findingsFieldCheckboxes = fieldCheckboxesByIndexRaw.get("findings") instanceof Map<?, ?> findingsMap ? findingsMap : null;
            JCheckBox findingsSeverityField = findingsFieldCheckboxes != null
                    ? (JCheckBox) findingsFieldCheckboxes.get("issue.severity")
                    : null;

            ConfigState.State imported = new ConfigState.State(
                    List.of(ConfigKeys.SRC_FINDINGS, ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(false, "", false, false, false, "", "", "", ConfigState.OPEN_SEARCH_TLS_VERIFY),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    List.of("burp_ai", "scanner", "proxy"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null,
                    null
            );

            runEdt(() -> panel.onImportResult(imported));

            runEdt(() -> {
                assertThat(issuesCheckbox.isEnabled()).isFalse();
                assertThat(issuesCheckbox.isSelected()).isFalse();
                assertThat(issuesCriticalCheckbox.isEnabled()).isFalse();
                assertThat(issuesCriticalCheckbox.isSelected()).isFalse();
                JButton findingsExpandButtonRef = java.util.Objects.requireNonNull(findingsExpandButton);
                assertThat(findingsExpandButtonRef.isEnabled()).isFalse();
                JCheckBox findingsSeverityFieldRef = java.util.Objects.requireNonNull(findingsSeverityField);
                assertThat(findingsSeverityFieldRef.isEnabled()).isFalse();
                assertThat(findingsSeverityFieldRef.isSelected()).isFalse();

                assertThat(trafficCheckbox.isSelected()).isTrue();
                assertThat(trafficBurpAiCheckbox.isEnabled()).isFalse();
                assertThat(trafficBurpAiCheckbox.isSelected()).isFalse();
                assertThat(trafficScannerCheckbox.isEnabled()).isFalse();
                assertThat(trafficScannerCheckbox.isSelected()).isFalse();
                assertThat(trafficProxyCheckbox.isEnabled()).isTrue();
                assertThat(trafficProxyCheckbox.isSelected()).isTrue();
            });

            runEdt(() -> {
                trafficCheckbox.doClick();
                trafficCheckbox.doClick();
            });

            runEdt(() -> {
                assertThat(trafficCheckbox.getState()).isEqualTo(TriStateCheckBox.State.SELECTED);
                assertThat(trafficBurpAiCheckbox.isSelected()).isFalse();
                assertThat(trafficScannerCheckbox.isSelected()).isFalse();
                assertThat(trafficProxyCheckbox.isSelected()).isTrue();
            });
        } finally {
            cleanupState();
        }
    }

    @Test
    void importing_professional_config_then_starting_in_community_keeps_runtime_state_stripped() throws Exception {
        Path exportRoot = Files.createTempDirectory("af-community-import-start");
        try {
            ConfigPanel panel = createPanel(BurpSuiteEdition.COMMUNITY_EDITION);
            JButton startStop = findByName(panel, "control.startStop", JButton.class);

            ConfigState.State imported = new ConfigState.State(
                    List.of(ConfigKeys.SRC_FINDINGS, ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(
                            true,
                            exportRoot.toAbsolutePath().normalize().toString(),
                            false,
                            true,
                            false,
                            "",
                            "",
                            "",
                            ConfigState.OPEN_SEARCH_TLS_VERIFY),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    List.of("burp_ai", "scanner", "proxy"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null,
                    null
            );

            runEdt(() -> panel.onImportResult(imported));
            runEdt(startStop::doClick);
            waitForStartedUi(startStop);

            assertThat(RuntimeConfig.isExportRunning()).isTrue();
            assertThat(RuntimeConfig.getState().dataSources()).containsExactly(ConfigKeys.SRC_TRAFFIC);
            assertThat(RuntimeConfig.getState().trafficToolTypes()).containsExactly("proxy");
            assertThat(RuntimeConfig.isDataSourceEnabled(ConfigKeys.SRC_FINDINGS)).isFalse();
            assertThat(RuntimeConfig.isTrafficToolTypeEnabled("burp_ai")).isFalse();
            assertThat(RuntimeConfig.isTrafficToolTypeEnabled("scanner")).isFalse();
            assertThat(RuntimeConfig.activeSinkSummary()).isEqualTo("Files");
        } finally {
            ExportReporterLifecycle.resetForTests();
            deleteRecursively(exportRoot);
            cleanupState();
        }
    }

    private static ConfigPanel createPanel(BurpSuiteEdition edition) throws Exception {
        cleanupState();
        MontoyaApiProvider.set(mockMontoyaApi(edition));
        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                ConfigPanel panel = new ConfigPanel(new ConfigController(new NoopUi()));
                panel.setSize(1000, 700);
                panel.doLayout();
                ref.set(panel);
            });
            return ref.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Failed to create ConfigPanel Community edition fixture", e);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            throw new RuntimeException(
                    "Failed to create ConfigPanel Community edition fixture", cause != null ? cause : e);
        }
    }

    private static MontoyaApi mockMontoyaApi(BurpSuiteEdition edition) {
        MontoyaApi api = mock(MontoyaApi.class);
        BurpSuite burpSuite = mock(BurpSuite.class);
        Version version = mock(Version.class);
        when(api.burpSuite()).thenReturn(burpSuite);
        when(burpSuite.version()).thenReturn(version);
        when(version.edition()).thenReturn(edition);
        return api;
    }

    private static void runEdt(Runnable runnable) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            runnable.run();
        } else {
            SwingUtilities.invokeAndWait(runnable);
        }
    }

    private static void waitForStartedUi(JButton startStop) {
        long deadline = System.currentTimeMillis() + 10_000;
        while (System.currentTimeMillis() < deadline) {
            try {
                SwingUtilities.invokeAndWait(() -> { });
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(e);
            } catch (InvocationTargetException e) {
                throw new RuntimeException(e);
            }
            if (RuntimeConfig.isExportRunning() && "Stop".equals(startStop.getText())) {
                return;
            }
            LockSupport.parkNanos(100_000_000L);
        }
        throw new AssertionError("Start button did not reach running state within timeout");
    }

    private static <T extends Component> T findByName(Container root, String name, Class<T> type) {
        String componentName = root.getName();
        if (name.equals(componentName) && type.isInstance(root)) {
            return type.cast(root);
        }
        for (Component component : root.getComponents()) {
            if (name.equals(component.getName()) && type.isInstance(component)) {
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

    private static JLabel findLabelByText(Container root, String text) {
        if (root instanceof JLabel label && text.equals(label.getText())) {
            return label;
        }
        for (Component component : root.getComponents()) {
            if (component instanceof JLabel label && text.equals(label.getText())) {
                return label;
            }
            if (component instanceof Container child) {
                JLabel nested = findLabelByText(child, text);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }

    /**
     * Best-effort recursive delete of a temp directory tree.
     *
     * <p>Uses {@link Files#walkFileTree} with a {@link SimpleFileVisitor} so per-entry I/O failures
     * (which happen when an in-flight async start probe such as {@code FileUtil.ensureDirectoryWritable}
     * creates and deletes {@code .burp-exporter-write-probe-*.tmp} files concurrently with
     * cleanup) do not abort the walk. Returning {@link FileVisitResult#CONTINUE} from
     * {@code visitFileFailed} lets the rest of the tree still be cleaned up rather than leaking
     * remaining files when the first vanished entry would otherwise turn an in-stream
     * {@code NoSuchFileException} into an {@code UncheckedIOException} that escapes the cleanup.</p>
     */
    private static void deleteRecursively(Path root) {
        if (root == null) {
            return;
        }
        try {
            if (!Files.exists(root)) {
                return;
            }
            Files.walkFileTree(root, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    try {
                        Files.deleteIfExists(file);
                    } catch (java.io.IOException ignored) {
                        // Best-effort temp cleanup for tests.
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, java.io.IOException exc) {
                    // Entry vanished or could not be stat'd mid-walk; keep cleaning the rest.
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, java.io.IOException exc) {
                    try {
                        Files.deleteIfExists(dir);
                    } catch (java.io.IOException ignored) {
                        // Best-effort temp cleanup for tests.
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (java.io.IOException ignored) {
            // Best-effort temp cleanup for tests.
        }
    }

    private static boolean sectionEnabled(
            String indexName,
            Map<String, JPanel> headerRows,
            Map<String, JPanel> subPanels,
            Map<String, Map<String, JCheckBox>> fieldCheckboxesByIndex) {
        JPanel header = headerRows != null ? headerRows.get(indexName) : null;
        if (header != null && !header.isEnabled()) {
            return false;
        }
        JPanel sub = subPanels != null ? subPanels.get(indexName) : null;
        if (sub != null && !sub.isEnabled()) {
            return false;
        }
        Map<String, JCheckBox> checkboxes = fieldCheckboxesByIndex != null ? fieldCheckboxesByIndex.get(indexName) : null;
        if (checkboxes != null) {
            for (JCheckBox checkbox : checkboxes.values()) {
                if (!checkbox.isEnabled()) {
                    return false;
                }
            }
        }
        return true;
    }

    private static final class NoopUi implements ConfigController.Ui {
        @Override public void onFileStatus(String message) {}
        @Override public void onDatabaseStatus(String message) {}
        @Override public void onControlStatus(String message) {}
    }
}
