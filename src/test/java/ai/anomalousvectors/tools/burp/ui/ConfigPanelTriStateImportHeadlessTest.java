package ai.anomalousvectors.tools.burp.ui;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JCheckBox;
import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.testutils.Reflect;
import ai.anomalousvectors.tools.burp.ui.controller.ConfigController;
import ai.anomalousvectors.tools.burp.ui.primitives.TriStateCheckBox;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;

/**
 * Verifies that tri-state parent checkboxes reflect the aggregate state of their children after
 * a config import.
 *
 * <p>Importing a configuration updates child selections programmatically via
 * {@code setSelected(...)}. The parent must settle on {@link TriStateCheckBox.State#SELECTED},
 * {@link TriStateCheckBox.State#INDETERMINATE}, or {@link TriStateCheckBox.State#DESELECTED}
 * according to how many enabled children are selected.</p>
 */
class ConfigPanelTriStateImportHeadlessTest {

    @Test
    void import_withPartialTrafficChildren_setsTrafficParentToIndeterminate() throws Exception {
        ConfigPanel panel = createPanel();

        TriStateCheckBox trafficCheckbox = Reflect.get(panel, "trafficCheckbox", TriStateCheckBox.class);

        // Imported state selects "traffic" at top-level but only "repeater_tabs" among children.
        ConfigState.State imported = new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("repeater_tabs"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                null);

        SwingUtilities.invokeAndWait(() -> panel.onImportResult(imported));

        assertThat(trafficCheckbox.getState())
                .as("Traffic parent must reflect partial sub-selection after import")
                .isEqualTo(TriStateCheckBox.State.INDETERMINATE);

        JCheckBox repeaterTabs = Reflect.get(panel, "trafficRepeaterTabsCheckbox", JCheckBox.class);
        JCheckBox proxy = Reflect.get(panel, "trafficProxyCheckbox", JCheckBox.class);
        assertThat(repeaterTabs.isSelected()).isTrue();
        assertThat(proxy.isSelected()).isFalse();
    }

    @Test
    void import_withAllTrafficChildren_setsTrafficParentToSelected() throws Exception {
        ConfigPanel panel = createPanel();

        TriStateCheckBox trafficCheckbox = Reflect.get(panel, "trafficCheckbox", TriStateCheckBox.class);

        ConfigState.State imported = new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("burp_ai", "extensions", "intruder", "proxy", "proxy_history",
                        "repeater", "repeater_tabs", "scanner", "sequencer"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                null);

        SwingUtilities.invokeAndWait(() -> panel.onImportResult(imported));

        assertThat(trafficCheckbox.getState()).isEqualTo(TriStateCheckBox.State.SELECTED);
    }

    @Test
    void import_withNoTrafficChildren_setsTrafficParentToDeselected() throws Exception {
        ConfigPanel panel = createPanel();

        TriStateCheckBox trafficCheckbox = Reflect.get(panel, "trafficCheckbox", TriStateCheckBox.class);

        ConfigState.State imported = new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of(),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                null);

        SwingUtilities.invokeAndWait(() -> panel.onImportResult(imported));

        assertThat(trafficCheckbox.getState()).isEqualTo(TriStateCheckBox.State.DESELECTED);
    }

    @Test
    void import_withPartialExporterChildren_setsExporterParentToIndeterminate() throws Exception {
        ConfigPanel panel = createPanel();

        TriStateCheckBox exporterCheckbox = Reflect.get(panel, "exporterCheckbox", TriStateCheckBox.class);

        // Two of the seven exporter sub-options selected.
        ConfigState.State imported = new ConfigState.State(
                List.of("exporter"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of(),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                List.of("error", "stats"),
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                null);

        SwingUtilities.invokeAndWait(() -> panel.onImportResult(imported));

        assertThat(exporterCheckbox.getState()).isEqualTo(TriStateCheckBox.State.INDETERMINATE);
    }

    private static ConfigPanel createPanel() throws Exception {
        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ConfigPanel panel = new ConfigPanel(new ConfigController(new NoopUi()));
            panel.setSize(1000, 700);
            panel.doLayout();
            ref.set(panel);
        });
        return ref.get();
    }

    private static final class NoopUi implements ConfigController.Ui {
        @Override public void onFileStatus(String message) {}
        @Override public void onDatabaseStatus(String message) {}
        @Override public void onControlStatus(String message) {}
    }
}
