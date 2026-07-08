package ai.anomalousvectors.tools.burp.ui;

import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JCheckBox;
import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.testutils.Reflect;
import ai.anomalousvectors.tools.burp.ui.controller.ConfigController;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;

class ConfigPanelRepeaterTabsHeadlessTest {

    @Test
    void repeaterTabsTrafficOption_defaultsEnabled_andPersistsIntoBuiltState() throws Exception {
        ConfigPanel panel = createPanel();

        JCheckBox repeaterTabsCheckbox = Reflect.get(panel, "trafficRepeaterTabsCheckbox", JCheckBox.class);

        ConfigState.State state = (ConfigState.State) Reflect.call(panel, "buildCurrentState");

        assertThat(repeaterTabsCheckbox.isSelected()).isTrue();
        assertThat(repeaterTabsCheckbox.getToolTipText()).contains("Historic traffic from Repeater tabs");
        assertThat(repeaterTabsCheckbox.getToolTipText()).contains("one-time snapshot when Start is clicked");
        assertThat(repeaterTabsCheckbox.getToolTipText()).contains("best-effort Repeater tab and group labels");
        assertThat(repeaterTabsCheckbox.getToolTipText()).contains("For ongoing and future Repeater traffic, select Repeater");
        assertThat(repeaterTabsCheckbox.getToolTipText()).doesNotContain("may miss");
        assertThat(repeaterTabsCheckbox.getToolTipText()).doesNotContain("enable or disable each one independently");
        assertThat(state.trafficToolTypes()).contains("repeater_tabs");
    }

    @Test
    void onImportResult_restoresRepeaterTabsTrafficOption() throws Exception {
        ConfigPanel panel = createPanel();
        JCheckBox repeaterTabsCheckbox = Reflect.get(panel, "trafficRepeaterTabsCheckbox", JCheckBox.class);

        ConfigState.State imported = new ConfigState.State(
                java.util.List.of("traffic"),
                "all",
                java.util.List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                java.util.List.of("proxy", "repeater_tabs"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                null);

        SwingUtilities.invokeAndWait(() -> panel.onImportResult(imported));

        assertThat(repeaterTabsCheckbox.isSelected()).isTrue();
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
