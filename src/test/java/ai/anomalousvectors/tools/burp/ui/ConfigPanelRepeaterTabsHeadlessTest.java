package ai.anomalousvectors.tools.burp.ui;

import java.awt.Component;
import java.awt.Container;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.testutils.Reflect;
import ai.anomalousvectors.tools.burp.ui.controller.ConfigController;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;

class ConfigPanelRepeaterTabsHeadlessTest {

    @Test
    void repeaterTabsTrafficOption_defaultsDisabled_withTooltip_andPersistsWhenEnabled() throws Exception {
        ConfigPanel panel = createPanel();

        JCheckBox repeaterTabsCheckbox = Reflect.get(panel, "trafficRepeaterTabsCheckbox", JCheckBox.class);

        ConfigState.State defaultState = (ConfigState.State) Reflect.call(panel, "buildCurrentState");

        assertThat(repeaterTabsCheckbox.isSelected()).isFalse();
        assertThat(repeaterTabsCheckbox.getToolTipText()).contains("Historic traffic from Repeater tabs");
        assertThat(repeaterTabsCheckbox.getToolTipText()).contains("one-time snapshot when Start is clicked");
        assertThat(repeaterTabsCheckbox.getToolTipText()).contains("best-effort Repeater tab and group labels");
        assertThat(repeaterTabsCheckbox.getToolTipText()).contains("For ongoing and future Repeater traffic, select Repeater");
        assertThat(repeaterTabsCheckbox.getToolTipText()).doesNotContain("may miss");
        assertThat(repeaterTabsCheckbox.getToolTipText()).doesNotContain("enable or disable each one independently");
        assertThat(repeaterTabsCheckbox.getToolTipText()).doesNotContain("frozen or unresponsive");
        assertThat(defaultState.trafficToolTypes()).doesNotContain("repeater_tabs");

        SwingUtilities.invokeAndWait(() -> repeaterTabsCheckbox.setSelected(true));
        ConfigState.State enabledState = (ConfigState.State) Reflect.call(panel, "buildCurrentState");
        assertThat(enabledState.trafficToolTypes()).contains("repeater_tabs");
    }

    @Test
    void repeaterTabsInfoNotice_isVisible_withStartupFreezeWarningTooltip() throws Exception {
        ConfigPanel panel = createPanel();

        JPanel notice = findByName(panel, "src.traffic.repeater_tabs.infoNotice", JPanel.class);
        JLabel icon = findByName(panel, "src.traffic.repeater_tabs.infoNotice.icon", JLabel.class);

        assertThat(notice).isNotNull();
        assertThat(notice.isVisible()).isTrue();
        assertThat(icon).isNotNull();
        assertThat(icon.getToolTipText()).contains("Repeater Tabs startup");
        assertThat(icon.getToolTipText()).contains("Montoya API");
        assertThat(icon.getToolTipText()).contains("EDT");
        assertThat(icon.getToolTipText()).contains("After start, Burp may appear frozen or unresponsive while the walk runs");
        assertThat(icon.getToolTipText()).contains("10-30 seconds");
        assertThat(icon.getToolTipText()).contains("walk runs twice");
        assertThat(icon.getToolTipText()).contains("correlated");
        assertThat(icon.getToolTipText()).doesNotContain("officially expose");
        assertThat(icon.getToolTipText()).doesNotContain("Live Repeater traffic is separate");
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

    private static <T extends Component> T findByName(Container root, String name, Class<T> type) {
        if (name.equals(root.getName()) && type.isInstance(root)) {
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

    private static final class NoopUi implements ConfigController.Ui {
        @Override public void onFileStatus(String message) {}
        @Override public void onDatabaseStatus(String message) {}
        @Override public void onControlStatus(String message) {}
    }
}
