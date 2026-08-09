package ai.anomalousvectors.tools.burp.ui;

import java.util.prefs.Preferences;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JTextField;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import static ai.anomalousvectors.tools.burp.ui.LogPanelTestHarness.button;
import static ai.anomalousvectors.tools.burp.ui.LogPanelTestHarness.check;
import static ai.anomalousvectors.tools.burp.ui.LogPanelTestHarness.click;
import static ai.anomalousvectors.tools.burp.ui.LogPanelTestHarness.combo;
import static ai.anomalousvectors.tools.burp.ui.LogPanelTestHarness.field;
import static ai.anomalousvectors.tools.burp.ui.LogPanelTestHarness.newPanel;
import static ai.anomalousvectors.tools.burp.ui.LogPanelTestHarness.setText;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

/**
 * Ensures min-level, pause flag, filter text, and last search query persist across new instances.
 */
class LogPanelPersistenceHeadlessTest {

    @Test
    void defaults_minLevelToInfo_whenPreferenceMissing() {
        Preferences prefs = Preferences.userRoot().node("ai.anomalousvectors.tools.burp.ui.LogPanel");
        prefs.remove("minLevel");

        LogPanel panel = newPanel();
        JComboBox<?> level = combo(panel, "log.filter.level");
        assertThat(level.getSelectedItem()).isEqualTo("INFO");
    }

    @Test
    void persists_minLevel_pause_filterText_lastSearch() {
        // Instance A: set values
        LogPanel a = newPanel();

        JComboBox<?> level = combo(a, "log.filter.level");
        level.setSelectedItem("WARN");

        JButton pause = button(a, "log.pause");
        if (!"Unpause".equals(pause.getText())) {
            click(pause);
        }

        JTextField filter = field(a, "log.filter.text");
        setText(filter, "persist-me");

        JTextField search = field(a, "log.search.field");
        setText(search, "needle");

        // Simulate panel lifecycle end
        a.removeNotify();

        // Instance B: verify restoration
        LogPanel b = newPanel();

        JComboBox<?> levelB = combo(b, "log.filter.level");
        assertThat(levelB.getSelectedItem()).isEqualTo("WARN");

        JButton pauseB = button(b, "log.pause");
        assertThat(pauseB.getText()).isEqualTo("Unpause");

        JTextField filterB = field(b, "log.filter.text");
        assertThat(filterB.getText()).isEqualTo("persist-me");

        JTextField searchB = field(b, "log.search.field");
        assertThat(searchB.getText()).isEqualTo("needle");
    }

    @Test
    void persists_filterNegative_acrossPanelInstances() {
        LogPanel a = newPanel();
        JCheckBox filterNegative = check(a, "log.filter.negative");
        if (!filterNegative.isSelected()) {
            click(filterNegative);
        }
        a.removeNotify();

        LogPanel b = newPanel();
        JCheckBox restored = check(b, "log.filter.negative");
        assertThat(restored.isSelected()).isTrue();
    }

    @Test
    void ui_changes_update_runtime_config_log_panel_preferences() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            LogPanel panel = newPanel();

            JComboBox<?> level = combo(panel, "log.filter.level");
            level.setSelectedItem("ERROR");

            JButton pause = button(panel, "log.pause");
            if (!"Unpause".equals(pause.getText())) {
                click(pause);
            }

            setText(field(panel, "log.filter.text"), "opensearch");
            JCheckBox filterRegex = check(panel, "log.filter.regex");
            if (!filterRegex.isSelected()) click(filterRegex);
            JCheckBox filterNegative = check(panel, "log.filter.negative");
            if (!filterNegative.isSelected()) click(filterNegative);
            setText(field(panel, "log.search.field"), "traffic");

            ConfigState.LogPanelPreferences preferences = RuntimeConfig.logPanelPreferences();
            assertThat(preferences.minLevel()).isEqualTo("error");
            assertThat(preferences.pauseAutoscroll()).isTrue();
            assertThat(preferences.filterText()).isEqualTo("opensearch");
            assertThat(preferences.filterRegex()).isTrue();
            assertThat(preferences.filterNegative()).isTrue();
            assertThat(preferences.searchText()).isEqualTo("traffic");
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }
}
