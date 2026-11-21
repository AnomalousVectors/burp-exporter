package ai.anomalousvectors.tools.burp.ui;

import static org.assertj.core.api.Assertions.assertThat;

import java.awt.Component;

import javax.swing.JLabel;
import javax.swing.JButton;

import org.junit.jupiter.api.Test;

class LogPanelTooltipHeadlessTest {
    @Test
    void copyHelpExplainsSelectionAndVisibleText() {
        LogPanel panel = LogPanelTestHarness.newPanel();
        JButton copy = (JButton) LogPanelTestHarness.findBy(panel,
                component -> "log.copy".equals(component.getName()));
        assertThat(copy.getToolTipText()).contains("selected text", "all visible log text");
    }


    @Test
    void toolbarLabels_and_searchCount_have_expected_tooltips() {
        LogPanel panel = LogPanelTestHarness.newPanel();

        JLabel minLevelLabel = (JLabel) LogPanelTestHarness.findBy(panel,
                component -> component instanceof JLabel label && "Min level:".equals(label.getText()));
        JLabel filterLabel = (JLabel) LogPanelTestHarness.findBy(panel,
                component -> component instanceof JLabel label && "Filter:".equals(label.getText()));
        JLabel findLabel = (JLabel) LogPanelTestHarness.findBy(panel,
                component -> component instanceof JLabel label && "Find:".equals(label.getText()));
        Component searchCount = LogPanelTestHarness.findBy(panel,
                component -> component instanceof JLabel label && "log.search.count".equals(label.getName()));

        assertThat(minLevelLabel.getToolTipText()).isEqualTo("<html>Choose the minimum log level shown in the pane.</html>");
        assertThat(filterLabel.getToolTipText()).isEqualTo("<html>Filter visible log entries by plain text or regex.</html>");
        assertThat(findLabel.getToolTipText()).isEqualTo("<html>Search within the visible log entries.</html>");
        assertThat(((JLabel) searchCount).getToolTipText())
                .isEqualTo("<html>Current match and total matches for the active Find query.</html>");
    }
}
