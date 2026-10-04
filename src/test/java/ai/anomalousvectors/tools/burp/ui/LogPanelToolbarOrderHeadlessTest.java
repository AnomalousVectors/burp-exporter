package ai.anomalousvectors.tools.burp.ui;

import static org.assertj.core.api.Assertions.assertThat;

import java.awt.Component;
import java.awt.Container;
import java.util.Arrays;
import java.util.List;

import javax.swing.JButton;

import org.junit.jupiter.api.Test;

class LogPanelToolbarOrderHeadlessTest {

    @Test
    void toolbarOrdersCopyBeforeClear_withoutVerticalSeparators() {
        LogPanel panel = LogPanelTestHarness.newPanel();

        JButton copy = LogPanelTestHarness.button(panel, "log.copy");
        JButton clear = LogPanelTestHarness.button(panel, "log.clear");
        JButton pause = LogPanelTestHarness.button(panel, "log.pause");

        assertThat(pause.getText()).isIn("Pause", "Unpause");

        Container actionSection = copy.getParent();
        List<Component> actionComponents = Arrays.asList(actionSection.getComponents());
        assertThat(actionComponents).containsExactly(copy);

        Container trailingSection = pause.getParent();
        assertThat(trailingSection).isSameAs(clear.getParent());
        List<Component> trailingComponents = Arrays.asList(trailingSection.getComponents());
        assertThat(trailingComponents.indexOf(pause)).isLessThan(trailingComponents.indexOf(clear));

        Container toolbar = trailingSection.getParent();
        assertThat(actionSection.getParent()).isSameAs(toolbar);
        List<Component> toolbarComponents = Arrays.asList(toolbar.getComponents());
        assertThat(toolbarComponents.indexOf(actionSection)).isLessThan(toolbarComponents.indexOf(trailingSection));
        assertThat(toolbarComponents).noneMatch(javax.swing.JSeparator.class::isInstance);
        assertThat(toolbarComponents).hasSize(9);
    }

    @Test
    void pauseButtonWidthStableWhenToggled() {
        LogPanel panel = LogPanelTestHarness.newPanel();
        JButton pause = LogPanelTestHarness.button(panel, "log.pause");
        int width = pause.getPreferredSize().width;
        LogPanelTestHarness.click(pause);
        assertThat(pause.getPreferredSize().width).isEqualTo(width);
        LogPanelTestHarness.click(pause);
        assertThat(pause.getPreferredSize().width).isEqualTo(width);
    }
}
