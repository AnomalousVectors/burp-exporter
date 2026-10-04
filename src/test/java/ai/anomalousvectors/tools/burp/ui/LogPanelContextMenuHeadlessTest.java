package ai.anomalousvectors.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;

import static ai.anomalousvectors.tools.burp.ui.LogPanelTestHarness.*;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Validates context menu composition without invoking system clipboard (headless-safe).
 */
class LogPanelContextMenuHeadlessTest {

    @Test
    void contextMenu_containsExpectedItems_inOrder() {
        LogPanel p = newPanel();
        JPopupMenu menu = buildContextMenuViaReflection(p);

        // Expected items:
        // 0: "Copy selection"
        // 1: "Copy current line"
        // 2: "Copy all"
        assertThat(menu.getComponentCount()).isEqualTo(3);

        JMenuItem i0 = (JMenuItem) menu.getComponent(0);
        JMenuItem i1 = (JMenuItem) menu.getComponent(1);
        JMenuItem i2 = (JMenuItem) menu.getComponent(2);

        assertThat(i0.getText()).isEqualTo("Copy selection");
        assertThat(i1.getText()).isEqualTo("Copy current line");
        assertThat(i2.getText()).isEqualTo("Copy all");
    }
}
