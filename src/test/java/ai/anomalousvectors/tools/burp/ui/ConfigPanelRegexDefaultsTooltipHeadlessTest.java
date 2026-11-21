package ai.anomalousvectors.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JComponent;
import javax.swing.JRadioButton;
import javax.swing.JCheckBox;
import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies each newly added row has regex toggle selected by default,
 * and the regex toggle includes the expected HTML tooltip.
 */
class ConfigPanelRegexDefaultsTooltipHeadlessTest {

    @Test
    void regex_default_on_and_tooltip_present() throws Exception {
        ConfigPanel panel = new ConfigPanel();

        // Enable Custom, then add two rows
        JRadioButton custom = findByName(panel, "scope.custom", JRadioButton.class);
        runEdt(() -> custom.setSelected(true));
        findByName(panel, "scope.custom.add", javax.swing.JButton.class).doClick();
        findByName(panel, "scope.custom.add", javax.swing.JButton.class).doClick();

        List<JCheckBox> toggles = findToggles(panel);
        assertThat(toggles).hasSize(3);
        for (JCheckBox cb : toggles) {
            assertThat(cb.isSelected()).isTrue();
            assertThat(cb.getToolTipText()).contains("regular expression", "anchors", "exact host match");
        }
    }

    // ---------- helpers ----------

    private static List<JCheckBox> findToggles(JComponent root) {
        List<JCheckBox> out = new ArrayList<>();
        collect(root, JCheckBox.class, out);
        out.removeIf(x -> x.getName() == null || !x.getName().startsWith("scope.custom.toggle"));
        return out;
    }

    private static <T extends JComponent> T findByName(JComponent root, String name, Class<T> type) {
        List<T> all = new ArrayList<>();
        collect(root, type, all);
        for (T c : all) if (name.equals(c.getName())) return c;
        throw new AssertionError("Component not found: " + name + " (" + type.getSimpleName() + ")");
    }

    private static <T extends JComponent> void collect(JComponent root, Class<T> type, List<T> out) {
        if (type.isInstance(root)) out.add(type.cast(root));
        for (var comp : root.getComponents()) if (comp instanceof JComponent jc) collect(jc, type, out);
    }

    private static void runEdt(Runnable r) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) r.run();
        else SwingUtilities.invokeAndWait(r);
    }
}
