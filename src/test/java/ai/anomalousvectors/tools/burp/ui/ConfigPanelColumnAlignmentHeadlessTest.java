package ai.anomalousvectors.tools.burp.ui;

import java.awt.Component;
import java.awt.Container;
import java.awt.Rectangle;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Asserts column alignment: all text fields share the same left x, and all buttons share the same left x.
 */
class ConfigPanelColumnAlignmentHeadlessTest {

    @Test
    void fields_and_buttons_share_left_edge_across_rows() throws Exception {
        ConfigPanel panel = new ConfigPanel();

        // Enable Custom and add rows
        JRadioButton custom = findByName(panel, "scope.custom", JRadioButton.class);
        runEdt(() -> custom.setSelected(true));
        JButton add = findByName(panel, "scope.custom.add", JButton.class);
        runEdt(() -> { add.doClick(); add.doClick(); });

        layoutPanel(panel);

        List<JTextField> fields = findFieldsSorted(panel);
        int fx = bounds(fields.getFirst()).x;
        for (JTextField f : fields) assertThat(bounds(f).x).isEqualTo(fx);

        List<JButton> dels = findDeletes(panel);
        if (!dels.isEmpty()) {
            int bx = bounds(dels.getFirst()).x;
            for (JButton b : dels) assertThat(bounds(b).x).isEqualTo(bx);
        }
    }

    @Test
    void destination_path_fields_share_left_edge() throws Exception {
        ConfigPanel panel = new ConfigPanel();
        layoutPanel(panel);

        JTextField filesPath = findByName(panel, "files.path", JTextField.class);
        JTextField openSearchUrl = findByName(panel, "os.url", JTextField.class);
        JTextField openSearchAmazonUrl = findByName(panel, "os.amazon.url", JTextField.class);
        JTextField elasticSearchUrl = findByName(panel, "os.elasticsearch.url", JTextField.class);
        JCheckBox database = findByName(panel, "database.enable", JCheckBox.class);
        JRadioButton openSearch = findByName(panel, "os.destination.openSearch", JRadioButton.class);
        JRadioButton openSearchAmazon = findByName(panel, "os.destination.amazon", JRadioButton.class);
        JRadioButton elasticSearch = findByName(panel, "os.destination.elasticsearch", JRadioButton.class);
        assertThat(openSearchAmazon.getParent()).isSameAs(elasticSearch.getParent());
        assertThat(openSearch.getParent()).isSameAs(openSearchAmazon.getParent());
        assertThat(openSearchAmazon.getParent().getComponentZOrder(openSearchAmazon))
                .isLessThan(openSearchAmazon.getParent().getComponentZOrder(elasticSearch));
        assertThat(elasticSearch.getParent().getComponentZOrder(elasticSearch))
                .isLessThan(elasticSearch.getParent().getComponentZOrder(openSearch));

        assertThat(absoluteX(filesPath)).isEqualTo(absoluteX(openSearchUrl));
        assertThat(openSearchUrl.isVisible()).isTrue();
        assertThat(openSearchAmazonUrl.isVisible()).isFalse();
        assertThat(elasticSearchUrl.isVisible()).isFalse();

        int expectedRadioDelta = 42;
        assertThat(absoluteX(openSearch) - absoluteX(database)).isEqualTo(expectedRadioDelta);

        runEdt(() -> openSearchAmazon.doClick());
        layoutPanel(panel);
        assertThat(openSearch.isSelected()).isFalse();
        assertThat(openSearchAmazon.isSelected()).isTrue();
        assertThat(absoluteX(filesPath)).isEqualTo(absoluteX(openSearchAmazonUrl));
        assertThat(absoluteX(openSearchAmazon) - absoluteX(database)).isEqualTo(expectedRadioDelta);
        assertThat(absoluteRight(openSearchAmazon)).isLessThan(absoluteX(openSearchAmazonUrl));
        assertThat(openSearchUrl.isVisible()).isFalse();
        assertThat(openSearchAmazonUrl.isVisible()).isTrue();
        assertThat(elasticSearchUrl.isVisible()).isFalse();

        runEdt(() -> elasticSearch.doClick());
        layoutPanel(panel);
        assertThat(openSearchAmazon.isSelected()).isFalse();
        assertThat(elasticSearch.isSelected()).isTrue();
        assertThat(absoluteX(filesPath)).isEqualTo(absoluteX(elasticSearchUrl));
        assertThat(absoluteX(elasticSearch) - absoluteX(database)).isEqualTo(expectedRadioDelta);
        assertThat(openSearchUrl.isVisible()).isFalse();
        assertThat(openSearchAmazonUrl.isVisible()).isFalse();
        assertThat(elasticSearchUrl.isVisible()).isTrue();
    }

    @Test
    void file_format_options_render_jsonl_before_ndjson() throws Exception {
        ConfigPanel panel = new ConfigPanel();
        layoutPanel(panel);

        JRadioButton jsonl = findByName(panel, "files.format.jsonl", JRadioButton.class);
        JRadioButton ndjson = findByName(panel, "files.format.bulkNdjson", JRadioButton.class);

        assertThat(jsonl.getParent()).isSameAs(ndjson.getParent());
        assertThat(jsonl.getParent().getComponentZOrder(jsonl))
                .isLessThan(jsonl.getParent().getComponentZOrder(ndjson));
    }

    // ---------- helpers ----------

    private static List<JButton> findDeletes(JComponent root) {
        List<JButton> out = new ArrayList<>();
        collect(root, JButton.class, out);
        out.removeIf(b -> b.getName() == null || !b.getName().startsWith("scope.custom.delete."));
        out.sort(Comparator.comparingInt(ConfigPanelColumnAlignmentHeadlessTest::btnIndex));
        return out;
    }

    private static int btnIndex(JButton b) {
        String n = b.getName();
        int dot = n.lastIndexOf('.');
        return dot < 0 ? Integer.MAX_VALUE : Integer.parseInt(n.substring(dot + 1));
    }

    private static Rectangle bounds(JComponent c) { return c.getBounds(); }

    private static void layoutPanel(ConfigPanel panel) throws Exception {
        runEdt(() -> {
            panel.setSize(1000, 800);
            layoutTree(panel);
        });
    }

    private static void layoutTree(Container container) {
        container.doLayout();
        for (Component component : container.getComponents()) {
            if (component instanceof Container child) {
                layoutTree(child);
            }
        }
    }

    private static int absoluteX(Component component) {
        int x = 0;
        Component current = component;
        while (current != null) {
            x += current.getX();
            current = current.getParent();
        }
        return x;
    }

    private static int absoluteRight(Component component) {
        return absoluteX(component) + component.getWidth();
    }

    private static List<JTextField> findFieldsSorted(JComponent root) {
        List<JTextField> out = new ArrayList<>();
        collect(root, JTextField.class, out);
        out.removeIf(x -> x.getName() == null || !x.getName().startsWith("scope.custom.regex"));
        out.sort(Comparator.comparingInt(ConfigPanelColumnAlignmentHeadlessTest::index));
        return out;
    }

    private static int index(JTextField f) {
        String n = f.getName();
        if ("scope.custom.regex".equals(n)) return 1;
        int dot = n.lastIndexOf('.');
        return dot < 0 ? Integer.MAX_VALUE : Integer.parseInt(n.substring(dot + 1));
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
