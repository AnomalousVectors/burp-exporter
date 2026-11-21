package ai.anomalousvectors.tools.burp.ui;

import java.awt.Component;
import java.awt.Font;
import java.util.Objects;

import javax.swing.ButtonGroup;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;

import ai.anomalousvectors.tools.burp.ui.primitives.ScopeGrid;
import ai.anomalousvectors.tools.burp.ui.text.Tooltips;
import net.miginfocom.swing.MigLayout;

/**
 * Builds the "Export Scope" section panel used by {@link ConfigPanel}.
 *
 * <p>Components are owned by {@link ConfigPanel} and injected to keep a single source of state.</p>
 */
public final class ConfigScopePanel {

    private final JRadioButton allRadio;
    private final JRadioButton burpRadio;
    private final JRadioButton customRadio;
    private final ScopeGrid grid;
    private final int indentPx;

    private static final String GAPLEFT = "gapleft ";
    private static final String ALIGN_LEFT_TOP = "alignx left, top";

    /**
     * Stores the shared scope controls for later panel assembly on the EDT.
     *
     * @param allRadio all-traffic selection control
     * @param burpRadio Burp-scope selection control
     * @param customRadio custom-scope selection control
     * @param grid custom scope-rule editor
     * @param indentPx horizontal indentation in pixels
     * @throws NullPointerException if any control is {@code null}
     */
    public ConfigScopePanel(
            JRadioButton allRadio,
            JRadioButton burpRadio,
            JRadioButton customRadio,
            ScopeGrid grid,
            int indentPx
    ) {
        this.allRadio = Objects.requireNonNull(allRadio, "allRadio");
        this.burpRadio = Objects.requireNonNull(burpRadio, "burpRadio");
        this.customRadio = Objects.requireNonNull(customRadio, "customRadio");
        this.grid = Objects.requireNonNull(grid, "grid");
        this.indentPx = indentPx;
    }

    /**
     * Builds the Scope section UI containing header, radios, and the custom grid row.
     *
     * <p>Caller must invoke on the EDT. Layout mirrors other sections (Sources/Destination/Control) and
     * aligns the grid's field column with Destination (first column 150!, gap 20).</p>
     *
     * @return assembled panel with scope controls and custom grid
     */
    public JPanel build() {
        JPanel panel = new JPanel(new MigLayout("insets 0, wrap 1", "[left]", ""));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel title = Tooltips.label("Export Scope",
                Tooltips.html("Configure the export scope."));
        title.setFont(title.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(title, "gapbottom 6");

        // Group radios
        ButtonGroup group = new ButtonGroup();
        group.add(allRadio);
        group.add(burpRadio);
        group.add(customRadio);

        // Burp radio (indented)
        panel.add(burpRadio, GAPLEFT + indentPx + ", " + ALIGN_LEFT_TOP);

        // Custom row: two columns — [150!, left]20[grid (fields)]
        JPanel customRow = new JPanel(new MigLayout("insets 0", "[150!,left]20[fill,grow]", ""));
        customRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        customRow.add(customRadio, GAPLEFT + indentPx + ", " + ALIGN_LEFT_TOP);
        customRow.add(grid, "growx");
        panel.add(customRow, "growx");

        // All radio (indented)
        panel.add(allRadio, GAPLEFT + indentPx + ", " + ALIGN_LEFT_TOP);

        // UI-only enablement: grid active only when Custom is selected
        Runnable refresh = () -> grid.setEnabled(customRadio.isSelected());
        customRadio.addItemListener(e -> refresh.run());
        burpRadio.addItemListener(e -> refresh.run());
        allRadio.addItemListener(e -> refresh.run());
        refresh.run(); // initial

        return panel;
    }
}
