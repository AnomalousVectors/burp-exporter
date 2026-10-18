package ai.anomalousvectors.tools.burp.ui.primitives;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import ai.anomalousvectors.tools.burp.ui.text.RegexIndicatorBinder;
import ai.anomalousvectors.tools.burp.ui.text.Tooltips;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.ConfigImportPolicy;
import net.miginfocom.swing.MigLayout;

/**
 * Custom scope entries grid:
 * - Col 1: text field (size-grouped)
 * - Col 2: ".*" toggle + ✓/✖ indicator
 * - Col 3: action button (Add on row 1, Delete on rows > 1)
 *
 * <p><strong>EDT:</strong> Public mutators expect to be called on the EDT.</p>
 */
public final class ScopeGrid extends JPanel {

    @Serial private static final long serialVersionUID = 1L;

    /**
     * Max number of rows permitted. The Add button disables at this limit.
     */
    private static final String TIP_ADD_ROW     = Tooltips.html("Add new row.");
    private static final String TIP_SCOPE_ENTRY = Tooltips.html("Scope entry.", "Enter a plain string or regular expression.");
    private static final String TIP_REGEX_TOGGLE = Tooltips.html("Interpret value as a regular expression.");
    private static final String TIP_DELETE_ROW  = Tooltips.html("Delete this row.");

    /**
     * Initial row seed for a custom entry.
     */
    public record ScopeEntryInit(String value, boolean regex) implements Serializable {
        @Serial private static final long serialVersionUID = 1L;
    }

    private final ArrayList<Row> rows = new ArrayList<>();
    private final JButton addButton = new Tooltips.HtmlButton("Add");

    /**
     * Tracks external enable/disable state to combine with the MAX_ROWS rule.
     */
    private boolean enabled = true;

    /**
     * Optional callback when any scope entry field or regex toggle changes.
     * Not serialized; set after construction by the owning panel.
     */
    private transient Runnable onContentChange;
    /** Rebuilds non-serializable row listeners before a restored grid becomes displayable. */
    private transient boolean rebuildAfterDeserialization;

    /**
     * Constructs the grid with optional seed entries.
     *
     * @param initial ordered initial entries; blank row created when {@code null} or empty
     */
    public ScopeGrid(List<ScopeEntryInit> initial) {
        super(new MigLayout(
                "insets 0, gapx 20, gapy 6",
                "[fill,grow,sg tf]20[]20[sg btn,left]"));
        requireDisplayableEntryCount(initial);
        if (initial == null || initial.isEmpty()) {
            rows.add(new Row("", true)); // default: regex ON
        } else {
            for (ScopeEntryInit se : initial) {
                rows.add(new Row(Objects.requireNonNullElse(se.value(), ""), se.regex()));
            }
        }

        addButton.setName("scope.custom.add");
        ButtonStyles.normalize(addButton);
        Tooltips.apply(addButton, TIP_ADD_ROW);
        bindAddAction();

        rebuild();
    }

    /** Wires the transient Add action after construction or deserialization. */
    private void bindAddAction() {
        addButton.addActionListener(e -> {
            if (rows.size() < ConfigImportPolicy.MAX_CUSTOM_SCOPE_ENTRIES) {
                rows.add(new Row("", true)); // new rows default to regex ON
                rebuild();
            }
            // No else: silently ignore beyond cap (button is disabled anyway when at cap)
        });

    }

    /**
     * Current text values across rows (in order).
     *
     * @return list of row values
     */
    public List<String> values() {
        List<String> out = new ArrayList<>(rows.size());
        for (Row r : rows) out.add(r.field.getText());
        return out;
    }

    /**
     * Current kinds across rows (in order).
     *
     * @return list of regex flags ({@code true} means regex)
     */
    public List<Boolean> regexKinds() {
        List<Boolean> out = new ArrayList<>(rows.size());
        for (Row r : rows) out.add(r.toggle.isSelected());
        return out;
    }

    /**
     * Replaces all rows with the provided entries.
     *
     * <p>A single blank row is created when {@code null} or empty.</p>
     *
     * @param entries new entries to apply
     */
    public void setEntries(List<ScopeEntryInit> entries) {
        requireDisplayableEntryCount(entries);
        rows.clear();
        if (entries == null || entries.isEmpty()) {
            rows.add(new Row("", true));
        } else {
            for (ScopeEntryInit se : entries) {
                rows.add(new Row(Objects.requireNonNullElse(se.value(), ""), se.regex()));
            }
        }
        rebuild();
    }

    private static void requireDisplayableEntryCount(List<ScopeEntryInit> entries) {
        if (entries != null && entries.size() > ConfigImportPolicy.MAX_CUSTOM_SCOPE_ENTRIES) {
            throw new IllegalArgumentException("Custom scope has " + entries.size()
                    + " entries; maximum is " + ConfigImportPolicy.MAX_CUSTOM_SCOPE_ENTRIES + ".");
        }
    }

    /**
     * Enables/disables the entire grid (fields, toggles, Add/Delete).
     *
     * <p>The Add button remains constrained by the shared custom-scope entry limit.</p>
     *
     * @param enabled whether controls should be enabled
     */
    @Override
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        applyEnablement();
    }

    /**
     * Sets a callback invoked when any scope entry field or regex toggle changes.
     * Used so the config panel can push custom scope changes to {@link
     * ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig} without requiring a separate
     * button click.
     *
     * @param runnable callback to run on content change; {@code null} to clear
     */
    public void setOnContentChange(Runnable runnable) {
        this.onContentChange = runnable;
    }

    /**
     * Restores Add and row action listeners before a deserialized grid is attached to Swing.
     *
     * <p>Caller must invoke on the EDT. Each restored grid is rewired only once.</p>
     */
    @Override
    public void addNotify() {
        if (rebuildAfterDeserialization) {
            rebuildAfterDeserialization = false;
            bindAddAction();
            rebuild();
        }
        super.addNotify();
    }

    private void fireContentChange() {
        if (onContentChange != null) {
            onContentChange.run();
        }
    }

    /* ---------------- internal ---------------- */

    /**
     * Rebuilds the visual rows.
     *
     * <p>Caller must invoke on the EDT.</p>
     */
    private void rebuild() {
        removeAll();

        for (int i = 0; i < rows.size(); i++) {
            Row r = rows.get(i);
            r.assignNamesForIndex(i + 1);
            r.attachContentChangeListener(this::fireContentChange);

            assignRowToolTips(r);

            // Common part: field + toggle + indicator
            add(r.field, "sg tf, growx"); // col 1
            add(r.toggle, "split 2");     // col 2
            add(r.indicator);

            if (i == 0) {
                // Row 1 has Add
                add(addButton, "sg btn"); // col 3
            } else {
                // Rows > 1 have Delete
                r.ensureDeleteHandler(() -> {
                    rows.remove(r);
                    rebuild();
                });
                add(r.delete, "sg btn");  // col 3
            }

            add(new JLabel(), "wrap");
        }

        applyEnablement();
        revalidate();
        repaint();
    }

    /**
     * Ensures row-level tooltips are applied consistently.
     *
     * @param r row to update
     */
    private static void assignRowToolTips(Row r) {
        Tooltips.apply(r.field, TIP_SCOPE_ENTRY);
        ensureToggleTextAndTip(r);
        Tooltips.apply(r.delete, TIP_DELETE_ROW);
    }

    /**
     * Applies enablement state to all row components.
     */
    private void applyEnablement() {
        boolean canAdd = enabled && rows.size() < ConfigImportPolicy.MAX_CUSTOM_SCOPE_ENTRIES;
        addButton.setEnabled(canAdd);
        for (int i = 0; i < rows.size(); i++) {
            Row r = rows.get(i);
            r.field.setEnabled(enabled);
            r.toggle.setEnabled(enabled);
            r.delete.setEnabled(enabled && i > 0);
        }
    }

    /**
     * Standardizes toggle text and tooltip.
     *
     * @param r row to adjust
     */
    private static void ensureToggleTextAndTip(Row r) {
        if (!".*".equals(r.toggle.getText())) r.toggle.setText(".*");
        Tooltips.apply(r.toggle, TIP_REGEX_TOGGLE);
    }

    /** Row model: text field, toggle, indicator, and (rows &gt; 1) a Delete button. */
    private static final class Row implements Serializable {
        @Serial private static final long serialVersionUID = 1L;

        private final JTextField field = new Tooltips.HtmlTextField();
        private final JCheckBox  toggle = new Tooltips.HtmlCheckBox(".*");
        private final JLabel     indicator = new Tooltips.HtmlLabel(""); // ✓ / ✖ glyph
        private final JButton    delete = new Tooltips.HtmlButton("Delete");
        private transient AutoCloseable binding;
        private boolean deleteBound;
        private boolean contentChangeListenerAttached;

        /**
         * Creates a row with provided value and regex flag.
         *
         * @param value    initial field text
         * @param isRegex  whether regex toggle is selected
         */
        Row(String value, boolean isRegex) {
            field.setText(value);
            toggle.setSelected(isRegex);
            ButtonStyles.normalize(delete);
            binding = RegexIndicatorBinder.bind(field, toggle, null, false, indicator);
        }

        /** Recreates the regex binding and lets the owning grid restore row action listeners. */
        @Serial
        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            binding = RegexIndicatorBinder.bind(field, toggle, null, false, indicator);
            deleteBound = false;
            contentChangeListenerAttached = false;
        }

        /**
         * Attaches a listener so that any change to the field or toggle invokes the runnable.
         * Idempotent: only attaches once per row.
         */
        void attachContentChangeListener(Runnable onContentChange) {
            if (contentChangeListenerAttached || onContentChange == null) {
                return;
            }
            contentChangeListenerAttached = true;
            field.getDocument().addDocumentListener(new DocumentListener() {
                @Override
                public void insertUpdate(DocumentEvent e) { onContentChange.run(); }
                @Override
                public void removeUpdate(DocumentEvent e) { onContentChange.run(); }
                @Override
                public void changedUpdate(DocumentEvent e) { onContentChange.run(); }
            });
            toggle.addItemListener(e -> onContentChange.run());
        }

        /**
         * Assigns deterministic component names for headless tests.
         *
         * @param index1 1-based row index
         */
        void assignNamesForIndex(int index1) {
            if (index1 == 1) {
                field.setName("scope.custom.regex");
                toggle.setName("scope.custom.toggle");
            } else {
                field.setName("scope.custom.regex." + index1);
                toggle.setName("scope.custom.toggle." + index1);
            }
            indicator.setName("scope.custom.regex.indicator." + index1);
            delete.setName("scope.custom.delete." + index1);
        }

        /**
         * Binds the delete handler once, closing regex binding before removal.
         *
         * @param onDelete callback invoked after cleanup
         */
        void ensureDeleteHandler(Runnable onDelete) {
            if (deleteBound) return;
            deleteBound = true;
            delete.addActionListener(e -> {
                try {
                    if (binding != null) binding.close();
                } catch (Exception ex) {
                    Logger.internalDebug("ScopeGrid.Row: error closing binding: " + ex);
                }
                onDelete.run();
            });
        }
    }

    /** Marks row action listeners for restoration when this grid next joins a display hierarchy. */
    @Serial
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        rebuildAfterDeserialization = true;
    }
}
