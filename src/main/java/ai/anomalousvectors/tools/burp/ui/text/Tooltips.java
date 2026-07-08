package ai.anomalousvectors.tools.burp.ui.text;

import java.awt.Component;
import java.awt.Container;
import java.awt.Point;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.Popup;
import javax.swing.PopupFactory;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.JToolTip;
import javax.swing.SwingUtilities;
import javax.swing.ToolTipManager;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.plaf.basic.BasicComboPopup;

/**
 * Shared tooltip helpers so panels use consistent formatting.
 */
public final class Tooltips {
    private static final String HTML_DISABLE = "html.disable";
    private static final String TOOLTIP_FORWARDER_KEY = Tooltips.class.getName() + ".tooltipForwarder";
    private static final int STRUCTURED_TOOLTIP_THRESHOLD = 120;

    /** Hover delay before showing a tooltip (initial and when moving to another control). */
    public static final int TOOLTIP_SHOW_DELAY_MS = 100;

    private Tooltips() {}

    /**
     * Configures the JVM-wide {@link ToolTipManager} for consistent hover behavior across every
     * extension panel (Config, Log, Stats, About).
     *
     * <p>Invoked once from {@link ai.anomalousvectors.tools.burp.Exporter#initialize}. Tooltips appear
     * after {@link #TOOLTIP_SHOW_DELAY_MS} ms on first hover and when moving to another control.
     * They stay visible while the cursor remains over the hover target ({@code dismissDelay} is
     * effectively unlimited).</p>
     */
    public static void configureSharedToolTipManager() {
        ToolTipManager manager = ToolTipManager.sharedInstance();
        manager.setInitialDelay(TOOLTIP_SHOW_DELAY_MS);
        manager.setReshowDelay(TOOLTIP_SHOW_DELAY_MS);
        manager.setDismissDelay(Integer.MAX_VALUE);
    }

    public static JToolTip createHtmlToolTip(JComponent owner) {
        JToolTip toolTip = new JToolTip();
        toolTip.putClientProperty(HTML_DISABLE, Boolean.FALSE);
        toolTip.setComponent(owner);
        return toolTip;
    }

    public static final class HtmlLabel extends JLabel {
        public HtmlLabel(String text) {
            super(text);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        public HtmlLabel(String text, int horizontalAlignment) {
            super(text, horizontalAlignment);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        @Override
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
        }
    }

    /**
     * {@link JPanel} variant whose {@link JToolTip} is configured to render HTML so callers can
     * pass tooltips produced by {@link #htmlRaw(String...)} / {@link #html(String...)}. Plain
     * {@code JPanel} produces a default {@code JToolTip} without the {@code html.disable=FALSE}
     * client property, which causes Swing to render HTML markup as literal text.
     */
    public static final class HtmlPanel extends JPanel {
        public HtmlPanel() {
            super();
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        public HtmlPanel(java.awt.LayoutManager layout) {
            super(layout);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        @Override
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
        }
    }

    public static final class HtmlButton extends JButton {
        public HtmlButton(String text) {
            super(text);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        @Override
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
        }
    }

    public static class HtmlCheckBox extends JCheckBox {
        public HtmlCheckBox(String text, boolean selected) {
            super(text, selected);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        public HtmlCheckBox(String text) {
            super(text);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        @Override
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
        }
    }

    public static final class HtmlRadioButton extends JRadioButton {
        public HtmlRadioButton(String text) {
            super(text);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        public HtmlRadioButton(String text, boolean selected) {
            super(text, selected);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        @Override
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
        }
    }

    public static final class HtmlTextField extends JTextField {
        public HtmlTextField() {
            super();
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        @Override
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
        }
    }

    public static final class HtmlPasswordField extends JPasswordField {
        public HtmlPasswordField() {
            super();
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        @Override
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
        }
    }

    public static final class HtmlComboBox<E> extends JComboBox<E> {
        public HtmlComboBox(E[] items) {
            super(items);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        @Override
        public void addNotify() {
            super.addNotify();
            syncChildTooltips();
        }

        @Override
        public void updateUI() {
            super.updateUI();
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
            syncChildTooltips();
        }

        @Override
        public void setToolTipText(String text) {
            super.setToolTipText(text);
            syncChildTooltips();
        }

        @Override
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
        }

        /**
         * Mirrors HTML tooltip ownership to child widgets such as the combo arrow button.
         *
         * <p>Swing copies tooltip text to combo children, but it does not copy this helper's HTML
         * client-property setup. Refresh after UI install and tooltip updates so every hover target
         * within the combo renders the same HTML tooltip.</p>
         */
        private void syncChildTooltips() {
            Runnable sync = () -> applyHtmlTooltipToChildren(this, this, getToolTipText());
            if (isDisplayable()) {
                SwingUtilities.invokeLater(sync);
            } else {
                sync.run();
            }
        }
    }

    /**
     * Combo box that exposes HTML tooltips for individual popup items.
     *
     * <p>The selected value has no tooltip because the popup list already exposes item help.
     * Popup rows use a small owned tooltip popup so long HTML descriptions render consistently
     * across look-and-feel popup lists that otherwise display markup as literal text.</p>
     *
     * @param <E> combo item type
     */
    public static final class ItemTooltipComboBox<E> extends JComboBox<E> {
        private final Map<Object, String> itemTooltips;
        private transient Popup itemTooltipPopup;
        private transient JList<?> popupList;
        private transient MouseAdapter popupTooltipHandler;
        private transient Object popupTooltipValue;

        /**
         * Creates a combo box with item-specific HTML tooltip text.
         *
         * <p>Caller must invoke on the EDT. Tooltip strings may come from {@link #htmlRaw(String...)}
         * or {@link #html(String...)} and are keyed by the same values supplied in {@code items}.</p>
         *
         * @param items visible combo items
         * @param itemTooltips tooltip text by item value
         */
        public ItemTooltipComboBox(E[] items, Map<E, String> itemTooltips) {
            super(items);
            this.itemTooltips = new java.util.HashMap<>(itemTooltips);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
            setRenderer(new TooltipListCellRenderer());
            addPopupMenuListener(new PopupMenuListener() {
                @Override
                public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                    SwingUtilities.invokeLater(ItemTooltipComboBox.this::syncPopupListTooltips);
                }

                @Override
                public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
                    hideItemTooltip();
                }

                @Override
                public void popupMenuCanceled(PopupMenuEvent e) {
                    hideItemTooltip();
                }
            });
            syncSelectedTooltip();
        }

        @Override
        public void setSelectedItem(Object item) {
            super.setSelectedItem(item);
            syncSelectedTooltip();
        }

        @Override
        public void addNotify() {
            super.addNotify();
            syncChildTooltips();
            syncPopupListTooltips();
        }

        @Override
        public void updateUI() {
            super.updateUI();
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
            setRenderer(new TooltipListCellRenderer());
            if (itemTooltips != null) {
                syncSelectedTooltip();
            }
            SwingUtilities.invokeLater(this::syncPopupListTooltips);
        }

        @Override
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
        }

        private void syncSelectedTooltip() {
            setToolTipText(null);
            syncChildTooltips();
        }

        private String tooltipFor(Object value) {
            if (itemTooltips == null) {
                return null;
            }
            return itemTooltips.get(value);
        }

        private void syncChildTooltips() {
            Runnable sync = () -> applyHtmlTooltipToChildren(this, this, getToolTipText());
            if (isDisplayable()) {
                SwingUtilities.invokeLater(sync);
            } else {
                sync.run();
            }
        }

        private void syncPopupListTooltips() {
            if (getUI() == null) {
                return;
            }
            int childCount = getUI().getAccessibleChildrenCount(this);
            for (int i = 0; i < childCount; i++) {
                Object child = getUI().getAccessibleChild(this, i);
                if (child instanceof BasicComboPopup popup) {
                    installPopupListTooltipHandler(popup.getList());
                    return;
                }
            }
        }

        private void installPopupListTooltipHandler(JList<?> list) {
            if (list == null || list == popupList) {
                return;
            }
            uninstallPopupListTooltipHandler();
            popupList = list;
            popupList.putClientProperty(HTML_DISABLE, Boolean.FALSE);
            popupList.setToolTipText(null);
            popupTooltipHandler = new MouseAdapter() {
                @Override
                public void mouseMoved(MouseEvent e) {
                    int index = popupList.locationToIndex(e.getPoint());
                    if (index < 0) {
                        hideItemTooltip();
                        return;
                    }
                    Object value = popupList.getModel().getElementAt(index);
                    showItemTooltip(popupList, e, value, tooltipFor(value));
                }

                @Override
                public void mouseExited(MouseEvent e) {
                    hideItemTooltip();
                }
            };
            popupList.addMouseListener(popupTooltipHandler);
            popupList.addMouseMotionListener(popupTooltipHandler);
        }

        private void uninstallPopupListTooltipHandler() {
            if (popupList != null && popupTooltipHandler != null) {
                popupList.removeMouseListener(popupTooltipHandler);
                popupList.removeMouseMotionListener(popupTooltipHandler);
            }
            popupList = null;
            popupTooltipHandler = null;
            hideItemTooltip();
        }

        private void showItemTooltip(Component owner, MouseEvent event, Object value, String tooltip) {
            if (tooltip == null || tooltip.isBlank()) {
                hideItemTooltip();
                return;
            }
            if (Objects.equals(value, popupTooltipValue) && itemTooltipPopup != null) {
                return;
            }
            hideItemTooltip();
            popupTooltipValue = value;
            JToolTip toolTip = createHtmlToolTip(this);
            toolTip.setTipText(tooltip);
            Point ownerLocation = owner.getLocationOnScreen();
            itemTooltipPopup = PopupFactory.getSharedInstance().getPopup(
                    owner,
                    toolTip,
                    ownerLocation.x + event.getX() + 12,
                    ownerLocation.y + event.getY() + 18);
            itemTooltipPopup.show();
        }

        private void hideItemTooltip() {
            if (itemTooltipPopup != null) {
                itemTooltipPopup.hide();
                itemTooltipPopup = null;
            }
            popupTooltipValue = null;
        }

        private final class TooltipListCellRenderer extends DefaultListCellRenderer {
            @Override
            public Component getListCellRendererComponent(
                    JList<?> list,
                    Object value,
                    int index,
                    boolean isSelected,
                    boolean cellHasFocus) {
                Component component = super.getListCellRendererComponent(
                        list, value, index, isSelected, cellHasFocus);
                if (component instanceof JComponent jc) {
                    jc.putClientProperty(HTML_DISABLE, Boolean.FALSE);
                    jc.setToolTipText(null);
                }
                list.putClientProperty(HTML_DISABLE, Boolean.FALSE);
                list.setToolTipText(null);
                return component;
            }
        }
    }

    public static <T extends JComponent> T apply(T component, String tooltip) {
        component.putClientProperty(HTML_DISABLE, Boolean.FALSE);
        component.setToolTipText(tooltip);
        return component;
    }

    /**
     * Applies one HTML tooltip to a metric row and each direct child so hover on labels and
     * values uses the same {@link ToolTipManager} delays as {@link #configureSharedToolTipManager()}.
     */
    public static void applyToRow(JPanel row, String tooltip) {
        if (row == null || tooltip == null || tooltip.isBlank()) {
            return;
        }
        apply(row, tooltip);
        for (Component child : row.getComponents()) {
            if (child instanceof JComponent jc) {
                apply(jc, tooltip);
            }
        }
    }

    public static JLabel label(String text, String tooltip) {
        return apply(new HtmlLabel(text), tooltip);
    }

    public static String html(String... lines) {
        String body = Arrays.stream(lines)
                .filter(Objects::nonNull)
                .map(line -> line.trim())
                .filter(line -> !line.isEmpty())
                .map(line -> escapeHtml(line))
                .collect(Collectors.joining("<br>"));
        return body.isEmpty() ? null : "<html>" + body + "</html>";
    }

    public static String htmlRaw(String... lines) {
        String body = Arrays.stream(lines)
                .filter(Objects::nonNull)
                .map(line -> line.trim())
                .filter(line -> !line.isEmpty())
                .collect(Collectors.joining("<br>"));
        return body.isEmpty() ? null : "<html>" + body + "</html>";
    }

    public static String htmlWithSource(String description, String source) {
        String cleanDescription = description == null ? "" : description.trim();
        String cleanSource = source == null ? "" : source.trim();
        if (cleanDescription.isEmpty() && cleanSource.isEmpty()) {
            return null;
        }
        List<String> lines = new ArrayList<>();
        if (!cleanDescription.isEmpty()) {
            appendLabeledTooltipText(lines, "Description", cleanDescription);
        }
        if (!cleanSource.isEmpty()) {
            appendLabeledTooltipText(lines, "Source", cleanSource);
        }
        return htmlRaw(lines.toArray(String[]::new));
    }

    public static String textWithSource(String description, String source) {
        return htmlWithSource(description, source);
    }

    public static String escapeHtml(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }

    private static void appendLabeledTooltipText(List<String> lines, String label, String text) {
        List<String> textLines = splitTooltipText(text);
        if (textLines.isEmpty()) {
            return;
        }
        if (textLines.size() == 1 && text.length() <= STRUCTURED_TOOLTIP_THRESHOLD) {
            lines.add("<b>" + label + ":</b> " + escapeHtml(textLines.getFirst()));
            return;
        }
        lines.add("<b>" + label + ":</b>");
        for (String line : textLines) {
            lines.add("&nbsp;&nbsp;" + escapeHtml(line));
        }
    }

    private static List<String> splitTooltipText(String text) {
        String normalized = text == null ? "" : text.trim();
        if (normalized.isEmpty()) {
            return List.of();
        }
        String[] parts = normalized.split("(?<=\\.)\\s+|;\\s+|\\r?\\n");
        List<String> lines = new ArrayList<>();
        for (String part : parts) {
            String trimmed = part == null ? "" : part.trim();
            if (!trimmed.isEmpty()) {
                lines.add(trimmed);
            }
        }
        return lines.isEmpty() ? List.of(normalized) : lines;
    }

    private static void applyHtmlTooltipToChildren(Container root, JComponent tooltipOwner, String tooltip) {
        for (Component child : root.getComponents()) {
            if (child instanceof JComponent jc) {
                jc.putClientProperty(HTML_DISABLE, Boolean.FALSE);
                if (jc instanceof JButton) {
                    installTooltipForwarder(jc, tooltipOwner);
                } else {
                    jc.setToolTipText(tooltip);
                }
            }
            if (child instanceof Container nested) {
                applyHtmlTooltipToChildren(nested, tooltipOwner, tooltip);
            }
        }
    }

    private static void installTooltipForwarder(JComponent child, JComponent tooltipOwner) {
        Object existing = child.getClientProperty(TOOLTIP_FORWARDER_KEY);
        if (existing instanceof ComboChildTooltipForwarder forwarder) {
            child.removeMouseListener(forwarder);
            child.removeMouseMotionListener(forwarder);
        }
        child.setToolTipText(null);
        ComboChildTooltipForwarder forwarder = new ComboChildTooltipForwarder(child, tooltipOwner);
        child.addMouseListener(forwarder);
        child.addMouseMotionListener(forwarder);
        child.putClientProperty(TOOLTIP_FORWARDER_KEY, forwarder);
    }

    /** Forwards combo-child hover events to the combo so the combo's HTML tooltip is used. */
    private static final class ComboChildTooltipForwarder extends MouseAdapter {
        private final JComponent source;
        private final JComponent tooltipOwner;

        private ComboChildTooltipForwarder(JComponent source, JComponent tooltipOwner) {
            this.source = source;
            this.tooltipOwner = tooltipOwner;
        }

        @Override
        public void mouseEntered(MouseEvent e) {
            ToolTipManager.sharedInstance().mouseEntered(convert(e));
        }

        @Override
        public void mouseMoved(MouseEvent e) {
            ToolTipManager.sharedInstance().mouseMoved(convert(e));
        }

        @Override
        public void mouseExited(MouseEvent e) {
            ToolTipManager.sharedInstance().mouseExited(convert(e));
        }

        private MouseEvent convert(MouseEvent e) {
            return SwingUtilities.convertMouseEvent(source, e, tooltipOwner);
        }
    }
}
