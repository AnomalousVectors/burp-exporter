package ai.anomalousvectors.tools.burp.ui.text;

import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.GraphicsEnvironment;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.Window;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.Serial;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import javax.swing.DefaultListCellRenderer;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.JToolTip;
import javax.swing.Popup;
import javax.swing.PopupFactory;
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
    private static final String WINDOW_CLAMP_KEY = Tooltips.class.getName() + ".clampToWindow";
    private static final String TIP_TO_RIGHT_KEY = Tooltips.class.getName() + ".tipToRight";
    private static final String TOOLTIP_FORWARDER_KEY = Tooltips.class.getName() + ".tooltipForwarder";
    private static final int STRUCTURED_TOOLTIP_THRESHOLD = 120;
    private static final int WINDOW_EDGE_MARGIN_PX = 4;
    /** Soft cap so long HTML tips stay near the hover target instead of spanning the Burp window. */
    private static final int MAX_CONSTRAINED_TIP_WIDTH_PX = 420;
    private static final int COMBO_ITEM_TIP_GAP_PX = 8;
    private static PopupFactory previousPopupFactory;
    private static PopupFactory installedPopupFactory;

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
     * effectively unlimited). Also installs a {@link PopupFactory} that keeps exporter HTML
     * tooltips inside the ancestor Burp window when possible. Invoke during extension
     * initialization before tooltip events begin; do not race this method with
     * {@link #restoreSharedPopupFactory()}.</p>
     */
    public static void configureSharedToolTipManager() {
        ToolTipManager manager = ToolTipManager.sharedInstance();
        manager.setInitialDelay(TOOLTIP_SHOW_DELAY_MS);
        manager.setReshowDelay(TOOLTIP_SHOW_DELAY_MS);
        manager.setDismissDelay(Integer.MAX_VALUE);
        installWindowClampedPopupFactory();
    }

    /**
     * Creates an HTML-enabled tooltip owned by a Swing component.
     *
     * <p>Caller must invoke on the EDT.</p>
     *
     * @param owner component that owns the tooltip; may be {@code null}
     * @return tooltip configured for HTML rendering and window clamping
     */
    public static JToolTip createHtmlToolTip(JComponent owner) {
        JToolTip toolTip = new JToolTip();
        toolTip.putClientProperty(HTML_DISABLE, Boolean.FALSE);
        toolTip.putClientProperty(WINDOW_CLAMP_KEY, Boolean.TRUE);
        toolTip.setComponent(owner);
        return toolTip;
    }

    /**
     * Clamps a preferred screen-space popup origin so the tip stays inside {@code bounds}.
     *
     * <p>Overflow is corrected by sliding toward the nearest fitting edge (not by flipping the tip
     * to the far side of the preferred point). Used by field tooltips, combo item tooltips, and the
     * window-clamped {@link PopupFactory}.</p>
     *
     * @param bounds window or screen bounds in screen coordinates
     * @param preferredX preferred tip X
     * @param preferredY preferred tip Y
     * @param tipSize tip preferred size; {@code null} or non-positive treated as 1x1
     * @param margin inset from bounds edges
     * @return clamped top-left screen location
     */
    static Point clampToBounds(
            Rectangle bounds,
            int preferredX,
            int preferredY,
            Dimension tipSize,
            int margin) {
        Rectangle safeBounds = bounds == null || bounds.width <= 0 || bounds.height <= 0
                ? new Rectangle(preferredX, preferredY, 1, 1)
                : bounds;
        int width = tipSize == null ? 1 : Math.max(1, tipSize.width);
        int height = tipSize == null ? 1 : Math.max(1, tipSize.height);
        int edge = Math.max(0, margin);
        int minX = safeBounds.x + edge;
        int minY = safeBounds.y + edge;
        int maxX = safeBounds.x + safeBounds.width - width - edge;
        int maxY = safeBounds.y + safeBounds.height - height - edge;
        int x = preferredX;
        if (maxX < minX) {
            x = minX;
        } else {
            x = Math.min(Math.max(x, minX), maxX);
        }
        int y;
        if (maxY < minY) {
            y = minY;
        } else {
            y = Math.min(Math.max(preferredY, minY), maxY);
        }
        return new Point(x, y);
    }

    private static synchronized void installWindowClampedPopupFactory() {
        PopupFactory current = PopupFactory.getSharedInstance();
        if (current == installedPopupFactory || current instanceof WindowClampedPopupFactory) {
            return;
        }
        previousPopupFactory = current;
        installedPopupFactory = new WindowClampedPopupFactory(current);
        PopupFactory.setSharedInstance(installedPopupFactory);
    }

    /**
     * Restores the shared popup factory replaced by {@link #configureSharedToolTipManager()}.
     *
     * <p>The previous factory is restored only while this class's wrapper is still installed, so
     * cleanup does not overwrite a newer factory installed by Burp or another extension. Invoke
     * during extension teardown after tooltip events have stopped.</p>
     */
    public static synchronized void restoreSharedPopupFactory() {
        if (installedPopupFactory != null
                && previousPopupFactory != null
                && PopupFactory.getSharedInstance() == installedPopupFactory) {
            PopupFactory.setSharedInstance(previousPopupFactory);
        }
        installedPopupFactory = null;
        previousPopupFactory = null;
    }

    private static Rectangle resolveClampBounds(Component owner) {
        Window window = owner == null ? null : SwingUtilities.getWindowAncestor(owner);
        if (window != null && window.isShowing()) {
            return window.getBounds();
        }
        if (owner != null && owner.getGraphicsConfiguration() != null) {
            return owner.getGraphicsConfiguration().getBounds();
        }
        return GraphicsEnvironment.getLocalGraphicsEnvironment().getMaximumWindowBounds();
    }

    private static void constrainTipWidthToWindow(Component owner, JToolTip tip) {
        constrainTipWidthToBounds(resolveClampBounds(owner), tip);
    }

    static void constrainTipWidthToBounds(Rectangle bounds, JToolTip tip) {
        if (tip == null) {
            return;
        }
        Rectangle safeBounds = bounds == null || bounds.width <= 0
                ? new Rectangle(0, 0, 1, 1)
                : bounds;
        int popupWidth = Math.max(1, safeBounds.width - (WINDOW_EDGE_MARGIN_PX * 2));
        java.awt.Insets insets = tip.getInsets();
        int contentWidth = Math.max(1, popupWidth - insets.left - insets.right);
        int maxWidth = Math.min(MAX_CONSTRAINED_TIP_WIDTH_PX, contentWidth);
        String text = tip.getTipText();
        if (text == null || text.isBlank() || !text.regionMatches(true, 0, "<html>", 0, 6)) {
            return;
        }
        if (text.toLowerCase(Locale.ROOT).contains("width=")) {
            return;
        }
        Dimension preferred = tip.getPreferredSize();
        int maxPopupWidth = Math.min(
                popupWidth,
                MAX_CONSTRAINED_TIP_WIDTH_PX + insets.left + insets.right);
        if (preferred.width <= maxPopupWidth) {
            return;
        }
        String narrowed = constrainHtmlWidth(text, maxWidth);
        tip.setTipText(narrowed);
        int overflow = tip.getPreferredSize().width - popupWidth;
        if (overflow > 0) {
            tip.setTipText(constrainHtmlWidth(text, Math.max(1, maxWidth - overflow)));
        }
    }

    private static String constrainHtmlWidth(String text, int width) {
        String narrowed = text.replaceFirst("(?i)<html>", "<html><body width=\"" + width + "\">");
        if (narrowed.regionMatches(true, narrowed.length() - 7, "</html>", 0, 7)) {
            narrowed = narrowed.substring(0, narrowed.length() - 7) + "</body></html>";
        } else {
            narrowed = narrowed + "</body>";
        }
        return narrowed;
    }

    private static void prepareOpaqueTip(JToolTip tip) {
        if (tip == null) {
            return;
        }
        tip.setOpaque(true);
        java.awt.Color background = javax.swing.UIManager.getColor("ToolTip.background");
        if (background != null) {
            tip.setBackground(background);
        }
        java.awt.Color foreground = javax.swing.UIManager.getColor("ToolTip.foreground");
        if (foreground != null) {
            tip.setForeground(foreground);
        }
    }

    private static Point fitTooltipPopup(Component owner, JToolTip tip, int preferredX, int preferredY) {
        constrainTipWidthToWindow(owner, tip);
        prepareOpaqueTip(tip);
        Dimension tipSize = tip.getPreferredSize();
        return clampToBounds(resolveClampBounds(owner), preferredX, preferredY, tipSize, WINDOW_EDGE_MARGIN_PX);
    }

    /**
     * Places a tip immediately to the right of {@code owner}, avoiding covering it.
     *
     * <p>Used for action buttons such as Test Connection where a default below-cursor tip would
     * overlay the click target and intercept the path to the button.</p>
     */
    private static Point fitTooltipToRightOfOwner(Component owner, JToolTip tip) {
        constrainTipWidthToWindow(owner, tip);
        prepareOpaqueTip(tip);
        if (owner == null || !owner.isShowing()) {
            Dimension tipSize = tip.getPreferredSize();
            return clampToBounds(resolveClampBounds(owner), 0, 0, tipSize, WINDOW_EDGE_MARGIN_PX);
        }
        Point origin = owner.getLocationOnScreen();
        Rectangle avoid = new Rectangle(
                origin.x,
                origin.y,
                Math.max(1, owner.getWidth()),
                Math.max(1, owner.getHeight()));
        return placeToRightOf(resolveClampBounds(owner), avoid, tip.getPreferredSize());
    }

    /**
     * Places a tip preferring the right side of {@code avoidBounds}, then left, below, and above.
     *
     * @param window clamp bounds in screen coordinates
     * @param avoidBounds component rectangle the tip must not cover
     * @param tipSize tip preferred size
     * @return screen location that prefers right-of-target placement
     */
    static Point placeToRightOf(Rectangle window, Rectangle avoidBounds, Dimension tipSize) {
        Rectangle avoid = avoidBounds == null ? new Rectangle(0, 0, 1, 1) : avoidBounds;
        return placeBesideAvoiding(window, avoid, tipSize, avoid.y, true);
    }

    /**
     * Places a combo-item tip outside the open popup menu so it does not cover the list or flicker.
     *
     * <p>Prefers below the menu (Config columns are often too narrow for a side tip), then above,
     * then right/left. Placement never intentionally returns a rectangle that intersects the menu:
     * when space is tight the tip is still anchored outside the menu even if it clips the window
     * edge. Callers should also use a mouse-transparent tip so a residual overlap cannot steal
     * mouse events from the list.</p>
     *
     * @param list popup list under the mouse
     * @param tip prepared tip component
     * @param event mouse event over the list row
     * @return clamped top-left screen location
     */
    static Point fitComboItemTooltip(JList<?> list, JToolTip tip, MouseEvent event) {
        constrainTipWidthToWindow(list, tip);
        prepareOpaqueTip(tip);
        Dimension tipSize = tip.getPreferredSize();
        Rectangle window = resolveClampBounds(list);
        Point listOrigin = list.getLocationOnScreen();
        Rectangle listBounds = new Rectangle(listOrigin.x, listOrigin.y, list.getWidth(), list.getHeight());
        Rectangle avoidBounds = resolveComboPopupAvoidBounds(list, listBounds);
        int row = list.locationToIndex(event.getPoint());
        Rectangle cell = row >= 0 ? list.getCellBounds(row, row) : null;
        int preferredY = cell == null
                ? listOrigin.y + event.getY()
                : listOrigin.y + cell.y;
        return placeBesideAvoiding(window, avoidBounds, tipSize, preferredY);
    }

    /**
     * Resolves the screen rectangle the combo tip must not cover.
     *
     * <p>Prefers {@link BasicComboPopup}, then a parent {@link javax.swing.JPopupMenu}, then the
     * list bounds. Burp/FlatLaf may wrap the list so the popup ancestor is not always
     * {@code BasicComboPopup}.</p>
     */
    private static Rectangle resolveComboPopupAvoidBounds(JList<?> list, Rectangle listBounds) {
        Container popup = SwingUtilities.getAncestorOfClass(BasicComboPopup.class, list);
        if (popup != null && popup.isShowing()) {
            Point popupOrigin = popup.getLocationOnScreen();
            return new Rectangle(popupOrigin.x, popupOrigin.y, popup.getWidth(), popup.getHeight());
        }
        Container menu = SwingUtilities.getAncestorOfClass(javax.swing.JPopupMenu.class, list);
        if (menu != null && menu.isShowing()) {
            Point menuOrigin = menu.getLocationOnScreen();
            return new Rectangle(menuOrigin.x, menuOrigin.y, menu.getWidth(), menu.getHeight());
        }
        return listBounds;
    }

    /**
     * Chooses a tip origin beside or under {@code avoidBounds} that stays inside {@code window}.
     *
     * @param window clamp bounds in screen coordinates
     * @param avoidBounds popup/menu rectangle the tip must not cover
     * @param tipSize tip preferred size
     * @param preferredY preferred tip Y when placing to the side (usually the hovered row)
     * @return clamped top-left screen location that does not intersect {@code avoidBounds} when
     *     any outside anchor fits
     */
    static Point placeBesideAvoiding(
            Rectangle window,
            Rectangle avoidBounds,
            Dimension tipSize,
            int preferredY) {
        return placeBesideAvoiding(window, avoidBounds, tipSize, preferredY, false);
    }

    /**
     * Chooses a tip origin beside or under {@code avoidBounds} that stays inside {@code window}.
     *
     * @param window clamp bounds in screen coordinates
     * @param avoidBounds popup/menu rectangle the tip must not cover
     * @param tipSize tip preferred size
     * @param preferredY preferred tip Y when placing to the side (usually the hovered row)
     * @param preferRight when {@code true}, try right/left before below/above (action-button tips);
     *     when {@code false}, prefer below/above first (Config auth columns are often too narrow)
     * @return clamped top-left screen location that does not intersect {@code avoidBounds} when
     *     any outside anchor fits
     */
    static Point placeBesideAvoiding(
            Rectangle window,
            Rectangle avoidBounds,
            Dimension tipSize,
            int preferredY,
            boolean preferRight) {
        Rectangle safeWindow = window == null || window.width <= 0 || window.height <= 0
                ? new Rectangle(0, 0, 1, 1)
                : window;
        Rectangle avoid = avoidBounds == null
                ? new Rectangle(preferredY, preferredY, 1, 1)
                : avoidBounds;
        Dimension size = tipSize == null ? new Dimension(1, 1) : tipSize;
        int width = Math.max(1, size.width);
        int height = Math.max(1, size.height);
        int gap = COMBO_ITEM_TIP_GAP_PX;
        int edge = WINDOW_EDGE_MARGIN_PX;
        int spaceRight = Math.max(0, (safeWindow.x + safeWindow.width) - (avoid.x + avoid.width) - gap - edge);
        int spaceLeft = Math.max(0, avoid.x - safeWindow.x - gap - edge);
        int spaceBelow = Math.max(0, (safeWindow.y + safeWindow.height) - (avoid.y + avoid.height) - gap - edge);
        int spaceAbove = Math.max(0, avoid.y - safeWindow.y - gap - edge);

        Point right = new Point(avoid.x + avoid.width + gap, preferredY);
        Point left = new Point(avoid.x - width - gap, preferredY);
        Point below = new Point(avoid.x, avoid.y + avoid.height + gap);
        Point above = new Point(avoid.x, avoid.y - height - gap);

        List<Point> candidates = new ArrayList<>(4);
        if (preferRight) {
            if (spaceRight >= width) {
                candidates.add(right);
            }
            if (spaceLeft >= width) {
                candidates.add(left);
            }
            if (spaceBelow >= height || spaceBelow >= spaceAbove) {
                candidates.add(below);
            }
            if (spaceAbove >= height) {
                candidates.add(above);
            }
        } else {
            // Prefer below/above first: Config auth columns are usually too narrow for a full-width tip.
            if (spaceBelow >= height || spaceBelow >= spaceAbove) {
                candidates.add(below);
            }
            if (spaceAbove >= height) {
                candidates.add(above);
            }
            if (spaceRight >= width) {
                candidates.add(right);
            }
            if (spaceLeft >= width) {
                candidates.add(left);
            }
        }
        if (candidates.isEmpty()) {
            if (preferRight) {
                if (spaceRight >= spaceLeft) {
                    candidates.add(right);
                } else {
                    candidates.add(left);
                }
            } else if (spaceRight >= spaceLeft) {
                candidates.add(right);
            } else {
                candidates.add(left);
            }
            candidates.add(below);
        }

        Point bestOutside = null;
        for (Point preferred : candidates) {
            Point clamped = clampToBounds(safeWindow, preferred.x, preferred.y, new Dimension(width, height), edge);
            Rectangle tipRect = new Rectangle(clamped.x, clamped.y, width, height);
            if (!tipRect.intersects(avoid)) {
                return clamped;
            }
            // Clamp slid the tip back over the menu (tip wider than remaining side). Keep searching.
            if (bestOutside == null) {
                // Force an outside anchor on the preferred axis without sliding back over the menu.
                Point forced = forceOutsideAvoid(avoid, preferred, width, height, gap);
                Rectangle forcedRect = new Rectangle(forced.x, forced.y, width, height);
                if (!forcedRect.intersects(avoid)) {
                    bestOutside = forced;
                }
            }
        }
        if (bestOutside != null) {
            return bestOutside;
        }
        // Last resort: directly below the menu, even if partially off-window.
        return new Point(avoid.x, avoid.y + avoid.height + gap);
    }

    /**
     * Anchors a tip fully outside {@code avoid} on the same side as {@code preferred}.
     */
    private static Point forceOutsideAvoid(
            Rectangle avoid,
            Point preferred,
            int width,
            int height,
            int gap) {
        if (preferred.y >= avoid.y + avoid.height) {
            return new Point(preferred.x, avoid.y + avoid.height + gap);
        }
        if (preferred.y + height <= avoid.y) {
            return new Point(preferred.x, avoid.y - height - gap);
        }
        if (preferred.x >= avoid.x + avoid.width) {
            return new Point(avoid.x + avoid.width + gap, preferred.y);
        }
        if (preferred.x + width <= avoid.x) {
            return new Point(avoid.x - width - gap, preferred.y);
        }
        return new Point(avoid.x, avoid.y + avoid.height + gap);
    }

    /**
     * Popup factory that keeps exporter HTML tooltips inside the ancestor window when possible.
     *
     * <p>Non-exporter popups (Burp menus, dialogs, etc.) are delegated unchanged.</p>
     */
    private static final class WindowClampedPopupFactory extends PopupFactory {
        private final PopupFactory delegate;

        private WindowClampedPopupFactory(PopupFactory delegate) {
            this.delegate = Objects.requireNonNull(delegate, "delegate");
        }

        /**
         * Creates a popup, fitting exporter tooltips to their owner window when possible.
         *
         * @param owner popup owner
         * @param contents popup contents
         * @param x requested screen X coordinate
         * @param y requested screen Y coordinate
         * @return popup created by the wrapped factory
         * @throws IllegalArgumentException when the wrapped factory rejects the request
         */
        @Override
        public Popup getPopup(Component owner, Component contents, int x, int y)
                throws IllegalArgumentException {
            if (contents instanceof JToolTip tip
                    && Boolean.TRUE.equals(tip.getClientProperty(WINDOW_CLAMP_KEY))) {
                Point fitted = owner instanceof JComponent jc
                        && Boolean.TRUE.equals(jc.getClientProperty(TIP_TO_RIGHT_KEY))
                        ? fitTooltipToRightOfOwner(owner, tip)
                        : fitTooltipPopup(owner, tip, x, y);
                return delegate.getPopup(owner, tip, fitted.x, fitted.y);
            }
            return delegate.getPopup(owner, contents, x, y);
        }
    }

    /**
     * Label whose tooltips render exporter HTML.
     *
     * <p>Caller must construct and mutate on the EDT. The type has no custom transient state.</p>
     */
    public static final class HtmlLabel extends JLabel {
        @Serial private static final long serialVersionUID = 1L;

        /**
         * Creates an HTML-tooltip-enabled label.
         *
         * @param text label text; passed to {@link JLabel}
         */
        public HtmlLabel(String text) {
            super(text);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        /**
         * Creates an aligned HTML-tooltip-enabled label.
         *
         * @param text label text; passed to {@link JLabel}
         * @param horizontalAlignment Swing horizontal-alignment constant
         */
        public HtmlLabel(String text, int horizontalAlignment) {
            super(text, horizontalAlignment);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        /**
         * Creates this label's HTML-enabled tooltip.
         *
         * @return tooltip owned by this label
         */
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
     *
     * <p>Caller must construct and mutate on the EDT. The type has no custom transient state.</p>
     */
    public static final class HtmlPanel extends JPanel {
        @Serial private static final long serialVersionUID = 1L;

        /**
         * Creates an HTML-tooltip-enabled panel with the default layout.
         *
         * <p>Caller must invoke on the EDT. The type has no custom transient state.</p>
         */
        public HtmlPanel() {
            super();
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        /**
         * Creates an HTML-tooltip-enabled panel with a caller-provided layout.
         *
         * <p>Caller must invoke on the EDT.</p>
         *
         * @param layout panel layout manager; passed to {@link JPanel}
         */
        public HtmlPanel(java.awt.LayoutManager layout) {
            super(layout);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        /**
         * Creates this panel's HTML-enabled tooltip.
         *
         * @return tooltip owned by this panel
         */
        @Override
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
        }
    }

    /**
     * Button whose tooltips render exporter HTML.
     *
     * <p>Caller must construct and mutate on the EDT. The type has no custom transient state.</p>
     */
    public static final class HtmlButton extends JButton {
        @Serial private static final long serialVersionUID = 1L;

        /**
         * Creates an HTML-tooltip-enabled button.
         *
         * @param text button text; passed to {@link JButton}
         */
        public HtmlButton(String text) {
            super(text);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        /**
         * Returns the configured tooltip origin for this button.
         *
         * @param event triggering mouse event
         * @return right-side origin when requested, otherwise the Swing default
         */
        @Override
        public Point getToolTipLocation(MouseEvent event) {
            if (Boolean.TRUE.equals(getClientProperty(TIP_TO_RIGHT_KEY))) {
                return new Point(getWidth() + COMBO_ITEM_TIP_GAP_PX, 0);
            }
            return super.getToolTipLocation(event);
        }

        /**
         * Creates this button's HTML-enabled tooltip.
         *
         * @return tooltip owned by this button
         */
        @Override
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
        }
    }

    /**
     * Check box whose tooltips render exporter HTML.
     *
     * <p>Caller must construct and mutate on the EDT. The type has no custom transient state.</p>
     */
    public static class HtmlCheckBox extends JCheckBox {
        @Serial private static final long serialVersionUID = 1L;

        /**
         * Creates an HTML-tooltip-enabled check box.
         *
         * @param text check-box text
         * @param selected initial selection state
         */
        public HtmlCheckBox(String text, boolean selected) {
            super(text, selected);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        /**
         * Creates an unselected HTML-tooltip-enabled check box.
         *
         * @param text check-box text
         */
        public HtmlCheckBox(String text) {
            super(text);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        /**
         * Creates this check box's HTML-enabled tooltip.
         *
         * @return tooltip owned by this check box
         */
        @Override
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
        }
    }

    /**
     * Radio button whose tooltips render exporter HTML.
     *
     * <p>Caller must construct and mutate on the EDT. The type has no custom transient state.</p>
     */
    public static final class HtmlRadioButton extends JRadioButton {
        @Serial private static final long serialVersionUID = 1L;

        /**
         * Creates an unselected HTML-tooltip-enabled radio button.
         *
         * @param text radio-button text
         */
        public HtmlRadioButton(String text) {
            super(text);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        /**
         * Creates an HTML-tooltip-enabled radio button.
         *
         * @param text radio-button text
         * @param selected initial selection state
         */
        public HtmlRadioButton(String text, boolean selected) {
            super(text, selected);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        /**
         * Creates this radio button's HTML-enabled tooltip.
         *
         * @return tooltip owned by this radio button
         */
        @Override
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
        }
    }

    /**
     * Text field whose tooltips render exporter HTML.
     *
     * <p>Caller must construct and mutate on the EDT. The type has no custom transient state.</p>
     */
    public static final class HtmlTextField extends JTextField {
        @Serial private static final long serialVersionUID = 1L;

        /** Creates an empty HTML-tooltip-enabled text field. Caller must invoke on the EDT. */
        public HtmlTextField() {
            super();
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        /**
         * Creates this field's HTML-enabled tooltip.
         *
         * @return tooltip owned by this text field
         */
        @Override
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
        }
    }

    /**
     * Password field whose tooltips render exporter HTML.
     *
     * <p>Caller must construct and mutate on the EDT. The type has no custom transient state.</p>
     */
    public static final class HtmlPasswordField extends JPasswordField {
        @Serial private static final long serialVersionUID = 1L;

        /** Creates an empty HTML-tooltip-enabled password field. Caller must invoke on the EDT. */
        public HtmlPasswordField() {
            super();
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        /**
         * Creates this field's HTML-enabled tooltip.
         *
         * @return tooltip owned by this password field
         */
        @Override
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
        }
    }

    /**
     * Combo box that mirrors an HTML tooltip to look-and-feel child controls.
     *
     * <p>Caller must construct and mutate on the EDT. The type has no custom transient state.</p>
     *
     * @param <E> combo item type
     */
    public static final class HtmlComboBox<E> extends JComboBox<E> {
        @Serial private static final long serialVersionUID = 1L;

        /**
         * Creates an HTML-tooltip-enabled combo box.
         *
         * @param items non-null initial items; passed to {@link JComboBox}
         * @throws NullPointerException if {@code items} is {@code null}
         */
        public HtmlComboBox(E[] items) {
            super(items);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        /** Installs child tooltip forwarding after the combo becomes displayable. */
        @Override
        public void addNotify() {
            super.addNotify();
            syncChildTooltips();
        }

        /** Restores HTML tooltip properties and child forwarding after a look-and-feel update. */
        @Override
        public void updateUI() {
            super.updateUI();
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
            syncChildTooltips();
        }

        /**
         * Sets tooltip text and mirrors it to combo child controls.
         *
         * @param text tooltip text; {@code null} clears the tooltip
         */
        @Override
        public void setToolTipText(String text) {
            super.setToolTipText(text);
            syncChildTooltips();
        }

        /**
         * Creates this combo box's HTML-enabled tooltip.
         *
         * @return tooltip owned by this combo box
         */
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
     * across look-and-feel popup lists that otherwise display markup as literal text. Item tips
     * prefer placement below the open dropdown (Config columns are often too narrow for a side tip),
     * fall back to above/beside, and stay mouse-transparent so they cannot steal hover from the
     * list or create a show/hide feedback loop. Tips stay opaque for readability.</p>
     *
     * <p>Popup ownership, popup-list references, handlers, and the current hover value are
     * transient. {@link #addNotify()} and {@link #updateUI()} rebuild popup-list wiring lazily on
     * the EDT after deserialization; an open popup and current hover value are not restored.</p>
     *
     * @param <E> combo item type
     */
    public static final class ItemTooltipComboBox<E> extends JComboBox<E> {
        @Serial private static final long serialVersionUID = 1L;

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
         * @param items non-null visible combo items
         * @param itemTooltips non-null tooltip text by item value
         * @throws NullPointerException if an argument is {@code null}
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
            if (items != null && items.length > 0) {
                E longest = items[0];
                for (E item : items) {
                    if (String.valueOf(item).length() > String.valueOf(longest).length()) {
                        longest = item;
                    }
                }
                setPrototypeDisplayValue(longest);
            }
        }

        /**
         * Selects an item and clears the selected-value tooltip.
         *
         * <p>Caller must invoke on the EDT.</p>
         *
         * @param item item to select; passed to {@link JComboBox}
         */
        @Override
        public void setSelectedItem(Object item) {
            super.setSelectedItem(item);
            syncSelectedTooltip();
        }

        /**
         * Installs popup-list tooltip wiring after the combo becomes displayable.
         *
         * <p>Caller must invoke on the EDT.</p>
         */
        @Override
        public void addNotify() {
            super.addNotify();
            syncChildTooltips();
            syncPopupListTooltips();
        }

        /**
         * Restores renderer and tooltip wiring after a look-and-feel update.
         *
         * <p>Caller must invoke on the EDT.</p>
         */
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

        /**
         * Creates this combo box's HTML-enabled tooltip.
         *
         * @return tooltip owned by this combo box
         */
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
            if (!(owner instanceof JList<?> list)) {
                hideItemTooltip();
                return;
            }
            if (tooltip == null || tooltip.isBlank()) {
                hideItemTooltip();
                return;
            }
            if (Objects.equals(value, popupTooltipValue) && itemTooltipPopup != null) {
                return;
            }
            hideItemTooltip();
            popupTooltipValue = value;
            // Mouse-transparent tip: contains() always false so the open combo list keeps receiving
            // mouse events even if placement still overlaps. That stops the show/hide flicker loop.
            JToolTip toolTip = new JToolTip() {
                @Serial private static final long serialVersionUID = 1L;

                @Override
                public boolean contains(int x, int y) {
                    return false;
                }
            };
            toolTip.putClientProperty(HTML_DISABLE, Boolean.FALSE);
            toolTip.setComponent(this);
            toolTip.setTipText(tooltip);
            Point fitted = fitComboItemTooltip(list, toolTip, event);
            itemTooltipPopup = PopupFactory.getSharedInstance().getPopup(
                    owner,
                    toolTip,
                    fitted.x,
                    fitted.y);
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
            @Serial private static final long serialVersionUID = 1L;

            /**
             * Renders a combo item without installing Swing's default per-cell tooltip.
             *
             * @param list popup list
             * @param value item value
             * @param index item index
             * @param isSelected whether the item is selected
             * @param cellHasFocus whether the cell has focus
             * @return renderer component
             */
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

    /**
     * Applies exporter HTML tooltip configuration to a component.
     *
     * <p>Caller must invoke on the EDT when the component is displayable.</p>
     *
     * @param component component to configure; must not be {@code null}
     * @param tooltip tooltip text; {@code null} clears the tooltip
     * @param <T> component type
     * @return {@code component} for call chaining
     * @throws NullPointerException if {@code component} is {@code null}
     */
    public static <T extends JComponent> T apply(T component, String tooltip) {
        component.putClientProperty(HTML_DISABLE, Boolean.FALSE);
        component.setToolTipText(tooltip);
        return component;
    }

    /**
     * Prefers showing this component's tooltip to the right of the control.
     *
     * <p>Use for action buttons whose default below-cursor tip would cover the click target.
     * Caller must invoke on the EDT when the component is already realized; otherwise set before
     * first hover.</p>
     *
     * @param component hover target; must not be {@code null}
     * @param <T> component type
     * @return {@code component} for chaining with {@link #apply(JComponent, String)}
     */
    public static <T extends JComponent> T preferTipToRight(T component) {
        Objects.requireNonNull(component, "component");
        component.putClientProperty(TIP_TO_RIGHT_KEY, Boolean.TRUE);
        return component;
    }

    /**
     * Applies one HTML tooltip to a metric row and each direct child so hover on labels and
     * values uses the same {@link ToolTipManager} delays as {@link #configureSharedToolTipManager()}.
     *
     * <p>Caller must invoke on the EDT. Null rows and null or blank tooltips are ignored.</p>
     *
     * @param row row and direct children to configure
     * @param tooltip shared tooltip text
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

    /**
     * Creates an HTML-tooltip-enabled label.
     *
     * <p>Caller must invoke on the EDT.</p>
     *
     * @param text label text
     * @param tooltip tooltip text; {@code null} leaves the label without a tooltip
     * @return configured label
     */
    public static JLabel label(String text, String tooltip) {
        return apply(new HtmlLabel(text), tooltip);
    }

    /**
     * Builds escaped HTML tooltip text from nonblank lines.
     *
     * @param lines plain-text lines; null elements and blank lines are omitted
     * @return HTML text joined with line breaks, or {@code null} when no content remains
     * @throws NullPointerException if {@code lines} is {@code null}
     */
    public static String html(String... lines) {
        String body = Arrays.stream(lines)
                .filter(Objects::nonNull)
                .map(line -> line.trim())
                .filter(line -> !line.isEmpty())
                .map(line -> escapeHtml(line))
                .collect(Collectors.joining("<br>"));
        return body.isEmpty() ? null : "<html>" + body + "</html>";
    }

    /**
     * Builds HTML tooltip text from trusted markup lines.
     *
     * <p>Content is not escaped; callers must escape untrusted values before passing them.</p>
     *
     * @param lines trusted HTML fragments; null elements and blank lines are omitted
     * @return HTML text joined with line breaks, or {@code null} when no content remains
     * @throws NullPointerException if {@code lines} is {@code null}
     */
    public static String htmlRaw(String... lines) {
        String body = Arrays.stream(lines)
                .filter(Objects::nonNull)
                .map(line -> line.trim())
                .filter(line -> !line.isEmpty())
                .collect(Collectors.joining("<br>"));
        return body.isEmpty() ? null : "<html>" + body + "</html>";
    }

    /**
     * Builds escaped Description and Source sections for a field tooltip.
     *
     * @param description field description; null is treated as empty
     * @param source field provenance; null is treated as empty
     * @return structured HTML tooltip, or {@code null} when both values are blank
     */
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

    /**
     * Builds escaped Description and Source sections for a field tooltip.
     *
     * @param description field description; null is treated as empty
     * @param source field provenance; null is treated as empty
     * @return structured HTML tooltip, or {@code null} when both values are blank
     */
    public static String textWithSource(String description, String source) {
        return htmlWithSource(description, source);
    }

    /**
     * Escapes ampersands and angle brackets for insertion into HTML tooltip text.
     *
     * @param value plain text; {@code null} is treated as empty
     * @return escaped text
     */
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
