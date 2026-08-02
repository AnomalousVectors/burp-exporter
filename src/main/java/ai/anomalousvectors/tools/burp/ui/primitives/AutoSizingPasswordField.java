package ai.anomalousvectors.tools.burp.ui.primitives;

import javax.swing.JPasswordField;
import javax.swing.JToolTip;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Insets;
import java.awt.Point;
import java.awt.RenderingHints;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.Serial;
import java.util.Arrays;

import ai.anomalousvectors.tools.burp.ui.text.Tooltips;

/**
 * Password field whose preferred width tracks its content length within clamped bounds.
 * Uses the actual displayed character widths when revealed, and stays compact while hidden.
 *
 * <p>Caller must construct and mutate on the EDT. The type has no custom transient fields or
 * deserialization reconstruction contract and is intended for live UI construction rather than
 * persisted reuse.</p>
 */
public final class AutoSizingPasswordField extends JPasswordField {
    @Serial private static final long serialVersionUID = 1L;

    private static final int DEFAULT_MIN_W = 80;
    private static final int MAX_W = 900;
    private static final int PADDING = 8;
    private static final int EYE_ICON_WIDTH = 18;
    private static final int EYE_ICON_GAP = 8;
    private static final int EYE_ICON_RESERVED_WIDTH = EYE_ICON_WIDTH + (EYE_ICON_GAP * 2);

    /**
     * Empty preferred-width floor for destination credential password fields.
     *
     * <p>Twice the default empty floor so blank auth fields stay usable before content grows them.</p>
     */
    public static final int CREDENTIAL_MIN_WIDTH = DEFAULT_MIN_W * 2;

    private final int minWidth;
    private final char hiddenEchoChar;
    private boolean visibleText;

    /**
     * Creates an auto-sizing password field.
     *
     * <p>Caller must invoke on the EDT.</p>
     */
    public AutoSizingPasswordField() {
        this(DEFAULT_MIN_W);
    }

    /**
     * Creates an auto-sizing password field with a custom empty-width floor.
     *
     * <p>Caller must invoke on the EDT.</p>
     *
     * @param minWidth preferred-width floor while empty or short; clamped to at least {@code 1}
     */
    public AutoSizingPasswordField(int minWidth) {
        super();
        this.minWidth = Math.max(1, minWidth);
        hiddenEchoChar = getEchoChar();
        putClientProperty("html.disable", Boolean.FALSE);
        // Burp uses FlatLaf, which paints a native reveal control when the field is focused.
        // That control clashes with our custom eye glyph; keep only the painted eye toggle.
        putClientProperty("JPasswordField.showRevealButton", Boolean.FALSE);
        Insets margin = getMargin();
        setMargin(new Insets(
                margin.top,
                margin.left,
                margin.bottom,
                margin.right + EYE_ICON_RESERVED_WIDTH));
        getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { revalidate(); }

            @Override
            public void removeUpdate(DocumentEvent e) { revalidate(); }

            @Override
            public void changedUpdate(DocumentEvent e) { revalidate(); }
        });
        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (isEnabled() && isEyeIconHit(e.getPoint())) {
                    toggleVisibility();
                }
            }
        });
    }

    /**
     * Restores HTML and reveal-control properties after a look-and-feel update.
     *
     * <p>Caller must invoke on the EDT.</p>
     */
    @Override
    public void updateUI() {
        super.updateUI();
        putClientProperty("html.disable", Boolean.FALSE);
        putClientProperty("JPasswordField.showRevealButton", Boolean.FALSE);
    }

    /**
     * Computes preferred size based on content length (character count), clamped between
     * this field's minimum and {@value MAX_W} with padding.
     *
     * @return preferred dimension reflecting current content length
     */
    @Override
    public Dimension getPreferredSize() {
        FontMetrics fm = getFontMetrics(getFont());
        int textWidth = visibleText ? passwordTextWidth(fm) : 0;
        Insets margin = getMargin();
        int height = super.getPreferredSize().height;
        int w = Math.clamp(textWidth + margin.left + margin.right + PADDING, minWidth, MAX_W);
        return new Dimension(w, height);
    }

    /**
     * Paints the password field and its reveal glyph.
     *
     * @param g Swing paint context
     */
    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        paintEyeIcon(g);
    }

    /**
     * Creates this field's HTML-enabled tooltip.
     *
     * @return tooltip owned by this password field
     */
    @Override
    public JToolTip createToolTip() {
        return Tooltips.createHtmlToolTip(this);
    }

    private void toggleVisibility() {
        visibleText = !visibleText;
        setEchoChar(visibleText ? (char) 0 : hiddenEchoChar);
        revalidate();
        repaint();
    }

    private int passwordTextWidth(FontMetrics fm) {
        char[] password = getPassword();
        if (password == null || password.length == 0) {
            return 0;
        }
        int width = 0;
        try {
            for (char ch : password) {
                width += fm.charWidth(ch);
            }
            return width;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private boolean isEyeIconHit(Point point) {
        int iconX = getWidth() - EYE_ICON_WIDTH - EYE_ICON_GAP;
        return point.x >= iconX - EYE_ICON_GAP && point.x <= getWidth();
    }

    private void paintEyeIcon(Graphics graphics) {
        if (!(graphics instanceof Graphics2D g)) {
            return;
        }
        Graphics2D copy = (Graphics2D) g.create();
        try {
            copy.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            copy.setStroke(new BasicStroke(1.2f));
            Color iconColor = isEnabled()
                    ? getForeground()
                    : javax.swing.UIManager.getColor("TextField.inactiveForeground");
            copy.setColor(iconColor == null ? Color.GRAY : iconColor);
            int x = getWidth() - EYE_ICON_WIDTH - EYE_ICON_GAP;
            int y = (getHeight() - 10) / 2;
            copy.drawOval(x, y, 16, 10);
            copy.fillOval(x + 6, y + 3, 4, 4);
            if (visibleText) {
                copy.drawLine(x + 2, y + 11, x + 15, y - 1);
            }
        } finally {
            copy.dispose();
        }
    }
}
