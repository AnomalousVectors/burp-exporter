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
import java.util.Arrays;

import ai.anomalousvectors.tools.burp.ui.text.Tooltips;

/**
 * Password field whose preferred width tracks its content length within clamped bounds.
 * Uses the actual displayed character widths when revealed, and stays compact while hidden.
 *
 * <p>EDT: sizing is queried on the EDT by Swing.</p>
 */
public final class AutoSizingPasswordField extends JPasswordField {

    private static final int MIN_W = 80;
    private static final int MAX_W = 900;
    private static final int PADDING = 8;
    private static final int EYE_ICON_WIDTH = 18;
    private static final int EYE_ICON_GAP = 8;
    private static final int EYE_ICON_RESERVED_WIDTH = EYE_ICON_WIDTH + (EYE_ICON_GAP * 2);

    private final char hiddenEchoChar;
    private boolean visibleText;

    /**
     * Creates an auto-sizing password field.
     */
    public AutoSizingPasswordField() {
        super();
        hiddenEchoChar = getEchoChar();
        putClientProperty("html.disable", Boolean.FALSE);
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
     * Computes preferred size based on content length (character count), clamped between
     * {@value MIN_W} and {@value MAX_W} with padding.
     *
     * @return preferred dimension reflecting current content length
     */
    @Override
    public Dimension getPreferredSize() {
        FontMetrics fm = getFontMetrics(getFont());
        int textWidth = visibleText ? passwordTextWidth(fm) : 0;
        Insets margin = getMargin();
        int height = super.getPreferredSize().height;
        int w = Math.clamp(textWidth + margin.left + margin.right + PADDING, MIN_W, MAX_W);
        return new Dimension(w, height);
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        paintEyeIcon(g);
    }

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
