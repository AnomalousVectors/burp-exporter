package ai.anomalousvectors.tools.burp.ui.primitives;

import java.awt.Dimension;
import java.awt.FontMetrics;
import java.io.Serial;

import javax.swing.JToolTip;
import javax.swing.JTextField;

import ai.anomalousvectors.tools.burp.ui.text.Tooltips;

/**
 * Text field whose preferred width tracks its content length within clamped bounds.
 *
 * <p>Caller must construct and mutate on the EDT. The type has no custom transient fields or
 * deserialization reconstruction contract and is intended for live UI construction rather than
 * persisted reuse.</p>
 */
public final class AutoSizingTextField extends JTextField {
    @Serial private static final long serialVersionUID = 1L;

    private static final int DEFAULT_MIN_W = 80;
    private static final int MAX_W = 900;
    private static final int PADDING = 20;

    /**
     * Empty preferred-width floor for destination credential fields (username, tokens, paths, etc.).
     *
     * <p>Twice the default empty floor so blank auth fields stay usable before content grows them.</p>
     */
    public static final int CREDENTIAL_MIN_WIDTH = DEFAULT_MIN_W * 2;

    private final int minWidth;

    /**
     * Creates an auto-sizing text field seeded with the given text.
     *
     * <p>Caller must invoke on the EDT.</p>
     *
     * @param text initial content (nullable)
     */
    public AutoSizingTextField(String text) {
        this(text, DEFAULT_MIN_W);
    }

    /**
     * Creates an auto-sizing text field with a custom empty-width floor.
     *
     * <p>Caller must invoke on the EDT.</p>
     *
     * @param text initial content (nullable)
     * @param minWidth preferred-width floor while empty or short; clamped to at least {@code 1}
     */
    public AutoSizingTextField(String text, int minWidth) {
        super(text);
        this.minWidth = Math.max(1, minWidth);
        putClientProperty("html.disable", Boolean.FALSE);
    }

    /**
     * Computes preferred size based on content width, clamped between this field's minimum and
     * {@value MAX_W} with padding.
     *
     * @return preferred dimension reflecting current text width
     */
    /**
     * Creates this field's HTML-enabled tooltip.
     *
     * @return tooltip owned by this text field
     */
    @Override
    public Dimension getPreferredSize() {
        FontMetrics fm = getFontMetrics(getFont());
        int textWidth = fm.stringWidth(getText()) + PADDING;
        int height = super.getPreferredSize().height;
        int w = Math.clamp(textWidth, minWidth, MAX_W);
        return new Dimension(w, height);
    }

    @Override
    public JToolTip createToolTip() {
        return Tooltips.createHtmlToolTip(this);
    }
}
