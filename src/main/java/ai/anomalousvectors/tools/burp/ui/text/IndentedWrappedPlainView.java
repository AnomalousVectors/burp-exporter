package ai.anomalousvectors.tools.burp.ui.text;

import java.awt.Graphics2D;

import javax.swing.text.BadLocationException;
import javax.swing.text.Document;
import javax.swing.text.Element;
import javax.swing.text.WrappedPlainView;

/**
 * Wrapped plain view that indents continuation lines (wrapped segments after the first
 * visual line of each logical line) by a fixed pixel amount so wrapped log lines are
 * easier to scan.
 */
public final class IndentedWrappedPlainView extends WrappedPlainView {

    private static final int CONTINUATION_INDENT = 16;

    /**
     * Creates a word-wrapping view for one document element.
     *
     * <p>Caller must invoke on the EDT when attaching the view to a Swing text component.</p>
     *
     * @param elem document element represented by this view
     */
    public IndentedWrappedPlainView(Element elem) {
        super(elem, true);
    }

    /**
     * Adds continuation indent for wrapped lines: if this segment does not start
     * a logical line (character before p0 is not newline), draw with indent.
     */
    @Override
    protected void drawLine(int p0, int p1, Graphics2D g, float x, float y) {
        int indent = continuationIndent(p0);
        super.drawLine(p0, p1, g, x + indent, y);
    }

    private int continuationIndent(int p0) {
        if (p0 <= 0) return 0;
        Document doc = getDocument();
        if (doc == null) return 0;
        try {
            String s = doc.getText(p0 - 1, 1);
            return "\n".equals(s) ? 0 : CONTINUATION_INDENT;
        } catch (BadLocationException e) {
            return 0;
        }
    }
}
