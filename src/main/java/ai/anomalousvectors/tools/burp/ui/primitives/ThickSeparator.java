package ai.anomalousvectors.tools.burp.ui.primitives;

import java.awt.Dimension;
import java.io.Serial;

import javax.swing.JSeparator;

/**
 * 2px high separator for denser visual grouping.
 *
 * <p>EDT: used as a standard Swing component.</p>
 */
public final class ThickSeparator extends JSeparator {

    @Serial private static final long serialVersionUID = 1L;

    @Override
    public Dimension getPreferredSize() {
        return new Dimension(super.getPreferredSize().width, 2);
    }

    @Override
    protected void paintComponent(java.awt.Graphics g) {
        super.paintComponent(g);
        g.setColor(getForeground());
        g.fillRect(0, 1, getWidth(), 2);
    }
}
