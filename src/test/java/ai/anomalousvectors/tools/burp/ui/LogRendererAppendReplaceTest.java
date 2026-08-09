package ai.anomalousvectors.tools.burp.ui;

import ai.anomalousvectors.tools.burp.ui.log.LogRenderer;
import ai.anomalousvectors.tools.burp.ui.log.LogStore;
import org.junit.jupiter.api.Test;

import java.awt.Dimension;
import java.awt.Point;

import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JViewport;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Document rendering operations.
 *
 * <p>Validates append/replace behavior, formatted output, and viewport autoscroll that does not
 * move the caret (caret moves steal focus from Log toolbar controls).</p>
 */
class LogRendererAppendReplaceTest {

    /**
     * Appending then replacing the last line updates the document text,
     * and autoscroll moves the viewport without moving the caret.
     */
    @Test
    void append_then_replaceLast_updates_document_and_autoscroll_moves_viewport() throws Exception {
        JTextArea pane = new JTextArea();
        pane.setLineWrap(true);
        JScrollPane scroll = new JScrollPane(pane);
        scroll.setPreferredSize(new Dimension(240, 80));
        scroll.setSize(240, 80);
        pane.setSize(240, 80);
        LogRenderer r = new LogRenderer(pane);

        String line1 = r.formatLine(java.time.LocalDateTime.now(), LogStore.Level.INFO, "one", 1);
        StringBuilder tall = new StringBuilder();
        for (int i = 0; i < 40; i++) {
            tall.append(r.formatLine(java.time.LocalDateTime.now(), LogStore.Level.INFO, "seed-" + i, 1));
        }
        r.append(tall.toString(), LogStore.Level.INFO);
        r.append(line1, LogStore.Level.INFO);
        assertTrue(pane.getDocument().getText(0, pane.getDocument().getLength()).endsWith(line1));

        String line2 = r.formatLine(java.time.LocalDateTime.now(), LogStore.Level.ERROR, "two", 3);
        r.replaceLast(line2, LogStore.Level.ERROR);
        assertTrue(pane.getDocument().getText(0, pane.getDocument().getLength()).endsWith(line2));

        pane.setCaretPosition(0);
        JViewport viewport = scroll.getViewport();
        viewport.setViewPosition(new Point(0, 0));
        r.autoscrollIfNeeded(false);

        assertEquals(0, pane.getCaretPosition());
        int maxY = Math.max(0, pane.getPreferredSize().height - viewport.getExtentSize().height);
        assertTrue(maxY > 0);
        assertEquals(maxY, viewport.getViewPosition().y);
    }
}
