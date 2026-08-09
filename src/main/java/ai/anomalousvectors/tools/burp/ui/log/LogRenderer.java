package ai.anomalousvectors.tools.burp.ui.log;

import java.awt.Dimension;
import java.awt.Point;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Objects;

import javax.swing.JViewport;
import javax.swing.SwingUtilities;
import javax.swing.text.AbstractDocument;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;
import javax.swing.text.Element;
import javax.swing.text.JTextComponent;

import ai.anomalousvectors.tools.burp.utils.Logger;

/**
 * Renderer: writes/replaces lines in the document, formats output, and autoscrolls.
 * Uses plain text (no per-level styling) so the log can use JTextArea with line wrap.
 *
 * <p><strong>Threading:</strong> expected on the EDT.</p>
 *
 * <p><strong>State:</strong> bookkeeping for "the last rendered line" is read directly from the
 * document's line element model rather than cached. This keeps {@link #replaceLast} correct
 * even when other callers (for example {@link #removeLeadingLines}) have shifted the document
 * underneath us during an incremental trim.</p>
 *
 * <p><strong>Autoscroll:</strong> scrolls the enclosing {@link JViewport} without moving the caret.
 * Caret updates ({@code setCaretPosition} / {@code ALWAYS_UPDATE}) can steal focus from Log
 * toolbar controls while entries stream.</p>
 */
public final class LogRenderer {

    private final Document doc;
    private final JTextComponent component;
    private final Runnable scrollToEnd;

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /**
     * Creates a renderer bound to the provided text component (e.g. JTextArea for line wrap).
     *
     * <p>Caller must construct on the EDT.</p>
     *
     * @param textComponent target component to render into (must have an AbstractDocument)
     */
    public LogRenderer(JTextComponent textComponent) {
        this.component = Objects.requireNonNull(textComponent, "textComponent");
        this.doc = component.getDocument();
        this.scrollToEnd = this::scrollViewportToEnd;
    }

    /**
     * Clears all rendered content.
     *
     * <p>EDT only.</p>
     */
    public void clear() {
        try {
            if (doc instanceof AbstractDocument ad) {
                ad.remove(0, doc.getLength());
            }
        } catch (BadLocationException ex) {
            Logger.internalDebug("LogRenderer.clear: " + ex);
        }
    }

    /**
     * Appends a formatted line to the document.
     *
     * @param line  text to append (should include trailing newline)
     * @param level log level (unused; kept for API compatibility)
     */
    public void append(String line, LogStore.Level level) {
        try {
            if (doc instanceof AbstractDocument ad) {
                ad.insertString(doc.getLength(), line, null);
            }
        } catch (BadLocationException ex) {
            Logger.internalDebug("LogRenderer.append: " + ex);
        }
    }

    /**
     * Replaces the document's final content line (the last newline-terminated line) with
     * {@code line}. No-op when the document is empty.
     *
     * @param line  replacement text (should include trailing newline)
     * @param level log level (unused; kept for API compatibility)
     */
    public void replaceLast(String line, LogStore.Level level) {
        try {
            if (!(doc instanceof AbstractDocument ad)) return;
            int[] bounds = lastContentLineBounds();
            if (bounds == null) {
                ad.insertString(doc.getLength(), line, null);
                return;
            }
            int start = bounds[0];
            int len = bounds[1] - start;
            if (len > 0) ad.remove(start, len);
            ad.insertString(start, line, null);
        } catch (BadLocationException ex) {
            Logger.internalDebug("LogRenderer.replaceLast: " + ex);
        }
    }

    /**
     * Removes the first {@code lineCount} content lines from the document in a single
     * {@link AbstractDocument#remove} call. Used by incremental trim so the renderer never
     * has to clear and re-append the entire document just to drop a few head entries.
     *
     * @param lineCount number of leading newline-terminated lines to remove (clamped to the
     *                  number of content lines actually present)
     */
    public void removeLeadingLines(int lineCount) {
        if (lineCount <= 0) return;
        if (!(doc instanceof AbstractDocument ad)) return;
        try {
            Element root = doc.getDefaultRootElement();
            int contentLines = contentLineCount(doc, root);
            int toRemove = Math.min(lineCount, contentLines);
            if (toRemove <= 0) return;
            int endOffset = Math.min(root.getElement(toRemove - 1).getEndOffset(), doc.getLength());
            if (endOffset > 0) ad.remove(0, endOffset);
        } catch (BadLocationException ex) {
            Logger.internalDebug("LogRenderer.removeLeadingLines: " + ex);
        }
    }

    /**
     * Inserts {@code text} at offset 0. Intended for the suffix-diff trim path where a new
     * leading prefix replaces a removed one; callers concatenate multiple lines into a single
     * string so a single {@link AbstractDocument#insertString} call covers them all.
     *
     * @param text text to prepend (each logical line should already end in {@code "\n"})
     */
    public void prependLines(String text) {
        if (text == null || text.isEmpty()) return;
        if (!(doc instanceof AbstractDocument ad)) return;
        try {
            ad.insertString(0, text, null);
        } catch (BadLocationException ex) {
            Logger.internalDebug("LogRenderer.prependLines: " + ex);
        }
    }

    /**
     * Scrolls to the bottom unless paused.
     *
     * <p>Moves only the enclosing viewport. Does not change caret position or request focus.</p>
     *
     * @param paused when {@code true}, leaves the viewport unchanged
     */
    public void autoscrollIfNeeded(boolean paused) {
        if (!paused) {
            scrollToEnd.run();
        }
    }

    /**
     * Formats a log entry into a single rendered line.
     *
     * @param ts      timestamp (fallbacks to now when null)
     * @param lvl     log level
     * @param msg     log message (nullable)
     * @param repeats duplicate count; {@code >1} renders as {@code (xN)}
     * @return formatted line including trailing newline
     */
    public String formatLine(LocalDateTime ts, LogStore.Level lvl, String msg, int repeats) {
        String timestamp = "[" + TS.format(ts == null ? LocalDateTime.now() : ts) + "]";
        String base = String.format("%s [%s] %s", timestamp, lvl.name(), msg == null ? "" : msg);
        return repeats > 1 ? base + "  (x" + repeats + ")\n" : base + "\n";
    }

    /**
     * Scrolls the enclosing viewport to the bottom of the log document without moving the caret.
     */
    private void scrollViewportToEnd() {
        JViewport viewport = (JViewport) SwingUtilities.getAncestorOfClass(JViewport.class, component);
        if (viewport == null) {
            return;
        }
        component.revalidate();
        Dimension extent = viewport.getExtentSize();
        Dimension viewSize = component.getPreferredSize();
        int maxY = Math.max(0, viewSize.height - extent.height);
        Point current = viewport.getViewPosition();
        if (current.x != 0 || current.y != maxY) {
            viewport.setViewPosition(new Point(0, maxY));
        }
    }

    /**
     * Returns {@code [startOffset, endOffsetClamped]} of the document's last content line, or
     * {@code null} when the document has no content lines. Skips {@code PlainDocument}'s
     * synthetic empty trailing element (which represents the implicit position immediately
     * after the final {@code "\n"}).
     *
     * <p>End offsets are clamped to {@link Document#getLength()}: a {@code PlainDocument}
     * line element on the last line reports an end offset of {@code getLength() + 1} to
     * cover the implicit "next position", but {@link AbstractDocument#remove} validates
     * against {@code getLength()} and would otherwise reject the call.</p>
     */
    private int[] lastContentLineBounds() {
        Element root = doc.getDefaultRootElement();
        int n = root.getElementCount();
        if (n == 0) return null;
        int docLen = doc.getLength();
        Element last = root.getElement(n - 1);
        if (last.getStartOffset() >= docLen) {
            if (n < 2) return null;
            last = root.getElement(n - 2);
            if (last.getStartOffset() >= docLen) return null;
        }
        int start = last.getStartOffset();
        int end = Math.min(last.getEndOffset(), docLen);
        if (end <= start) return null;
        return new int[] { start, end };
    }

    /**
     * Number of content lines in the document. Each line whose start offset is below
     * {@link Document#getLength()} counts; the synthetic empty trailing element (whose
     * start offset equals {@code getLength()}) does not.
     */
    private static int contentLineCount(Document doc, Element root) {
        int n = root.getElementCount();
        if (n == 0) return 0;
        int docLen = doc.getLength();
        Element last = root.getElement(n - 1);
        return (last.getStartOffset() >= docLen) ? (n - 1) : n;
    }
}
