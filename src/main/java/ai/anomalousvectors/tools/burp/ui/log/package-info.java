/**
 * Stores, filters, and renders entries for the extension's Log panel.
 *
 * <p>{@link ai.anomalousvectors.tools.burp.ui.log.LogStore} holds a bounded in-memory log model,
 * compacts consecutive duplicates, and derives filtered aggregates.
 * {@link ai.anomalousvectors.tools.burp.ui.log.LogRenderer} applies incremental appends,
 * replacements, and trims to the panel's {@code JTextPane}. Log production and listener delivery
 * remain in {@link ai.anomalousvectors.tools.burp.utils.Logger}.</p>
 *
 * <p>The model is not thread-safe. The Log panel confines model access and Swing rendering to
 * the EDT; callers must not concurrently mutate the store or its rendered document.</p>
 */
package ai.anomalousvectors.tools.burp.ui.log;
