/**
 * Integrates Burp Exporter with the Montoya extension lifecycle.
 *
 * <p>{@link ai.anomalousvectors.tools.burp.Exporter} initializes shared services, registers the
 * extension tab and traffic handlers, and coordinates cleanup on unload. UI composition belongs
 * to {@link ai.anomalousvectors.tools.burp.ui}; source capture and destination delivery belong
 * to {@link ai.anomalousvectors.tools.burp.sinks}.</p>
 *
 * <p>Swing setup is dispatched to the EDT. Background owners manage export work and shutdown;
 * their individual lifecycle contracts define cancellation and bounded waits.</p>
 */
package ai.anomalousvectors.tools.burp;
