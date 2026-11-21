/**
 * Composes the extension's Config, Log, Stats, and About views.
 *
 * <p>The {@link ai.anomalousvectors.tools.burp.ui.BurpExporterPanel} is the top-level tab
 * added to Burp. It embeds dedicated subpanels for configuration
 * ({@link ai.anomalousvectors.tools.burp.ui.ConfigPanel}), logging
 * ({@link ai.anomalousvectors.tools.burp.ui.LogPanel}), statistics, and the about box.</p>
 *
 * <p>{@link ai.anomalousvectors.tools.burp.ui.ConfigPanel} composes the configuration subpanels
 * and binds their controls to typed runtime state. It delegates connection tests and
 * configuration import/export to
 * {@link ai.anomalousvectors.tools.burp.ui.controller.ConfigController}, which coordinates
 * background tasks and reports results through the
 * {@link ai.anomalousvectors.tools.burp.ui.controller.ConfigController.Ui} callback surface.
 * The controller never touches Swing components directly; it communicates via status strings
 * and typed state objects.</p>
 *
 * <p>Caller must construct and mutate Swing views on the EDT. Background owners perform
 * destination and filesystem work; immutable display snapshots and status callbacks carry
 * results back to the views. Pure formatting helpers do not require Swing access.</p>
 */
package ai.anomalousvectors.tools.burp.ui;
