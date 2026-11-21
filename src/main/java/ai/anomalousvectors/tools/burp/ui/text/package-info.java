/**
 * Provides text presentation, tooltip content, and document bindings for Swing views.
 *
 * <ul>
 *   <li>{@link Tooltips} supplies shared HTML formatting, popup placement, and component hooks.</li>
 *   <li>{@link ExportFieldTooltips} and {@link ExportFieldSectionTooltips} describe export fields
 *       and groups without changing their schema paths.</li>
 *   <li>{@link ValidationIndicator} and {@link RegexIndicatorBinder} present inline validity.</li>
 *   <li>{@link HighlighterManager}, {@link Doc}, and the wrapping editor/view helpers manage
 *       text-component presentation and document notifications.</li>
 * </ul>
 *
 * <p>Caller must access Swing components and documents on the EDT. Pure label and HTML-formatting
 * methods can be used without a component. Shared tooltip-manager and popup-factory setup has
 * process-wide effects; follow {@link Tooltips}' initialization and restoration contracts.</p>
 */
package ai.anomalousvectors.tools.burp.ui.text;
