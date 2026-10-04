/**
 * Action controller layer for the configuration UI.
 *
 * <p>{@link ai.anomalousvectors.tools.burp.ui.controller.ConfigController} owns background
 * execution for connection tests and configuration import/export, cancels or fences superseded
 * work, and reports current results on the EDT through
 * {@link ai.anomalousvectors.tools.burp.ui.controller.ConfigController.Ui}. Closing a controller
 * cancels its work and prevents callbacks into a removed extension panel.</p>
 */
package ai.anomalousvectors.tools.burp.ui.controller;
