/**
 * Common utilities shared across the extension.
 *
 * <p>Includes logging ({@link ai.anomalousvectors.tools.burp.utils.Logger}), export pressure log
 * throttling ({@link ai.anomalousvectors.tools.burp.utils.ExportPressureLogThrottler}), admission
 * budgets ({@link ai.anomalousvectors.tools.burp.utils.ExportAdmissionController}), runtime stats,
 * filesystem helpers, UI-control bridges, and small helpers reused by UI and sinks. Most APIs are
 * thread-safe and UI-agnostic; individual methods document listener-thread or EDT requirements.</p>
 */
package ai.anomalousvectors.tools.burp.utils;
