/**
 * Supplies cross-cutting logging, accounting, storage, and integration helpers.
 *
 * <p>Includes logging ({@link ai.anomalousvectors.tools.burp.utils.Logger}), export pressure log
 * throttling ({@link ai.anomalousvectors.tools.burp.utils.ExportPressureLogThrottler}), admission
 * budgets ({@link ai.anomalousvectors.tools.burp.utils.ExportAdmissionController}), runtime stats,
 * managed filesystem storage, UI-control bridges, scope checks, index naming, and Burp runtime
 * metadata. Specialized configuration, concurrency, export preparation, search transport, and
 * text-search responsibilities belong to their respective subpackages.</p>
 *
 * <p>Threading and side effects depend on the helper: counters and logging accept background
 * producers, storage helpers can block on disk I/O, and UI bridges define callback-thread or EDT
 * requirements. Follow each API's contract rather than assuming package-wide thread safety.</p>
 */
package ai.anomalousvectors.tools.burp.utils;
