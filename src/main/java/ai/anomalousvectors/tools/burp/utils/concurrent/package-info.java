/**
 * Coordinates background ownership, bounded snapshot work, and export-run fencing.
 *
 * <p>The main collaboration points are:</p>
 * <ul>
 *   <li>{@link ai.anomalousvectors.tools.burp.utils.concurrent.Workers} centralizes the
 *       "{@code shutdownNow} + {@code awaitTermination}" and "{@code interrupt} + {@code join}"
 *       patterns for {@link java.util.concurrent.ExecutorService} and raw
 *       {@link java.lang.Thread} owners.</li>
 *   <li>{@link ai.anomalousvectors.tools.burp.utils.concurrent.LazyScheduler} owns lazy scheduler
 *       creation and bounded shutdown for recurring background work.</li>
 *   <li>{@link ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotExportEngine} runs parallel
 *       {@code build + prepare} on worker threads with overlapping bulk flushes, while serializing
 *       whole engine runs. Shared estimated-memory admission precedes construction and remains
 *       held through delivery; the prepared queue also has a count bound. Used by Proxy
 *       History, Sitemap initial, Findings backlog, and Proxy WebSocket historic snapshots.</li>
 *   <li>{@link ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotFlushExecutor} owns the
 *       separate shared pools for whole-chunk flushes and nested dual-sink work, preserving the
 *       no-pool-nesting invariant required to avoid deadlock.</li>
 *   <li>{@link ai.anomalousvectors.tools.burp.utils.concurrent.StartupSnapshotCoordinator} queues
 *       startup snapshot lanes. Reporters re-queue continuations after each engine run and share
 *       adaptive per-lane wall-time targeting, so sources interleave without raising engine concurrency.
 *       Stop removes queued work and cooperatively cancels token-scoped engine activity.</li>
 *   <li>{@link ai.anomalousvectors.tools.burp.utils.concurrent.ExportRunContext} carries the
 *       captured export-run token through explicitly scoped asynchronous work so stale outcomes
 *       can be rejected. The thread-local context is not inherited by child threads.</li>
 *   <li>{@link ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotPacing} and
 *       {@link ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotScopeCache} throttle and
 *       memoize scope checks during large one-shot exports.
 *       {@link ai.anomalousvectors.tools.burp.utils.concurrent.EdtMonitor} diagnoses UI stalls.</li>
 * </ul>
 *
 * <p>Shutdown waits and snapshot destination work must run off the EDT. Cancellation is
 * cooperative and waits are bounded; a wait returning does not guarantee that non-cooperative
 * external work has terminated. Owners must propagate run tokens and honor publication fences.</p>
 */
package ai.anomalousvectors.tools.burp.utils.concurrent;
