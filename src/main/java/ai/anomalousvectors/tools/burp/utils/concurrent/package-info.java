/**
 * Concurrency helpers shared by sinks, UI, and retry paths.
 *
 * <p>Contains small utilities that every extension-owned background worker uses so lifecycle
 * semantics stay consistent across UI stop and extension unload:</p>
 * <ul>
 *   <li>{@link ai.anomalousvectors.tools.burp.utils.concurrent.Workers} centralizes the
 *       "{@code shutdownNow} + {@code awaitTermination}" and "{@code interrupt} + {@code join}"
 *       patterns for {@link java.util.concurrent.ExecutorService} and raw
 *       {@link java.lang.Thread} owners.</li>
 *   <li>{@link ai.anomalousvectors.tools.burp.utils.concurrent.LazyScheduler} owns the
 *       "{@code volatile} field + {@code synchronized} ensure-started + {@link
 *       ai.anomalousvectors.tools.burp.utils.concurrent.Workers} shutdown" pattern used by every
 *       reporter and by the orphan-flush path so lazy start and deterministic teardown are
 *       implemented in one place.</li>
 *   <li>{@link ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotExportEngine} runs parallel
 *       {@code build + prepare} on worker threads with overlapping bulk flushes, while serializing
 *       whole engine runs and bounding prepared build-ahead by both count and bytes. Used by Proxy
 *       History, Sitemap initial, Findings backlog, and Proxy WebSocket historic snapshots.</li>
 *   <li>{@link ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotFlushExecutor} owns the
 *       separate shared pools for whole-chunk flushes and nested dual-sink work, preserving the
 *       no-pool-nesting invariant required to avoid deadlock.</li>
 *   <li>{@link ai.anomalousvectors.tools.burp.utils.concurrent.StartupSnapshotCoordinator} queues
 *       those startup snapshot steps in ConfigPanel order (Findings → Sitemap → Proxy History →
 *       WebSocket). Reporters re-queue lane continuations after each engine run and share adaptive
 *       per-lane wall-time targeting, so sources interleave without raising engine concurrency.
 *       Stop removes queued work and cooperatively cancels token-scoped engine activity.</li>
 *   <li>{@link ai.anomalousvectors.tools.burp.utils.concurrent.ExportRunContext} carries the
 *       current export-run token through asynchronous flush work so late outcomes cannot mutate
 *       accounting after Stop or a later Start.</li>
 *   <li>{@link ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotPacing} and
 *       {@link ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotScopeCache} throttle and
 *       memoize scope checks during large one-shot exports.</li>
 * </ul>
 */
package ai.anomalousvectors.tools.burp.utils.concurrent;
