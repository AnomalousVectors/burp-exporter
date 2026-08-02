/**
 * OpenSearch transport utilities shared by all sinks that push to OpenSearch.
 *
 * <p>Three bulk strategies serve different workloads:</p>
 * <ul>
 *   <li>{@link PreparedBulkSender} and
 *       {@link OpenSearchClientWrapper#pushPreparedBulk}
 *       — pre-serialized NDJSON over raw HTTP. Used by
 *       {@link ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotExportEngine} snapshot
 *       reporters (Proxy History, Sitemap initial, Findings backlog, Proxy WebSocket historic)
 *       and by the {@link IndexingRetryCoordinator}
 *       drain thread after re-prepare.</li>
 *   <li>{@link ChunkedBulkSender} — queue drain
 *       used by the live traffic path. It materializes one bounded NDJSON body for signing and
 *       transport while avoiding a Java-client bulk request graph
 *       ({@link ai.anomalousvectors.tools.burp.sinks.TrafficExportQueue}). Reuses
 *       {@code bulkNdjsonBytes} from prepare when posting each chunk.</li>
 *   <li>{@link OpenSearchClientWrapper#doPushBulkWithDetails}
 *       — compatibility path for callers without pre-serialized bytes. It prepares documents and
 *       delegates to the same byte-budgeted sender used by prepared bulk operations.</li>
 * </ul>
 *
 * <p>Batch sizing is governed by
 * {@link BatchSizeController} for live traffic and
 * most incremental reporters. Proxy History snapshot uses local chunk targets (100–1500) with
 * live-queue and GC backpressure. All search destinations share
 * {@link BulkByteBudget} AIMD control (all adaptive
 * destinations start at 1 MiB with one in-flight flush; floor 512 KiB; grow/shrink under pressure;
 * asymmetric restore after soft-outage clear; metric-driven ceiling climb and up to three in-flight
 * snapshot flushes after a healthy success streak) and may briefly serialize snapshot flushes after
 * hard capacity pressure.
 * {@link BulkRateLimitBackoff} keeps hard
 * gateway/transport cooldowns cluster-wide, scopes mild per-item capacity cooldowns per index, and
 * caps Stop-drain cooldown waits so shutdown can still attempt recovery. Soft-outage drain keeps
 * the normal cadence while work is queued. Gateway/timeout health-probe failures enter soft outage
 * (queue + back off) instead of auto-disabling the destination.</p>
 *
 * <p>All paths share
 * {@link BulkNdjsonResponseParser} for per-item
 * failure logging and converge on {@link ai.anomalousvectors.tools.burp.sinks.FileExportService}
 * for file output.</p>
 */
package ai.anomalousvectors.tools.burp.utils.opensearch;
