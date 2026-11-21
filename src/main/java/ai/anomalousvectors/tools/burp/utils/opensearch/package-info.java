/**
 * Delivers search bulk requests with authentication, adaptive capacity control, and retries.
 *
 * <p>Despite the package name, these shared transport paths serve OpenSearch, Amazon OpenSearch,
 * and Elasticsearch. Destination-neutral endpoint, deployment, and mapping adaptation helpers
 * live in {@link ai.anomalousvectors.tools.burp.utils.search}.</p>
 *
 * <p>Three bulk entry paths serve different workloads:</p>
 * <ul>
 *   <li>{@link PreparedBulkSender} and
 *       {@link OpenSearchClientWrapper#pushPreparedBulk}
 *       — pre-serialized NDJSON over raw HTTP. Used by
 *       {@link ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotExportEngine} snapshot
 *       reporters (Proxy History, Sitemap initial, Findings backlog, Proxy WebSocket historic)
 *       and by the {@link IndexingRetryCoordinator} drain thread, which reuses existing prepared
 *       operation identities. Search-only fitting can derive a smaller copy without changing
 *       the queued original.</li>
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
 * <p>{@link BatchSizeController}, {@link BulkByteBudget}, and {@link OfferedLoadGovernor} bound
 * batch count, request bytes, in-flight work, and offered load. {@link BulkRateLimitBackoff}
 * coordinates shared or per-index cooldowns. {@link IndexingRetryCoordinator} retains transient
 * failures, pauses for authorization recovery, and distinguishes permanent item rejection from
 * recoverable destination pressure. Startup snapshot scheduling remains in
 * {@link ai.anomalousvectors.tools.burp.utils.concurrent}.</p>
 *
 * <p>Bulk paths share {@link BulkNdjsonResponseParser} for item-outcome parsing and failure logging.
 * Senders reconcile those outcomes with the attempted batch before retry or accounting. Initial
 * dual-destination delivery also gives the original prepared documents to
 * {@link ai.anomalousvectors.tools.burp.sinks.FileExportService}; database retries never append
 * those documents to Files again.</p>
 *
 * <p>Network calls, credential-provider resolution, cooldown waits, and retry drains can block
 * and must run off the EDT. Shared clients and background owners have explicit close/reset
 * contracts; callers must preserve prepared operation identities and export-run fences.</p>
 */
package ai.anomalousvectors.tools.burp.utils.opensearch;
