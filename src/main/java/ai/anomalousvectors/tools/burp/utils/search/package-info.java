/**
 * Connects search database destinations and coordinates authenticated, bounded delivery.
 *
 * <p>Shared paths serve OpenSearch, Amazon OpenSearch, and Elasticsearch. Endpoint validation,
 * deployment detection, mapping adaptation, and connection tests feed the destination facade
 * {@link SearchClientWrapper}. Product-specific support, such as {@link AmazonOpenSearchSigV4},
 * keeps the product name where it identifies an actual protocol or deployment requirement.</p>
 *
 * <ul>
 *   <li>{@link PreparedBulkSender} delivers prepared snapshot and retry operations.
 *       {@link ChunkedBulkSender} drains bounded live traffic batches. Compatibility callers of
 *       {@link SearchClientWrapper#doPushBulkWithDetails} prepare documents before using the
 *       same byte-budgeted delivery path.</li>
 *   <li>{@link BulkNdjsonResponseParser} classifies item outcomes; senders reconcile them with
 *       the attempted batch before accounting or retry. Prepared operation identities survive
 *       retries, and database retries do not append the same documents to Files again.</li>
 *   <li>{@link BatchSizeController}, {@link BulkByteBudget}, {@link OfferedLoadGovernor}, and
 *       {@link BulkRateLimitBackoff} bound count, bytes, offered load, concurrency, and cooldowns.</li>
 *   <li>{@link IndexingRetryCoordinator} retains transient failures, coordinates authorization
 *       recovery, and distinguishes permanent item rejection from recoverable pressure.</li>
 * </ul>
 *
 * <p>Network calls, credential-provider resolution, certificate import, cooldown waits, and
 * retry drains can block and must run off the EDT. Shared clients have explicit close/reset
 * contracts. Callers must preserve prepared operation identities and export-run fences;
 * snapshot scheduling belongs to {@link ai.anomalousvectors.tools.burp.utils.concurrent}.</p>
 */
package ai.anomalousvectors.tools.burp.utils.search;
