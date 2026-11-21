package ai.anomalousvectors.tools.burp.utils.export;

import java.util.Map;

/**
 * Prepared export document shared across sinks.
 *
 * <p>The record does not defensively copy the document map or serialized byte array. Callers must
 * treat both values as immutable after preparation and must not expose them to concurrent
 * mutation.</p>
 *
 * @param operationId stable per-snapshot operation identifier preserved across retries and spill
 *                    round-trips
 * @param indexName full target index name
 * @param indexKey short index key (for example {@code traffic})
 * @param document filtered document body
 * @param estimatedBulkBytes approximate serialized bulk payload size in bytes for chunk sizing
 * @param bulkNdjsonBytes pre-serialized bulk action+document NDJSON pair for OpenSearch flush
 * @param trafficRouteKey optional internal traffic-attribution key; never serialized into the
 *                        exported document source
 * @param searchRevision optional trusted streaming replacement metadata; null keeps the
 *                       operation ID as the database ID with ordinary indexing semantics
 */
public record PreparedExportDocument(
        String operationId,
        String indexName,
        String indexKey,
        Map<String, Object> document,
        long estimatedBulkBytes,
        byte[] bulkNdjsonBytes,
        String trafficRouteKey,
        SearchDocumentRevision searchRevision) {

    /**
     * Creates an ordinary operation without streaming replacement semantics.
     *
     * @param operationId stable per-snapshot operation identifier
     * @param indexName full target index name
     * @param indexKey logical index key
     * @param document filtered document body
     * @param estimatedBulkBytes estimated bulk payload bytes
     * @param bulkNdjsonBytes serialized bulk action and source
     * @param trafficRouteKey optional internal traffic attribution
     */
    public PreparedExportDocument(String operationId, String indexName, String indexKey,
            Map<String, Object> document, long estimatedBulkBytes, byte[] bulkNdjsonBytes,
            String trafficRouteKey) {
        this(operationId, indexName, indexKey, document, estimatedBulkBytes, bulkNdjsonBytes,
                trafficRouteKey, null);
    }

    /**
     * Creates an operation without an explicit traffic-attribution route.
     *
     * <p>Non-traffic exporters and legacy callers use this form. Traffic consumers fall back to
     * the exported document's reporting tool when {@link #trafficRouteKey()} is {@code null}.</p>
     *
     * @param operationId stable search bulk operation identifier
     * @param indexName full target index name
     * @param indexKey short logical index key
     * @param document filtered document body
     * @param estimatedBulkBytes approximate serialized bulk size
     * @param bulkNdjsonBytes serialized bulk action and document pair
     */
    public PreparedExportDocument(
            String operationId,
            String indexName,
            String indexKey,
            Map<String, Object> document,
            long estimatedBulkBytes,
            byte[] bulkNdjsonBytes) {
        this(operationId, indexName, indexKey, document, estimatedBulkBytes, bulkNdjsonBytes, null);
    }

    /**
     * Returns the byte size used for bulk chunking and retry drain caps.
     *
     * <p>Prefers the length of pre-serialized NDJSON when present so senders cannot under-count
     * against {@link ai.anomalousvectors.tools.burp.utils.search.BulkByteBudget}.</p>
     *
     * @return non-negative bulk payload bytes for this document
     */
    public long resolvedBulkBytes() {
        if (bulkNdjsonBytes != null && bulkNdjsonBytes.length > 0) {
            return bulkNdjsonBytes.length;
        }
        return Math.max(0L, estimatedBulkBytes);
    }
}
