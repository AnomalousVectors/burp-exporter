package ai.anomalousvectors.tools.burp.utils.export;

import java.util.Map;

/**
 * Prepared export document shared across sinks.
 *
 * <p>The record does not defensively copy the document map or serialized byte array. Callers must
 * treat both values as immutable after preparation and must not expose them to concurrent
 * mutation.</p>
 *
 * @param operationId stable search bulk operation identifier preserved across retries and spill
 *                    round-trips
 * @param indexName full target index name
 * @param indexKey short index key (for example {@code traffic})
 * @param document filtered document body
 * @param estimatedBulkBytes approximate serialized bulk payload size in bytes for chunk sizing
 * @param bulkNdjsonBytes pre-serialized bulk action+document NDJSON pair for OpenSearch flush
 */
public record PreparedExportDocument(
        String operationId,
        String indexName,
        String indexKey,
        Map<String, Object> document,
        long estimatedBulkBytes,
        byte[] bulkNdjsonBytes) {

    /**
     * Returns the byte size used for bulk chunking and retry drain caps.
     *
     * <p>Prefers the length of pre-serialized NDJSON when present so senders cannot under-count
     * against {@link ai.anomalousvectors.tools.burp.utils.opensearch.BulkByteBudget}.</p>
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
