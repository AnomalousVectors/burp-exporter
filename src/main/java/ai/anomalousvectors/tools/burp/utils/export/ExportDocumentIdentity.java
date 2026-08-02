package ai.anomalousvectors.tools.burp.utils.export;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Map;
import java.util.UUID;

import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.config.ExportFieldFilter;

/**
 * Filters and serializes export documents shared across sinks.
 *
 * <p>Each prepared operation receives one client-generated identifier. The identifier is carried in
 * bulk action metadata, never in {@code _source}, and remains stable when that prepared operation is
 * retried, fitted to a smaller search budget, or persisted through spill storage.</p>
 */
public final class ExportDocumentIdentity {

    private ExportDocumentIdentity() { }

    /**
     * Filters and returns a sink-ready export document for the provided logical key.
     *
     * @param indexName full target index name
     * @param indexKey short logical index key
     * @param document document source; {@code null} is filtered to an empty map
     * @return newly identified and serialized prepared operation
     * @throws IllegalArgumentException if a blank index key cannot be derived from
     *                                  {@code indexName}
     * @throws UncheckedIOException if the filtered source cannot be serialized
     */
    public static PreparedExportDocument prepare(String indexName, String indexKey, Map<String, Object> document) {
        return preparePreservingOperationId(
                UUID.randomUUID().toString(), indexName, indexKey, document);
    }

    /**
     * Filters and prepares a document while preserving an existing operation identifier.
     *
     * <p>Callers use this only when deriving another representation of the same logical prepared
     * operation, such as a search-only fitted copy. A new logical export must use
     * {@link #prepare(String, String, Map)}.</p>
     *
     * @param operationId non-blank identifier assigned by the original preparation
     * @param indexName full target index name
     * @param indexKey short logical index key
     * @param document document source; {@code null} is filtered to an empty map
     * @return prepared document with action metadata containing the same identifier
     * @throws IllegalArgumentException if {@code operationId} is blank or a blank index key cannot
     *                                  be derived from {@code indexName}
     * @throws UncheckedIOException if the filtered source cannot be serialized
     */
    public static PreparedExportDocument preparePreservingOperationId(
            String operationId,
            String indexName,
            String indexKey,
            Map<String, Object> document) {
        String normalizedIndexKey = normalizeIndexKey(indexName, indexKey);
        Map<String, Object> filtered = ExportFieldFilter.filterDocument(document, normalizedIndexKey);
        return serialize(operationId, indexName, normalizedIndexKey, filtered);
    }

    /**
     * Re-serializes an already-filtered derived source while preserving operation identity.
     *
     * <p>This is reserved for search-side structural fitting. It intentionally does not apply the
     * user field filter a second time because fitting adds integrity markers after the original
     * source was filtered. A null derived source is serialized as an empty map.</p>
     *
     * @param original non-null original prepared operation
     * @param derivedDocument derived search source, or {@code null} for an empty source
     * @return prepared derived copy with the original operation identifier
     * @throws IllegalArgumentException if {@code original} is null, its operation identifier is
     *                                  blank, or its logical index key cannot be derived
     * @throws UncheckedIOException if the derived source cannot be serialized
     */
    public static PreparedExportDocument reprepareDerived(
            PreparedExportDocument original,
            Map<String, Object> derivedDocument) {
        if (original == null) {
            throw new IllegalArgumentException("original must not be null");
        }
        String normalizedIndexKey = normalizeIndexKey(original.indexName(), original.indexKey());
        return serialize(
                original.operationId(),
                original.indexName(),
                normalizedIndexKey,
                derivedDocument == null ? Map.of() : derivedDocument);
    }

    private static String normalizeIndexKey(String indexName, String indexKey) {
        return indexKey == null || indexKey.isBlank()
                ? IndexNaming.requireKnownIndexKey(indexName)
                : indexKey.trim().toLowerCase(java.util.Locale.ROOT);
    }

    private static PreparedExportDocument serialize(
            String operationId,
            String indexName,
            String normalizedIndexKey,
            Map<String, Object> document) {
        if (operationId == null || operationId.isBlank()) {
            throw new IllegalArgumentException("operationId must not be blank");
        }
        byte[] bulkNdjsonBytes;
        try {
            bulkNdjsonBytes = ExportLineCodec.bulkNdjsonBytes(operationId, document);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return new PreparedExportDocument(
                operationId,
                indexName,
                normalizedIndexKey,
                document,
                bulkNdjsonBytes.length,
                bulkNdjsonBytes);
    }
}
