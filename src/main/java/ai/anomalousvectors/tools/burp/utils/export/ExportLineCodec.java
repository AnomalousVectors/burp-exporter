package ai.anomalousvectors.tools.burp.utils.export;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/**
 * Serializes prepared export documents into line-oriented sink formats.
 */
public final class ExportLineCodec {

    private static final ObjectMapper JSON = JsonMapper.builderWithJackson2Defaults().build();

    private ExportLineCodec() { }

    /**
     * Returns one JSONL line for the provided document body.
     *
     * @param document document source
     * @return newline-terminated JSON source line
     * @throws JacksonException when the source cannot be serialized
     */
    public static String jsonDocumentLine(Map<String, Object> document) throws JacksonException {
        return JSON.writeValueAsString(document) + "\n";
    }

    /**
     * Returns the two bulk NDJSON lines for the provided prepared document.
     *
     * @param document prepared operation
     * @return action and source lines, each newline-terminated
     * @throws JacksonException when action metadata or source cannot be serialized
     * @throws IllegalArgumentException if the operation identifier is null or blank
     * @throws NullPointerException if {@code document} is null
     */
    public static List<String> bulkNdjsonLines(PreparedExportDocument document) throws JacksonException {
        return List.of(
                bulkIndexActionLine(document.operationId(), document.searchRevision()),
                jsonDocumentLine(document.document())
        );
    }

    /**
     * Writes one bulk NDJSON action/document pair to the target stream.
     *
     * @param output destination stream
     * @param document prepared operation
     * @throws IOException when serialization or writing fails
     * @throws IllegalArgumentException if the operation identifier is null or blank
     * @throws NullPointerException if {@code output} or {@code document} is null
     */
    public static void writeBulkNdjson(OutputStream output, PreparedExportDocument document) throws IOException {
        try {
            output.write(bulkIndexActionBytes(document.operationId(), document.searchRevision()));
            JSON.writeValue(output, document.document());
            output.write('\n');
        } catch (JacksonException e) {
            // File/retry owners handle serialization failures through their checked-I/O path.
            throw new IOException("Bulk NDJSON serialization failed.", e);
        }
    }

    /**
     * Returns the bulk NDJSON action/document pair bytes for one prepared operation.
     *
     * @param operationId non-blank stable bulk operation identifier
     * @param document document source; the identifier is written only to action metadata
     * @return serialized action and source lines
     * @throws IOException when serialization fails
     * @throws IllegalArgumentException if {@code operationId} is null or blank
     */
    public static byte[] bulkNdjsonBytes(String operationId, Map<String, Object> document) throws IOException {
        return bulkNdjsonBytes(operationId, document, null);
    }

    /**
     * Serializes an operation with optional trusted streaming replacement metadata.
     *
     * @param operationId non-blank per-snapshot operation ID
     * @param document source document
     * @param revision trusted database identity/version, or null for an ordinary operation
     * @return complete action/source pair
     * @throws IOException if serialization fails
     * @throws IllegalArgumentException if the operation ID is blank
     */
    public static byte[] bulkNdjsonBytes(String operationId, Map<String, Object> document,
            SearchDocumentRevision revision) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream(256);
        try {
            output.write(bulkIndexActionBytes(operationId, revision));
            JSON.writeValue(output, document);
            output.write('\n');
        } catch (JacksonException e) {
            throw new IOException("Bulk NDJSON serialization failed.", e);
        }
        return output.toByteArray();
    }

    private static String bulkIndexActionLine(String operationId, SearchDocumentRevision revision)
            throws JacksonException {
        requireOperationId(operationId);
        Map<String, Object> action = revision == null
                ? Map.of("_id", operationId)
                : Map.of("_id", revision.documentId(), "version", revision.version(),
                        "version_type", "external");
        return JSON.writeValueAsString(Map.of("index", action)) + "\n";
    }

    private static byte[] bulkIndexActionBytes(String operationId, SearchDocumentRevision revision)
            throws JacksonException {
        return bulkIndexActionLine(operationId, revision).getBytes(StandardCharsets.UTF_8);
    }

    private static String requireOperationId(String operationId) {
        if (operationId == null || operationId.isBlank()) {
            throw new IllegalArgumentException("operationId must not be blank");
        }
        return operationId;
    }
}
