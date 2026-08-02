package ai.anomalousvectors.tools.burp.utils.export;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Serializes prepared export documents into line-oriented sink formats.
 */
public final class ExportLineCodec {

    private static final ObjectMapper JSON = new ObjectMapper();

    private ExportLineCodec() { }

    /**
     * Returns one JSONL line for the provided document body.
     *
     * @param document document source
     * @return newline-terminated JSON source line
     * @throws JsonProcessingException when the source cannot be serialized
     */
    public static String jsonDocumentLine(Map<String, Object> document) throws JsonProcessingException {
        return JSON.writeValueAsString(document) + "\n";
    }

    /**
     * Returns the two bulk NDJSON lines for the provided prepared document.
     *
     * @param document prepared operation
     * @return action and source lines, each newline-terminated
     * @throws JsonProcessingException when action metadata or source cannot be serialized
     * @throws IllegalArgumentException if the operation identifier is null or blank
     * @throws NullPointerException if {@code document} is null
     */
    public static List<String> bulkNdjsonLines(PreparedExportDocument document) throws JsonProcessingException {
        return List.of(
                bulkIndexActionLine(document.operationId()),
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
        output.write(bulkIndexActionBytes(document.operationId()));
        JSON.writeValue(output, document.document());
        output.write('\n');
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
        ByteArrayOutputStream output = new ByteArrayOutputStream(256);
        output.write(bulkIndexActionBytes(operationId));
        JSON.writeValue(output, document);
        output.write('\n');
        return output.toByteArray();
    }

    private static String bulkIndexActionLine(String operationId) throws JsonProcessingException {
        return JSON.writeValueAsString(Map.of("index", Map.of("_id", requireOperationId(operationId)))) + "\n";
    }

    private static byte[] bulkIndexActionBytes(String operationId) throws JsonProcessingException {
        return bulkIndexActionLine(operationId).getBytes(StandardCharsets.UTF_8);
    }

    private static String requireOperationId(String operationId) {
        if (operationId == null || operationId.isBlank()) {
            throw new IllegalArgumentException("operationId must not be blank");
        }
        return operationId;
    }
}
