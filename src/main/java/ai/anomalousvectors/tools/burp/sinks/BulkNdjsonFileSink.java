package ai.anomalousvectors.tools.burp.sinks;

import java.nio.file.Path;
import java.util.List;

import com.fasterxml.jackson.core.JsonProcessingException;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.export.ExportLineCodec;
import ai.anomalousvectors.tools.burp.utils.export.PreparedBulkBodies;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

/** Writes compatible {@code _bulk} NDJSON with explicit index metadata and stable IDs. */
final class BulkNdjsonFileSink extends RotatingLineFileSink {

    BulkNdjsonFileSink(Path rootDirectory, String indexName, String indexKey) {
        super(rootDirectory, indexName, indexKey, ".ndjson");
    }

    BulkNdjsonFileSink(
            Path rootDirectory,
            String indexName,
            String indexKey,
            FileAppendOperation appendOperation) {
        super(rootDirectory, indexName, indexKey, ".ndjson", appendOperation);
    }

    @Override
    public synchronized long estimateBytes(PreparedExportDocument document) {
        if (document == null) {
            return 0L;
        }
        byte[] bytes = document.bulkNdjsonBytes();
        if (bytes != null && bytes.length > 0) {
            return bytes.length;
        }
        return super.estimateBytes(document);
    }

    @Override
    public synchronized long appendDocument(PreparedExportDocument document) {
        if (document == null) {
            return 0L;
        }
        byte[] bytes = document.bulkNdjsonBytes();
        if (bytes != null && bytes.length > 0) {
            return appendBytes(bytes);
        }
        return super.appendDocument(document);
    }

    @Override
    public synchronized long appendBatch(List<PreparedExportDocument> documents) {
        if (documents == null || documents.isEmpty()) {
            return 0L;
        }
        byte[] body = PreparedBulkBodies.concatenate(documents);
        if (body.length > 0) {
            return appendBytes(body);
        }
        return super.appendBatch(documents);
    }

    @Override
    protected List<String> linesFor(PreparedExportDocument document) {
        try {
            return ExportLineCodec.bulkNdjsonLines(document);
        } catch (JsonProcessingException e) {
            Logger.logError("[Files] Bulk NDJSON serialize failed for " + document.indexName() + ": " + e.getMessage());
            return List.of();
        }
    }
}
