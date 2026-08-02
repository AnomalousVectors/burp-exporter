package ai.anomalousvectors.tools.burp.sinks;

import java.nio.file.Path;
import java.util.List;

import com.fasterxml.jackson.core.JsonProcessingException;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.export.ExportLineCodec;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

/** Writes one JSON document per line for local grep and inspection. */
final class JsonlFileSink extends RotatingLineFileSink {

    JsonlFileSink(Path rootDirectory, String indexName, String indexKey) {
        super(rootDirectory, indexName, indexKey, ".jsonl");
    }

    @Override
    protected List<String> linesFor(PreparedExportDocument document) {
        try {
            return List.of(ExportLineCodec.jsonDocumentLine(document.document()));
        } catch (JsonProcessingException e) {
            Logger.logError("[Files] JSONL serialize failed for " + document.indexName() + ": " + e.getMessage());
            return List.of();
        }
    }
}
