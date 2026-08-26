package ai.anomalousvectors.tools.burp.sinks;

import java.util.Map;

import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

/**
 * One traffic export item prepared once at enqueue time for the live drain path.
 *
 * <p>Spill files preserve prepared entries when possible so overflow/refill does not repeat
 * filtering or NDJSON serialization. Legacy raw-map spill files are still prepared during
 * recovery.</p>
 */
public final class TrafficQueueEntry {

    private final PreparedExportDocument prepared;

    private TrafficQueueEntry(PreparedExportDocument prepared) {
        this.prepared = prepared;
    }

    static TrafficQueueEntry fromPrepared(PreparedExportDocument prepared) {
        if (prepared == null) {
            return null;
        }
        return new TrafficQueueEntry(prepared);
    }

    /**
     * Prepares a traffic document using the route derived from its reporting-tool field.
     *
     * @param document traffic document; {@code null} returns {@code null}
     * @return prepared queue entry, or {@code null} for a null document
     */
    public static TrafficQueueEntry from(Map<String, Object> document) {
        return from(document, TrafficRouteBucket.fromDocument(document));
    }

    static TrafficQueueEntry from(
            Map<String, Object> document, TrafficRouteBucket.Route route) {
        if (document == null) {
            return null;
        }
        TrafficRouteBucket.Route resolved = route == null
                ? TrafficRouteBucket.fromDocument(document)
                : route;
        return new TrafficQueueEntry(ExportDocumentIdentity.prepareWithTrafficRoute(
                TrafficRouteBucket.trafficIndexName(),
                TrafficRouteBucket.INDEX_KEY,
                document,
                resolved.key()));
    }

    /** Returns the immutable prepared operation carried by this entry. */
    public PreparedExportDocument prepared() {
        return prepared;
    }

    /** Returns the filtered traffic document carried by the prepared operation. */
    public Map<String, Object> document() {
        return prepared.document();
    }
}
