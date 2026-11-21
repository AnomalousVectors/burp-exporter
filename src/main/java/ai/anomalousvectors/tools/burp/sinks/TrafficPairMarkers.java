package ai.anomalousvectors.tools.burp.sinks;

import java.util.List;
import java.util.Map;

import ai.anomalousvectors.tools.burp.utils.StringKeyedMaps;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;

/** Copies pair-level marker ranges into exported body maps without changing Burp annotations. */
final class TrafficPairMarkers {

    private TrafficPairMarkers() {}

    /**
     * Overlays available request and response ranges independently.
     *
     * <p>Mutates only the supplied export maps. A runtime failure from one marker accessor omits
     * that side's markers without preventing capture of the other side.</p>
     *
     * @param requestDoc mutable request document; {@code null} is ignored
     * @param responseDoc mutable response document; {@code null} is ignored
     * @param pair pair exposing marker ranges; {@code null} supplies no ranges
     */
    static void overlayPairMarkers(
            Map<String, Object> requestDoc, Map<String, Object> responseDoc, HttpRequestResponse pair) {
        try {
            List<Marker> requestMarkers = pair == null ? List.of() : pair.requestMarkers();
            if (requestMarkers != null && !requestMarkers.isEmpty()) {
                putBodyMarkers(requestDoc, RequestResponseDocBuilder.convertTrafficMarkersToList(requestMarkers));
            }
        } catch (RuntimeException ignored) {
            // Marker accessors may throw on partial or restored pairs; omit request markers.
        }
        try {
            List<Marker> responseMarkers = pair == null ? List.of() : pair.responseMarkers();
            if (responseDoc != null && responseMarkers != null && !responseMarkers.isEmpty()) {
                putBodyMarkers(responseDoc, RequestResponseDocBuilder.convertTrafficMarkersToList(responseMarkers));
            }
        } catch (RuntimeException ignored) {
            // Marker accessors may throw on partial or restored pairs; omit response markers.
        }
    }

    private static void putBodyMarkers(Map<String, Object> doc, List<Map<String, Object>> markers) {
        if (doc == null) {
            return;
        }
        Map<String, Object> body = StringKeyedMaps.copy((Map<?, ?>) doc.get("body"));
        body.put("markers", markers);
        doc.put("body", body);
    }

}
