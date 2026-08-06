package ai.anomalousvectors.tools.burp.sinks;

import java.util.Map;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;

/**
 * Writes {@code burp.notes} and {@code burp.highlight} when present on Montoya annotations.
 */
final class BurpAnnotationFields {

    private BurpAnnotationFields() { }

    /**
     * Writes {@code burp.notes} and/or {@code burp.highlight} when present on {@code annotations}.
     *
     * @param burp target {@code burp} sub-document; no-op when {@code null}
     * @param annotations Montoya annotations; no-op when {@code null}
     */
    static void put(Map<String, Object> burp, Annotations annotations) {
        if (burp == null || annotations == null) {
            return;
        }
        if (annotations.hasNotes()) {
            String notes = ProxyCorrelationToken.redact(annotations.notes());
            if (!notes.isEmpty()) {
                burp.put("notes", notes);
            }
        }
        if (annotations.hasHighlightColor()) {
            HighlightColor color = annotations.highlightColor();
            burp.put("highlight", color == null ? null : color.name());
        }
    }
}
