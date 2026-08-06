package ai.anomalousvectors.tools.burp.sinks;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.api.montoya.core.Annotations;

/**
 * Manages the private annotation marker used to join live Proxy exchanges to Proxy History rows.
 *
 * <p>The marker is appended to Burp notes and removed after the corresponding History row has
 * supplied its fields. Export builders always redact markers, including markers recovered after an
 * extension restart.</p>
 */
final class ProxyCorrelationToken {

    static final String PREFIX = "[[burp-exporter-correlation:v1:";
    private static final String SUFFIX = "]]";
    private static final Pattern MARKER_PATTERN = Pattern.compile(
            Pattern.quote(PREFIX) + "([A-Za-z0-9-]{16,128})" + Pattern.quote(SUFFIX));

    private ProxyCorrelationToken() { }

    /**
     * Appends a marker while preserving existing notes exactly.
     *
     * @param annotations annotations to mutate
     * @param token generated correlation token
     * @return whether the marker is present after the call
     */
    static boolean append(Annotations annotations, String token) {
        if (annotations == null || token == null || token.isBlank()) {
            return false;
        }
        String marker = marker(token);
        String existing = notes(annotations);
        if (existing.contains(marker)) {
            return true;
        }
        annotations.setNotes(existing.isEmpty() ? marker : existing + "\n" + marker);
        return true;
    }

    /**
     * Returns the first generated token in the annotations.
     *
     * @param annotations annotations to inspect
     * @return token when a valid marker is present
     */
    static Optional<String> find(Annotations annotations) {
        return find(notes(annotations));
    }

    /**
     * Returns the first generated token in a notes value.
     *
     * @param notes notes text; {@code null} is treated as empty
     * @return token when a valid marker is present
     */
    static Optional<String> find(String notes) {
        Matcher matcher = MARKER_PATTERN.matcher(notes == null ? "" : notes);
        return matcher.find() ? Optional.of(matcher.group(1)) : Optional.empty();
    }

    /**
     * Removes one exact token marker from the latest annotation value.
     *
     * <p>When the marker is still the suffix originally appended by this extension, the inserted
     * newline is removed with it. Only the marker itself is removed from the latest notes value read
     * by this method, preserving surrounding text present in that value.</p>
     *
     * @param annotations annotations to mutate
     * @param token exact token to remove
     * @return whether a marker was removed
     */
    static boolean remove(Annotations annotations, String token) {
        if (annotations == null || token == null || token.isBlank()) {
            return false;
        }
        String existing = notes(annotations);
        String marker = marker(token);
        String updated = removeExactMarker(existing, marker);
        if (existing.equals(updated)) {
            return false;
        }
        annotations.setNotes(updated);
        return true;
    }

    /**
     * Redacts all generated markers from notes before export.
     *
     * @param notes source notes; {@code null} is treated as empty
     * @return notes with generated markers removed
     */
    static String redact(String notes) {
        String result = notes == null ? "" : notes;
        Matcher matcher = MARKER_PATTERN.matcher(result);
        while (matcher.find()) {
            result = removeExactMarker(result, matcher.group());
            matcher = MARKER_PATTERN.matcher(result);
        }
        return result;
    }

    /**
     * Builds the exact annotation marker for a correlation token.
     *
     * <p>The marker form is {@code [[burp-exporter-correlation:v1:<token>]]}. Callers that append,
     * remove, or match markers must use this helper so the on-wire note text stays identical.</p>
     *
     * @param token generated correlation token; caller supplies a non-blank value
     * @return marker text embedding {@code token}
     */
    static String marker(String token) {
        return PREFIX + token + SUFFIX;
    }

    private static String notes(Annotations annotations) {
        if (annotations == null || !annotations.hasNotes()) {
            return "";
        }
        String notes = annotations.notes();
        return notes == null ? "" : notes;
    }

    private static String removeExactMarker(String notes, String marker) {
        if (notes.equals(marker)) {
            return "";
        }
        int markerStart = notes.indexOf(marker);
        if (markerStart < 0) {
            return notes;
        }
        int markerEnd = markerStart + marker.length();
        if (markerStart > 0 && notes.charAt(markerStart - 1) == '\n') {
            return notes.substring(0, markerStart - 1) + notes.substring(markerEnd);
        }
        if (markerEnd < notes.length() && notes.charAt(markerEnd) == '\n') {
            return notes.substring(0, markerStart) + notes.substring(markerEnd + 1);
        }
        return notes.substring(0, markerStart) + notes.substring(markerEnd);
    }
}
