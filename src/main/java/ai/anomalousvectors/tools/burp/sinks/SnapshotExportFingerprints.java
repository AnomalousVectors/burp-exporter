package ai.anomalousvectors.tools.burp.sinks;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;

/**
 * Stable in-memory item keys for sitemap/findings periodic export deduplication.
 *
 * <p>Keys are never written to OpenSearch documents. Sitemap dedupe always uses
 * {@link #sitemapEntryFingerprint(HttpRequestResponse)} so rows that share method and URL but differ
 * in body or annotations remain distinct. Findings use {@link #findingItemKey(AuditIssue)}.</p>
 */
final class SnapshotExportFingerprints {

    private SnapshotExportFingerprints() {}

    /**
     * SHA-256 fingerprint of request bytes, response bytes, and Burp annotations.
     *
     * <p>Used for sitemap periodic deduplication and Repeater tab correlation. Distinct site-map
     * rows that share method and URL but differ in body or annotations produce distinct keys.</p>
     *
     * @param requestResponse site-map or Repeater item; {@code null} yields empty string
     * @return lowercase hex digest, or empty string when {@code requestResponse} is {@code null}
     */
    static String sitemapEntryFingerprint(HttpRequestResponse requestResponse) {
        if (requestResponse == null) {
            return "";
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update((byte) 1);
            updateDigestWithMessage(digest, requestResponse.request());
            digest.update((byte) 2);
            updateDigestWithMessage(digest, requestResponse.response());
            updateDigestWithAnnotations(digest, requestResponse.annotations());
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 digest unavailable", e);
        }
    }

    /**
     * Stable in-memory key for findings periodic deduplication.
     *
     * <p>Combines issue type index, name, base URL, and a SHA-256 digest of {@link AuditIssue#detail()}
     * so distinct issues that share type/name/URL remain separate.</p>
     *
     * @param issue Montoya audit issue; {@code null} yields empty string
     * @return pipe-delimited key; never {@code null}
     */
    static String findingItemKey(AuditIssue issue) {
        if (issue == null) {
            return "";
        }
        int typeId = 0;
        try {
            AuditIssueDefinition definition = issue.definition();
            if (definition != null) {
                typeId = definition.typeIndex();
            }
        } catch (RuntimeException ignored) {
            // Burp lifecycle races can transiently reject definition access.
        }
        return typeId
                + "|"
                + nullToEmpty(issue.name())
                + "|"
                + nullToEmpty(issue.baseUrl())
                + "|"
                + detailFingerprint(issue);
    }

    /**
     * Stable SHA-256 fingerprint for {@link AuditIssue#detail()} so distinct issues that share
     * type/name/base URL are not collapsed during periodic deduplication.
     */
    private static String detailFingerprint(AuditIssue issue) {
        try {
            String detail = issue.detail();
            if (detail == null || detail.isBlank()) {
                return "";
            }
            return sha256HexUtf8(detail);
        } catch (RuntimeException ignored) {
            // Burp lifecycle races can transiently reject detail access.
            return "";
        }
    }

    private static String sha256HexUtf8(String text) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(text.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 digest unavailable", e);
        }
    }

    private static void updateDigestWithMessage(MessageDigest digest, HttpRequest request) {
        if (request == null) {
            updateDigestWithBytes(digest, null);
            return;
        }
        updateDigestWithBytes(digest, request.toByteArray().getBytes());
    }

    private static void updateDigestWithMessage(MessageDigest digest, HttpResponse response) {
        if (response == null) {
            updateDigestWithBytes(digest, null);
            return;
        }
        updateDigestWithBytes(digest, response.toByteArray().getBytes());
    }

    private static void updateDigestWithAnnotations(MessageDigest digest, Annotations annotations) {
        digest.update((byte) 3);
        if (annotations == null) {
            digest.update((byte) 0);
            return;
        }
        digest.update((byte) 1);
        String notes = annotations.hasNotes() ? annotations.notes() : null;
        updateDigestWithBytes(digest, notes == null ? null : notes.getBytes(StandardCharsets.UTF_8));
        digest.update((byte) 4);
        HighlightColor color = annotations.hasHighlightColor() ? annotations.highlightColor() : null;
        updateDigestWithBytes(digest, color == null ? null : color.name().getBytes(StandardCharsets.UTF_8));
    }

    // Presence and fixed-width byte lengths prevent field boundaries from moving into content.
    private static void updateDigestWithBytes(MessageDigest digest, byte[] bytes) {
        digest.update((byte) (bytes == null ? 0 : 1));
        if (bytes == null) return;
        int length = bytes.length;
        digest.update((byte) (length >>> 24));
        digest.update((byte) (length >>> 16));
        digest.update((byte) (length >>> 8));
        digest.update((byte) length);
        digest.update(bytes);
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
