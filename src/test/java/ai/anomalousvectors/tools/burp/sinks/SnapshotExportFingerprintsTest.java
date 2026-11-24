package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;
import static org.mockito.ArgumentMatchers.anyString;

import org.junit.jupiter.api.Test;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;

class SnapshotExportFingerprintsTest {

    @Test
    void findingItemKey_usesTypeIdNameAndBaseUrl() {
        AuditIssue issue = mock(AuditIssue.class);
        AuditIssueDefinition definition = mock(AuditIssueDefinition.class);
        when(issue.definition()).thenReturn(definition);
        when(definition.typeIndex()).thenReturn(42);
        when(issue.name()).thenReturn("SQL injection");
        when(issue.baseUrl()).thenReturn("https://example.com/");

        assertThat(SnapshotExportFingerprints.findingItemKey(issue))
                .isEqualTo("42|SQL injection|https://example.com/|");
    }

    @Test
    void findingItemKey_includesDetailFingerprintWhenPresent() {
        AuditIssue issue = mock(AuditIssue.class);
        AuditIssueDefinition definition = mock(AuditIssueDefinition.class);
        when(issue.definition()).thenReturn(definition);
        when(definition.typeIndex()).thenReturn(1);
        when(issue.name()).thenReturn("XSS");
        when(issue.baseUrl()).thenReturn("https://example.com/");
        when(issue.detail()).thenReturn("Reflected in param q");

        String expected = "1|XSS|https://example.com/|"
                + "34881c1f99c492197997d9d736bcedc95e0c3494e0d523b8e060b4a1360eeb63";
        assertThat(SnapshotExportFingerprints.findingItemKey(issue)).isEqualTo(expected);
    }

    @Test
    void sitemapEntryFingerprint_differsWhenRequestBodyDiffers() {
        HttpRequestResponse first = mockSitemapItem("GET", "https://example.com/a", "body-a");
        HttpRequestResponse second = mockSitemapItem("GET", "https://example.com/a", "body-b");

        assertThat(SnapshotExportFingerprints.sitemapEntryFingerprint(first))
                .isNotEqualTo(SnapshotExportFingerprints.sitemapEntryFingerprint(second));
    }

    @Test
    void sitemapEntryFingerprint_differsForSameMethodAndUrlOnly() {
        HttpRequestResponse first = mockSitemapItem("POST", "https://example.com/a", "alpha");
        HttpRequestResponse second = mockSitemapItem("POST", "https://example.com/a", "beta");

        assertThat(SnapshotExportFingerprints.sitemapEntryFingerprint(first))
                .isNotEqualTo(SnapshotExportFingerprints.sitemapEntryFingerprint(second));
    }

    @Test
    void sitemapEntryFingerprint_stableForIdenticalTraffic() {
        HttpRequestResponse first = mockSitemapItem("POST", "https://example.com/a", "same");
        HttpRequestResponse second = mockSitemapItem("POST", "https://example.com/a", "same");

        assertThat(SnapshotExportFingerprints.sitemapEntryFingerprint(first))
                .isEqualTo(SnapshotExportFingerprints.sitemapEntryFingerprint(second));
    }

    @Test
    void annotationBoundariesKeepChangedSitemapItemsEligibleWithoutWritingNotes() {
        HttpRequestResponse first = mockSitemapItem("GET", "https://example.com/", "same");
        HttpRequestResponse second = mockSitemapItem("GET", "https://example.com/", "same");
        Annotations firstNotes = annotations("statusRED", null);
        Annotations secondNotes = annotations("status", HighlightColor.RED);
        when(first.annotations()).thenReturn(firstNotes);
        when(second.annotations()).thenReturn(secondNotes);
        String firstKey = SnapshotExportFingerprints.sitemapEntryFingerprint(first);
        String secondKey = SnapshotExportFingerprints.sitemapEntryFingerprint(second);

        assertThat(firstKey).isNotEqualTo(secondKey);
        PeriodicExportSeenKeys seen = new PeriodicExportSeenKeys();
        seen.recordSeen(firstKey);
        assertThat(seen.claimNew(secondKey)).isTrue();
        assertThat(seen.claimNew(secondKey)).isFalse();
        verify(firstNotes, never()).setNotes(anyString());
        verify(firstNotes, never()).withNotes(anyString());
        verify(secondNotes, never()).setNotes(anyString());
        verify(secondNotes, never()).withNotes(anyString());
    }

    @Test
    void emptyMissingAndPresentAnnotationFieldsRemainDistinctAndStable() {
        HttpRequestResponse item = mockSitemapItem("GET", "https://example.com/", "same");
        String absent = SnapshotExportFingerprints.sitemapEntryFingerprint(item);
        Annotations empty = annotations(null, null);
        Annotations emptyText = annotations("", null);
        Annotations populated = annotations("\u0000\u0001RED", HighlightColor.BLUE);
        when(item.annotations()).thenReturn(empty);
        String emptyContainer = SnapshotExportFingerprints.sitemapEntryFingerprint(item);
        when(item.annotations()).thenReturn(emptyText);
        String emptyNotes = SnapshotExportFingerprints.sitemapEntryFingerprint(item);
        when(item.annotations()).thenReturn(populated);
        String present = SnapshotExportFingerprints.sitemapEntryFingerprint(item);
        assertThat(java.util.Set.of(absent, emptyContainer, emptyNotes, present)).hasSize(4);
        assertThat(SnapshotExportFingerprints.sitemapEntryFingerprint(item)).isEqualTo(present);
    }

    @Test
    void binaryContentCannotMoveTheRequestResponseBoundary() {
        HttpRequestResponse first = mockSitemapItem("POST", "https://example.com/", "a\u0001b");
        HttpRequestResponse second = mockSitemapItem("POST", "https://example.com/", "a");
        HttpResponse firstResponse = response("c");
        HttpResponse secondResponse = response("b\u0001c");
        when(first.response()).thenReturn(firstResponse);
        when(second.response()).thenReturn(secondResponse);
        assertThat(SnapshotExportFingerprints.sitemapEntryFingerprint(first))
                .isNotEqualTo(SnapshotExportFingerprints.sitemapEntryFingerprint(second));
    }

    private static Annotations annotations(String notes, HighlightColor color) {
        Annotations annotations = mock(Annotations.class);
        when(annotations.hasNotes()).thenReturn(notes != null);
        when(annotations.notes()).thenReturn(notes);
        when(annotations.hasHighlightColor()).thenReturn(color != null);
        when(annotations.highlightColor()).thenReturn(color);
        return annotations;
    }

    private static HttpResponse response(String body) {
        ByteArray bytes = mock(ByteArray.class);
        when(bytes.getBytes()).thenReturn(body.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        HttpResponse response = mock(HttpResponse.class);
        when(response.toByteArray()).thenReturn(bytes);
        return response;
    }

    private static HttpRequestResponse mockSitemapItem(String method, String url, String body) {
        byte[] raw = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        ByteArray requestBytes = mock(ByteArray.class);
        when(requestBytes.getBytes()).thenReturn(raw);
        HttpRequest request = mock(HttpRequest.class);
        when(request.method()).thenReturn(method);
        when(request.url()).thenReturn(url);
        when(request.toByteArray()).thenReturn(requestBytes);

        HttpRequestResponse item = mock(HttpRequestResponse.class);
        when(item.request()).thenReturn(request);
        when(item.response()).thenReturn(null);
        when(item.annotations()).thenReturn(null);
        return item;
    }
}
