package ai.anomalousvectors.tools.burp.utils.search;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;


import static org.assertj.core.api.Assertions.assertThat;

class SearchLogFormatTest {

    @Test
    void parseProtocolFromException_extractsHttp2() {
        Exception e = new RuntimeException("status line [HTTP/2.0 401 Unauthorized]\nUnauthorized");
        assertThat(SearchLogFormat.parseProtocolFromException(e)).isEqualTo("HTTP/2.0");
    }

    @Test
    void parseProtocolFromException_extractsHttp11() {
        Exception e = new RuntimeException("status line [HTTP/1.1 200 OK]");
        assertThat(SearchLogFormat.parseProtocolFromException(e)).isEqualTo("HTTP/1.1");
    }

    @Test
    void parseStatusCodeFromException_extractsCode() {
        Exception e = new RuntimeException("status line [HTTP/2.0 401 Unauthorized]");
        assertThat(SearchLogFormat.parseStatusCodeFromException(e)).isEqualTo(401);
    }

    @Test
    void parseReasonFromException_extractsReason() {
        Exception e = new RuntimeException("status line [HTTP/2.0 401 Unauthorized]");
        assertThat(SearchLogFormat.parseReasonFromException(e)).isEqualTo("Unauthorized");
    }

    @Test
    void formatRequestForLog_includesRedactedAuthWhenUsed() {
        String raw = SearchLogFormat.formatRequestForLog("GET", "/", "https://localhost:9200/", "HTTP/2.0", true);
        assertThat(raw).startsWith("GET / HTTP/2.0");
        assertThat(raw).contains("Host: localhost:9200");
        assertThat(raw).contains("Authorization: Basic ***");
    }

    @Test
    void formatRequestForLog_includesSelectedRedactedAuthScheme() {
        String raw = SearchLogFormat.formatRequestForLog(
                "GET", "/", "https://localhost:9200/", "HTTP/2.0", "ApiKey ***");
        assertThat(raw).contains("Authorization: ApiKey ***");
        assertThat(raw).doesNotContain("os_api_token");
    }

    @Test
    void formatRequestForLog_omitsAuthWhenNotUsed() {
        String raw = SearchLogFormat.formatRequestForLog("GET", "/", "https://localhost:9200/", "HTTP/1.1", false);
        assertThat(raw).doesNotContain("Authorization");
    }

    @Test
    void formatRequestForLog_withNullProtocol_usesVersionUnknown() {
        String raw = SearchLogFormat.formatRequestForLog("GET", "/", "https://localhost:9200/", null, false);
        assertThat(raw).startsWith("GET / HTTP (version unknown)");
        assertThat(raw).contains("Host: localhost:9200");
    }

    @Test
    void buildResponsePreviewWithHeaders_withNullProtocol_usesVersionUnknown() {
        String raw = SearchLogFormat.buildResponsePreviewWithHeaders(
                "", null, 0, "SSLHandshakeException", null);
        assertThat(raw).startsWith("HTTP (version unknown) 0 SSLHandshakeException");
    }

    @Test
    void shouldRedactHeader_returnsTrueForSensitiveNames() {
        assertThat(SearchLogFormat.shouldRedactHeader("Authorization")).isTrue();
        assertThat(SearchLogFormat.shouldRedactHeader("Set-Cookie")).isTrue();
        assertThat(SearchLogFormat.shouldRedactHeader("Cookie")).isTrue();
        assertThat(SearchLogFormat.shouldRedactHeader("X-Amz-Security-Token")).isTrue();
        assertThat(SearchLogFormat.shouldRedactHeader("X-Amz-Signature")).isTrue();
        assertThat(SearchLogFormat.shouldRedactHeader("Content-Type")).isFalse();
    }

    @Test
    void buildResponsePreviewWithHeaders_usesHeaderLinesWhenProvided() {
        String raw = SearchLogFormat.buildResponsePreviewWithHeaders(
                "{}",
                "HTTP/2.0",
                200,
                "OK",
                java.util.List.of("Content-Type: application/json", "X-Foo: bar"));
        assertThat(raw).startsWith("HTTP/2.0 200 OK");
        assertThat(raw).contains("Content-Type: application/json");
        assertThat(raw).contains("X-Foo: bar");
        assertThat(raw).contains("\n\nBody preview:\n{}");
    }

    @Test
    void buildResponsePreviewWithHeaders_boundsCompleteDiagnostic() {
        String raw = SearchLogFormat.buildResponsePreviewWithHeaders(
                "body".repeat(4_000),
                "HTTP/2.0",
                502,
                "Bad Gateway",
                java.util.stream.IntStream.range(0, 100)
                        .mapToObj(index -> "X-Large-" + index + ": " + "v".repeat(1_000))
                        .toList());

        assertThat(raw.getBytes(StandardCharsets.UTF_8).length)
                .isLessThanOrEqualTo(SearchDiagnosticText.RESPONSE_DIAGNOSTIC_BYTES);
        assertThat(raw).endsWith("... [truncated]");
    }

    @Test
    void describeExceptionChain_preservesTransportCauseTypesAndMessages() {
        Exception failure = new java.io.IOException(
                "request failed",
                new java.net.SocketTimeoutException("Read timed out"));

        assertThat(SearchLogFormat.describeExceptionChain(failure))
                .isEqualTo("IOException: request failed <- SocketTimeoutException: Read timed out");
    }

    @Test
    void formatStatusAndBodyPreview_indentsMultilineHtml() {
        String formatted = SearchLogFormat.formatStatusAndBodyPreview(
                504,
                "<html>\n<head><title>504 Gateway Time-out</title></head>\n</html>\n");
        assertThat(formatted).startsWith("504\n");
        assertThat(formatted).contains("\n  Body preview:");
        assertThat(formatted).contains("\n  <html>");
        assertThat(formatted).contains("\n  <head><title>504 Gateway Time-out</title></head>");
        assertThat(formatted).doesNotContain("\n<html>");
    }

    @Test
    void formatStatusAndBodyPreview_statusOnlyWhenBodyBlank() {
        assertThat(SearchLogFormat.formatStatusAndBodyPreview(502, "  ")).isEqualTo("502");
        assertThat(SearchLogFormat.formatStatusAndBodyPreview(500, null)).isEqualTo("500");
    }
}
