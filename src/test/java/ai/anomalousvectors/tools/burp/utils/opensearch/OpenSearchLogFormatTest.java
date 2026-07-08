package ai.anomalousvectors.tools.burp.utils.opensearch;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class OpenSearchLogFormatTest {

    @Test
    void parseProtocolFromException_extractsHttp2() {
        Exception e = new RuntimeException("status line [HTTP/2.0 401 Unauthorized]\nUnauthorized");
        assertThat(OpenSearchLogFormat.parseProtocolFromException(e)).isEqualTo("HTTP/2.0");
    }

    @Test
    void parseProtocolFromException_extractsHttp11() {
        Exception e = new RuntimeException("status line [HTTP/1.1 200 OK]");
        assertThat(OpenSearchLogFormat.parseProtocolFromException(e)).isEqualTo("HTTP/1.1");
    }

    @Test
    void parseStatusCodeFromException_extractsCode() {
        Exception e = new RuntimeException("status line [HTTP/2.0 401 Unauthorized]");
        assertThat(OpenSearchLogFormat.parseStatusCodeFromException(e)).isEqualTo(401);
    }

    @Test
    void parseReasonFromException_extractsReason() {
        Exception e = new RuntimeException("status line [HTTP/2.0 401 Unauthorized]");
        assertThat(OpenSearchLogFormat.parseReasonFromException(e)).isEqualTo("Unauthorized");
    }

    @Test
    void formatRequestForLog_includesRedactedAuthWhenUsed() {
        String raw = OpenSearchLogFormat.formatRequestForLog("GET", "/", "https://localhost:9200/", "HTTP/2.0", true);
        assertThat(raw).startsWith("GET / HTTP/2.0");
        assertThat(raw).contains("Host: localhost:9200");
        assertThat(raw).contains("Authorization: Basic ***");
    }

    @Test
    void formatRequestForLog_includesSelectedRedactedAuthScheme() {
        String raw = OpenSearchLogFormat.formatRequestForLog(
                "GET", "/", "https://localhost:9200/", "HTTP/2.0", "ApiKey ***");
        assertThat(raw).contains("Authorization: ApiKey ***");
        assertThat(raw).doesNotContain("os_api_token");
    }

    @Test
    void formatRequestForLog_omitsAuthWhenNotUsed() {
        String raw = OpenSearchLogFormat.formatRequestForLog("GET", "/", "https://localhost:9200/", "HTTP/1.1", false);
        assertThat(raw).doesNotContain("Authorization");
    }

    @Test
    void formatRequestForLog_withNullProtocol_usesVersionUnknown() {
        String raw = OpenSearchLogFormat.formatRequestForLog("GET", "/", "https://localhost:9200/", null, false);
        assertThat(raw).startsWith("GET / HTTP (version unknown)");
        assertThat(raw).contains("Host: localhost:9200");
    }

    @Test
    void buildRawResponseWithHeaders_withNullProtocol_usesVersionUnknown() {
        String raw = OpenSearchLogFormat.buildRawResponseWithHeaders("", null, 0, "SSLHandshakeException", null);
        assertThat(raw).startsWith("HTTP (version unknown) 0 SSLHandshakeException");
    }

    @Test
    void shouldRedactHeader_returnsTrueForSensitiveNames() {
        assertThat(OpenSearchLogFormat.shouldRedactHeader("Authorization")).isTrue();
        assertThat(OpenSearchLogFormat.shouldRedactHeader("Set-Cookie")).isTrue();
        assertThat(OpenSearchLogFormat.shouldRedactHeader("Cookie")).isTrue();
        assertThat(OpenSearchLogFormat.shouldRedactHeader("Content-Type")).isFalse();
    }

    @Test
    void buildRawResponseWithHeaders_usesHeaderLinesWhenProvided() {
        String raw = OpenSearchLogFormat.buildRawResponseWithHeaders("{}", "HTTP/2.0", 200, "OK", java.util.List.of("Content-Type: application/json", "X-Foo: bar"));
        assertThat(raw).startsWith("HTTP/2.0 200 OK");
        assertThat(raw).contains("Content-Type: application/json");
        assertThat(raw).contains("X-Foo: bar");
        assertThat(raw).contains("\n\n{}");
    }
}
