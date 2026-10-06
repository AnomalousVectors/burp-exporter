package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import burp.api.montoya.http.message.HttpHeader;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.Test;

/** Body export contracts for progressive Content-Encoding decoding and {@code body.text}. */
class BodyExportInsightTest {

    @Test
    void buildBodyContent_imagePngGzip_exportsWireAndDecodedBinaryButNoText() throws Exception {
        byte[] plain = new byte[] {(byte) 0x89, 0x50, 0x4E, 0x47};
        byte[] gzip = gzip(plain);
        List<HttpHeader> headers = List.of(
                header("Content-Type", "image/png"),
                header("Content-Encoding", "gzip"));

        Map<String, Object> body = HttpMessageDocSupport.buildBodyContent(
                gzip, headers, List.of("image/png"), false, 0, false);

        assertThat(body.get("decoded_b64"))
                .isEqualTo(java.util.Base64.getEncoder().encodeToString(plain));
        assertThat(body.get("content_encoding")).isEqualTo(Map.of(
                "applied", List.of("gzip"),
                "remaining", List.of(),
                "complete", true));
        assertThat(body.get("text")).isNull();
        assertThat(body.get("b64")).isEqualTo(java.util.Base64.getEncoder().encodeToString(gzip));
    }

    @Test
    void buildBodyContent_urlEncodedGzip_decompressesAndPopulatesText() throws Exception {
        byte[] plain = "org_id=abc&ja=123".getBytes(StandardCharsets.UTF_8);
        byte[] gzip = gzip(plain);
        List<HttpHeader> headers = List.of(
                header("Content-Type", "application/x-www-form-urlencoded"),
                header("Content-Encoding", "gzip"));

        Map<String, Object> body = HttpMessageDocSupport.buildBodyContent(
                gzip, headers, List.of("application/x-www-form-urlencoded"), false, 0, true);

        assertThat(body.get("text")).isEqualTo("org_id=abc&ja=123");
        assertThat(body.get("decoded_b64"))
                .isEqualTo(java.util.Base64.getEncoder().encodeToString(plain));
        assertThat(body.get("content_encoding")).isEqualTo(Map.of(
                "applied", List.of("gzip"),
                "remaining", List.of(),
                "complete", true));
    }

    @Test
    void buildBodyContent_multipart_populatesTextFromWireBytes() {
        String wire = """
                --boundary\r
                Content-Disposition: form-data; name="file"; filename="a.txt"\r
                \r
                hello\r
                --boundary--\r
                """;
        byte[] bytes = wire.getBytes(StandardCharsets.UTF_8);
        List<HttpHeader> headers = List.of(header("Content-Type", "multipart/form-data; boundary=boundary"));

        Map<String, Object> body = HttpMessageDocSupport.buildBodyContent(
                bytes, headers, List.of("multipart/form-data"), false, 0, true);

        assertThat((String) body.get("text")).contains("Content-Disposition");
        assertThat(body).doesNotContainKeys("decoded_b64", "content_encoding");
    }

    @Test
    void buildBodyContent_octetStreamPlainJson_sniffsTextWithoutDecompress() {
        byte[] plain = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
        List<HttpHeader> headers = List.of(header("Content-Type", "application/octet-stream"));

        Map<String, Object> body = HttpMessageDocSupport.buildBodyContent(
                plain, headers, List.of("application/octet-stream"), false, 0, false);

        assertThat(body.get("text")).isEqualTo("{\"ok\":true}");
        assertThat(body).doesNotContainKeys("decoded_b64", "content_encoding");
    }

    @Test
    void buildBodyContent_octetStreamGzipJson_decompressesAndPopulatesText() throws Exception {
        byte[] plain = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
        byte[] gzip = gzip(plain);
        List<HttpHeader> headers = List.of(
                header("Content-Type", "application/octet-stream"),
                header("Content-Encoding", "gzip"));

        Map<String, Object> body = HttpMessageDocSupport.buildBodyContent(
                gzip, headers, List.of("application/octet-stream"), false, 0, false);

        assertThat(body.get("text")).isEqualTo("{\"ok\":true}");
        assertThat(body.get("decoded_b64"))
                .isEqualTo(java.util.Base64.getEncoder().encodeToString(plain));
    }

    @Test
    void buildBodyContent_octetStreamGzipBinary_decompressesButTextNull() throws Exception {
        byte[] plain = new byte[] {0x00, 0x01, 0x02, 0x03, (byte) 0xFF, (byte) 0xFE};
        byte[] gzip = gzip(plain);
        List<HttpHeader> headers = List.of(
                header("Content-Type", "application/octet-stream"),
                header("Content-Encoding", "gzip"));

        Map<String, Object> body = HttpMessageDocSupport.buildBodyContent(
                gzip, headers, List.of("application/octet-stream"), false, 0, false);

        assertThat(body.get("text")).isNull();
        assertThat(body.get("decoded_b64"))
                .isEqualTo(java.util.Base64.getEncoder().encodeToString(plain));
    }

    @Test
    void buildBodyContent_outerSuccessInnerFailure_exportsDeepestBytesAndIncompleteChain() throws Exception {
        byte[] deepest = new byte[] {0x00, 0x01, (byte) 0xFF};
        byte[] wire = gzip(deepest);
        List<HttpHeader> headers = List.of(
                header("Content-Type", "application/octet-stream"),
                header("Content-Encoding", "gzip, gzip"));

        Map<String, Object> body = HttpMessageDocSupport.buildBodyContent(
                wire, headers, List.of("application/octet-stream"), false, 0, true);

        assertThat(body.get("b64"))
                .isEqualTo(java.util.Base64.getEncoder().encodeToString(wire));
        assertThat(body.get("decoded_b64"))
                .isEqualTo(java.util.Base64.getEncoder().encodeToString(deepest));
        assertThat(body.get("content_encoding")).isEqualTo(Map.of(
                "applied", List.of("gzip"),
                "remaining", List.of("gzip"),
                "complete", false));
        assertThat(body.get("text")).isNull();
    }

    @Test
    void buildBodyContent_unsupportedOuterLayer_exportsIncompleteMetadataWithoutDecodedBytes() {
        byte[] wire = new byte[] {0x00, 0x01, (byte) 0xFF};
        List<HttpHeader> headers = List.of(
                header("Content-Type", "application/octet-stream"),
                header("Content-Encoding", "gzip, custom"));

        Map<String, Object> body = HttpMessageDocSupport.buildBodyContent(
                wire, headers, List.of("application/octet-stream"), false, 0, false);

        assertThat(body.get("b64"))
                .isEqualTo(java.util.Base64.getEncoder().encodeToString(wire));
        assertThat(body).doesNotContainKey("decoded_b64");
        assertThat(body.get("content_encoding")).isEqualTo(Map.of(
                "applied", List.of(),
                "remaining", List.of("custom", "gzip"),
                "complete", false));
        assertThat(body.get("text")).isNull();
    }

    @Test
    void resolveForExport_imageGzip_decompressesWithoutChangingTextPolicy() throws Exception {
        byte[] plain = new byte[] {1, 2, 3, 4};
        byte[] gzip = gzip(plain);
        List<HttpHeader> headers = List.of(header("Content-Encoding", "gzip"));

        BodyContentEncodingSupport.ResolvedBody resolved = BodyContentEncodingSupport.resolveForExport(
                gzip, headers, false, false);

        assertThat(resolved.transformed()).isTrue();
        assertThat(resolved.logicalBytes()).isEqualTo(plain);
    }

    @Test
    void resolveForExport_octetStreamWithoutEncoding_skipsDecompress() {
        byte[] wire = "{\"a\":1}".getBytes(StandardCharsets.UTF_8);

        BodyContentEncodingSupport.ResolvedBody resolved = BodyContentEncodingSupport.resolveForExport(
                wire, List.of(), false, false);

        assertThat(resolved.transformed()).isFalse();
    }

    private static byte[] gzip(byte[] input) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(out)) {
            gzip.write(input);
        }
        return out.toByteArray();
    }

    private static HttpHeader header(String name, String value) {
        HttpHeader h = mock(HttpHeader.class);
        when(h.name()).thenReturn(name);
        when(h.value()).thenReturn(value);
        return h;
    }
}
