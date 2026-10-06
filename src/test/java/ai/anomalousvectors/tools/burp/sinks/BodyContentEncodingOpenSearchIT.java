package ai.anomalousvectors.tools.burp.sinks;

import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.awaitSingleIndexedDocument;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.createIndex;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.deleteIndex;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.nestedMap;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.openSearchSinks;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.pushOneDocument;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.stringObjectMapList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.Deflater;
import java.util.zip.GZIPOutputStream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;

import ai.anomalousvectors.tools.burp.testutils.OpenSearchReachable;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Verifies additional {@link BodyContentEncodingSupport} codecs round-trip through traffic export
 * documents indexed at {@link OpenSearchReachable#BASE_URL}.
 */
@Tag("integration")
@ResourceLock("traffic-opensearch-index")
class BodyContentEncodingOpenSearchIT {

    private final ConfigState.State previous = RuntimeConfig.getState();

    @AfterEach
    public void cleanup() {
        RuntimeConfig.updateState(previous);
        RuntimeConfig.setExportRunning(false);
        deleteIndex("traffic");
    }

    @Test
    void brotliJsonBody_indexesDecodedText() throws Exception {
        byte[] plain = "{\"metric\":42}".getBytes(StandardCharsets.UTF_8);
        pushEncodedBodyAndAssert(
                "br",
                brotli(plain),
                "application/json",
                ContentType.JSON,
                plain,
                "{\"metric\":42}",
                "https://example.test/brotli-body-it");
    }

    @Test
    void zstdFormBody_indexesDecodedTextAndBodyParams() throws Exception {
        byte[] plain = "alpha=1&beta=2".getBytes(StandardCharsets.UTF_8);
        Map<String, Object> stored = pushEncodedBodyAndAssert(
                "zstd",
                com.github.luben.zstd.Zstd.compress(plain),
                "application/x-www-form-urlencoded",
                ContentType.URL_ENCODED,
                plain,
                "alpha=1&beta=2",
                "https://example.test/zstd-body-it");
        List<Map<String, Object>> parameters =
                stringObjectMapList(nestedMap(stored, "request").get("parameters"));
        assertThat(parameters).extracting(p -> p.get("name")).contains("alpha", "beta");
    }

    @Test
    void deflateFormBody_indexesDecodedText() throws Exception {
        byte[] plain = "x=1&y=2".getBytes(StandardCharsets.UTF_8);
        pushEncodedBodyAndAssert(
                "deflate",
                deflate(plain),
                "application/x-www-form-urlencoded",
                ContentType.URL_ENCODED,
                plain,
                "x=1&y=2",
                "https://example.test/deflate-body-it");
    }

    @Test
    void gzipImageBody_indexesDecodedBinaryWithoutText() throws Exception {
        byte[] plain = new byte[] {(byte) 0x89, 0x50, 0x4E, 0x47, 0x00, (byte) 0xFF};

        pushEncodedBodyAndAssert(
                "gzip",
                gzip(plain),
                "image/png",
                ContentType.NONE,
                plain,
                null,
                "https://example.test/gzip-image-body-it");
    }

    private static Map<String, Object> pushEncodedBodyAndAssert(
            String encodingToken,
            byte[] wireBody,
            String contentTypeValue,
            ContentType burpContentType,
            byte[] expectedDecodedBytes,
            String expectedText,
            String url) throws Exception {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        HttpRequest request = mock(HttpRequest.class);
        when(request.parameters()).thenReturn(List.of());
        when(request.method()).thenReturn("POST");
        when(request.url()).thenReturn(url);
        when(request.path()).thenReturn("/it");
        when(request.pathWithoutQuery()).thenReturn("/it");
        when(request.query()).thenReturn("");
        when(request.fileExtension()).thenReturn("");
        when(request.contentType()).thenReturn(burpContentType);
        HttpHeader contentTypeHeader = header("Content-Type", contentTypeValue);
        HttpHeader encodingHeader = header("Content-Encoding", encodingToken);
        when(request.headers()).thenReturn(List.of(contentTypeHeader, encodingHeader));
        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn(wireBody);
        when(request.body()).thenReturn(body);
        when(request.markers()).thenReturn(List.of());

        Map<String, Object> requestDoc = RequestResponseDocBuilder.buildTrafficRequestDoc(request);
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("request", requestDoc);
        doc.put("meta", ExportMetaFields.meta("it"));

        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                openSearchSinks(),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of(),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                null);

        deleteIndex("traffic");
        createIndex("traffic");
        pushOneDocument("traffic", doc, state);
        Map<String, Object> stored = awaitSingleIndexedDocument("traffic");
        Map<?, ?> bodyDoc = nestedMap(nestedMap(stored, "request"), "body");
        assertThat(bodyDoc.get("text")).isEqualTo(expectedText);
        assertThat(bodyDoc.get("b64")).isEqualTo(Base64.getEncoder().encodeToString(wireBody));
        assertThat(bodyDoc.get("decoded_b64"))
                .isEqualTo(Base64.getEncoder().encodeToString(expectedDecodedBytes));
        Map<?, ?> encoding = nestedMap(bodyDoc, "content_encoding");
        assertThat(encoding.get("applied")).isEqualTo(List.of(encodingToken));
        assertThat(encoding.get("remaining")).isEqualTo(List.of());
        assertThat(encoding.get("complete")).isEqualTo(true);
        assertThat(nestedMap(stored, "meta").containsKey("export")).isFalse();
        return stored;
    }

    private static byte[] brotli(byte[] input) throws Exception {
        com.aayushatharva.brotli4j.Brotli4jLoader.ensureAvailability();
        return com.aayushatharva.brotli4j.encoder.Encoder.compress(input);
    }

    private static byte[] deflate(byte[] input) {
        Deflater deflater = new Deflater();
        deflater.setInput(input);
        deflater.finish();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[256];
        while (!deflater.finished()) {
            int count = deflater.deflate(buffer);
            out.write(buffer, 0, count);
        }
        deflater.end();
        return out.toByteArray();
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
