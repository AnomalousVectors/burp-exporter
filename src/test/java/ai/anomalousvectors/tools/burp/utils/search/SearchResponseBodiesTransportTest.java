package ai.anomalousvectors.tools.burp.utils.search;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.zip.GZIPOutputStream;

import com.sun.net.httpserver.HttpServer;
import org.apache.hc.client5.http.async.methods.SimpleRequestBuilder;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.HttpHost;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

/** Exercises reply budgets and retry identity through real loopback HTTP transports. */
class SearchResponseBodiesTransportTest {
    private enum Channel { CLASSIC, ASYNC }
    private HttpServer server;
    private ConfigState.State previous;
    private String baseUrl;
    private volatile int status = 200;
    private volatile byte[] reply = new byte[0];
    private volatile boolean compressed;
    private final List<String> requests = new CopyOnWriteArrayList<>();

    @BeforeEach
    void startServer() throws Exception {
        previous = RuntimeConfig.getState();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            requests.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] response = reply;
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            if (compressed) exchange.getResponseHeaders().set("Content-Encoding", "gzip");
            exchange.sendResponseHeaders(status, 0);
            try (var output = exchange.getResponseBody()) {
                output.write(response);
            } catch (java.io.IOException ignored) {
                // A bounded consumer deliberately aborts before this fixture finishes sending.
            } finally {
                exchange.close();
            }
        });
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        RuntimeConfig.updateState(new ConfigState.State(List.of("traffic"), "all", List.of(),
                new ConfigState.Sinks(false, null, true, baseUrl, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB, List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES, null));
        RuntimeConfig.setExportRunning(true);
        BulkByteBudget.resetForStart();
        SearchConnector.closeAll();
    }

    @AfterEach
    void stopServer() {
        SearchConnector.closeAll();
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.updateState(previous);
        BulkByteBudget.resetForStart();
        if (server != null) server.stop(0);
    }

    @ParameterizedTest
    @EnumSource(Channel.class)
    void compressedChunkedSuccessCannotBypassDecodedBudget(Channel channel) throws Exception {
        reply = gzip("x".repeat(128 * 1024));
        compressed = true;
        assertThat(reply.length).isLessThan(1024);
        assertThatThrownBy(() -> read(channel, 1024))
                .isInstanceOfAny(java.io.IOException.class, ExecutionException.class)
                .hasStackTraceContaining("reply budget");
    }

    @ParameterizedTest
    @EnumSource(Channel.class)
    void oversizedCompressedErrorPreservesStatusAndBoundsPreview(Channel channel) throws Exception {
        status = 429;
        reply = gzip("x".repeat(128 * 1024));
        compressed = true;
        String body = read(channel, 1024);
        assertThat(body).startsWith("xxx").endsWith("[Database response preview truncated]");
        assertThat(body.length()).isLessThan(SearchResponseBodies.ERROR_PREVIEW_BYTES + 100);
    }

    @Test
    void largeValidBulkAcknowledgmentsUseTheItemCountBudget() {
        int count = 128;
        String item = "{\"index\":{\"status\":201,\"result\":\"created\",\"padding\":\""
                + "x".repeat(8192) + "\"}}";
        reply = ("{\"errors\":false,\"items\":[" + String.join(",", java.util.Collections.nCopies(count, item))
                + "]}").getBytes(StandardCharsets.UTF_8);
        assertThat(reply.length).isGreaterThan(1024 * 1024).isLessThan(SearchResponseBodies.bulkLimit(count));
        List<PreparedExportDocument> documents = new ArrayList<>();
        for (int i = 0; i < count; i++) documents.add(document());
        var result = PreparedBulkSender.push(baseUrl, "tool-burp-traffic", documents);
        assertThat(result.successCount()).isEqualTo(count);
        assertThat(result.failedItems).isEmpty();
    }

    @Test
    void oversizedAcknowledgmentFailsTransientlyAndRetryKeepsOperationIdentity() throws Exception {
        PreparedExportDocument document = document();
        reply = gzip("x".repeat(2 * 1024 * 1024));
        compressed = true;
        var first = PreparedBulkSender.push(baseUrl, "tool-burp-traffic", List.of(document));
        assertThat(first.successCount()).isZero();
        assertThat(first.failedItems).singleElement().satisfies(failure -> {
            assertThat(failure.type()).isEqualTo("transport_exception");
            assertThat(BulkErrorClassification.of(failure.type())).isEqualTo(BulkErrorClassification.TRANSIENT);
        });
        compressed = false;
        reply = "{\"errors\":false,\"items\":[{\"index\":{\"status\":201}}]}".getBytes(StandardCharsets.UTF_8);
        var retry = PreparedBulkSender.push(baseUrl, "tool-burp-traffic", List.of(document));
        assertThat(retry.successCount()).isEqualTo(1);
        assertThat(requests).hasSize(2);
        assertThat(requests.get(0)).isEqualTo(requests.get(1)).contains(document.operationId());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void sdkMetadataConsumerRejectsIncrementallyOversizedResponses(boolean gzip) throws Exception {
        String oversized = "x".repeat(SearchResponseBodies.METADATA_LIMIT_BYTES + 1);
        compressed = gzip;
        reply = gzip ? gzip(oversized) : oversized.getBytes(StandardCharsets.UTF_8);
        var client = SearchConnector.getClient(baseUrl, SearchAuth.none());
        assertThatThrownBy(client::info).hasStackTraceContaining("buffer limit");
    }

    @ParameterizedTest
    @CsvSource({"false,200", "true,200", "false,413", "true,413"})
    void legacyConnectionProbeAcceptsMetadataAndRejectsOversizedReplies(boolean gzip, int replyStatus) throws Exception {
        var probe = SearchConnectionTester.class.getDeclaredMethod(
                "testElasticsearchConnection", String.class, SearchAuth.class);
        probe.setAccessible(true);
        reply = "{\"cluster_uuid\":\"lab\",\"version\":{\"number\":\"9.0.0\"}}".getBytes(StandardCharsets.UTF_8);
        var valid = (SearchConnectionStatus) probe.invoke(null, baseUrl, SearchAuth.none());
        assertThat(valid.success()).isTrue();
        assertThat(valid.version()).isEqualTo("9.0.0");

        String oversized = "x".repeat(SearchResponseBodies.METADATA_LIMIT_BYTES + 1);
        status = replyStatus;
        compressed = gzip;
        reply = gzip ? gzip(oversized) : oversized.getBytes(StandardCharsets.UTF_8);
        var rejected = (SearchConnectionStatus) probe.invoke(null, baseUrl, SearchAuth.none());
        assertThat(rejected.success()).isFalse();
        assertThat(rejected.message()).contains("reply budget");
    }

    private String read(Channel channel, int limit) throws Exception {
        if (channel == Channel.CLASSIC) {
            try (var client = HttpClients.createDefault()) {
                return client.execute(new HttpHost("http", "127.0.0.1", server.getAddress().getPort()),
                        new HttpGet("/"), response -> {
                            assertThat(response.getCode()).isEqualTo(status);
                            assertThat(response).isInstanceOf(org.apache.hc.core5.io.ModalCloseable.class);
                            return SearchResponseBodies.read(response, limit);
                        });
            }
        }
        try (var client = HttpAsyncClients.createDefault()) {
            client.start();
            var response = SearchResponseBodies.execute(client, SimpleRequestBuilder.get(baseUrl).build(), limit);
            assertThat(response.getCode()).isEqualTo(status);
            return response.getBodyText();
        }
    }

    private static PreparedExportDocument document() {
        return ExportDocumentIdentity.prepare("tool-burp-traffic", "traffic", Map.of("request", Map.of("method", "GET")));
    }

    private static byte[] gzip(String body) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(output)) {
            gzip.write(body.getBytes(StandardCharsets.UTF_8));
        }
        return output.toByteArray();
    }
}
