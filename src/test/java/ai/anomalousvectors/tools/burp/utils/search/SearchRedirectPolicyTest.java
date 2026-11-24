package ai.anomalousvectors.tools.burp.utils.search;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.apache.hc.client5.http.async.methods.SimpleRequestBuilder;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicClassicHttpResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.opensearch.client.transport.httpclient5.ResponseException;

import ai.anomalousvectors.tools.burp.testutils.Reflect;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;

/** Verifies that database redirects cannot forward credentials or export content to another URL. */
class SearchRedirectPolicyTest {
    private static final String BULK_BODY = "{\"index\":{}}\n{\"synthetic\":true}\n";
    private static final List<SearchAuth> AUTH_MODES = List.of(
            SearchAuth.none(), SearchAuth.basic("synthetic", "not-a-secret"),
            SearchAuth.apiKey("synthetic"), SearchAuth.bearerToken("synthetic"));

    /** Starts every case without a cached client from an earlier endpoint. */
    @BeforeEach
    void clearClients() {
        SearchConnector.closeAll();
    }

    /** Releases all production client workers, even when an assertion fails. */
    @AfterEach
    void closeClients() {
        SearchConnector.closeAll();
    }

    @ParameterizedTest(name = "HTTP {0}; same origin={1}")
    @MethodSource("redirects")
    void redirectsRetainOriginalStatusWithoutForwarding(int status, boolean sameOrigin) throws Exception {
        try (RedirectServer server = new RedirectServer(status, sameOrigin)) {
            for (SearchAuth auth : AUTH_MODES) {
                assertClassic(server, auth, status);
                assertAsync(server, auth, status);
                assertRawGet(server, auth, status);
                assertThatThrownBy(() -> SearchConnector.getClient(server.baseUrl(), auth).info())
                        .isInstanceOfSatisfying(ResponseException.class,
                                failure -> assertThat(failure.status()).isEqualTo(status));
                server.assertOriginal("GET", "", auth);
                SearchConnectionStatus legacy = elasticsearchProbe(server, auth);
                assertThat(legacy.success()).isFalse();
                assertThat(legacy.message()).contains("HTTP " + status);
                server.assertOriginal("GET", "", auth);
            }
        }
    }

    @Test
    void directEndpointsStillAcceptAuthenticationAndBulkContent() throws Exception {
        try (RedirectServer server = new RedirectServer(200, false)) {
            for (SearchAuth auth : AUTH_MODES) {
                assertClassic(server, auth, 200);
                assertAsync(server, auth, 200);
                assertRawGet(server, auth, 200);
                assertThat(SearchConnector.getClient(server.baseUrl(), auth).info().name()).isEqualTo("fixture");
                server.assertOriginal("GET", "", auth);
                assertThat(elasticsearchProbe(server, auth).success()).isTrue();
                server.assertOriginal("GET", "", auth);
            }
        }
    }

    private static Stream<Arguments> redirects() {
        return Stream.of(301, 302, 303, 307, 308)
                .flatMap(status -> Stream.of(true, false).map(same -> Arguments.of(status, same)));
    }

    @ParameterizedTest
    @ValueSource(ints = {301, 302, 303, 307, 308})
    void bulkRedirectCannotAcknowledgeDocumentsEvenWithSuccessShapedBody(int status) throws IOException {
        var documents = List.of(
                ExportDocumentIdentity.prepare("traffic", "traffic", Map.of("fixture", "first")),
                ExportDocumentIdentity.prepare("traffic", "traffic", Map.of("fixture", "second")));
        try (var response = new BasicClassicHttpResponse(status)) {
            response.setEntity(new StringEntity(
                    "{\"items\":[{\"index\":{\"status\":201}},{\"index\":{\"status\":201}}]}",
                    ContentType.APPLICATION_JSON));
            var result = SearchClientWrapper.BulkResult.class.cast(Reflect.callStatic(
                    PreparedBulkSender.class, "handleBulkResponse", response, "traffic", documents, -1L));
            assertThat(result.successCount()).isZero();
            assertThat(result.breakdown().failed()).isEqualTo(2);
            assertThat(result.failedItems).extracting(item -> item.index()).containsExactly(0, 1);
            assertThat(result.failedItems).allSatisfy(item -> {
                assertThat(item.type()).isEqualTo("http_failure");
                assertThat(item.reason()).contains("status " + status);
            });
        }
    }

    private static void assertClassic(RedirectServer server, SearchAuth auth, int expected) throws Exception {
        HttpHost host = HttpHost.create(server.baseUrl());
        var post = new HttpPost("/_bulk");
        auth.applyTo(post);
        post.setEntity(new StringEntity(BULK_BODY, ContentType.create("application/x-ndjson")));
        int code = SearchConnector.getClassicHttpClient(server.baseUrl(), auth).execute(host, post, response -> {
            SearchResponseBodies.read(response);
            return response.getCode();
        });
        assertThat(code).isEqualTo(expected);
        server.assertOriginal("POST", BULK_BODY, auth);

        // Default-only headers are another supported way a cached classic client adds auth.
        int getCode = SearchConnector.getClassicHttpClient(server.baseUrl(), auth)
                .execute(host, new HttpGet("/"), response -> {
                    SearchResponseBodies.read(response);
                    return response.getCode();
                });
        assertThat(getCode).isEqualTo(expected);
        server.assertOriginal("GET", "", auth);
    }

    private static void assertAsync(RedirectServer server, SearchAuth auth, int expected) throws Exception {
        var post = SimpleRequestBuilder.post(server.baseUrl() + "/_bulk")
                .setBody(BULK_BODY, ContentType.create("application/x-ndjson")).build();
        auth.applyTo(post);
        var response = SearchResponseBodies.execute(
                SearchConnector.getAsyncHttpClient(server.baseUrl(), auth), post,
                SearchResponseBodies.METADATA_LIMIT_BYTES);
        assertThat(response.getCode()).isEqualTo(expected);
        server.assertOriginal("POST", BULK_BODY, auth);
    }

    private static void assertRawGet(RedirectServer server, SearchAuth auth, int expected) {
        var response = SearchRawGet.performRawGet(server.baseUrl(), auth);
        assertThat(response.statusCode()).isEqualTo(expected);
        server.assertOriginal("GET", "", auth);
    }

    private static SearchConnectionStatus elasticsearchProbe(RedirectServer server, SearchAuth auth) {
        return SearchConnectionStatus.class.cast(Reflect.callStatic(
                SearchConnectionTester.class, "testElasticsearchConnection", server.baseUrl(), auth));
    }

    private record ObservedRequest(String method, String body, String authorization) { }

    /** Owns two loopback origins and records only small synthetic test messages. */
    private static final class RedirectServer implements AutoCloseable {
        private static final byte[] ROOT = ("{\"name\":\"fixture\",\"cluster_name\":\"fixture\","
                + "\"cluster_uuid\":\"fixture\",\"tagline\":\"fixture\",\"version\":{"
                + "\"distribution\":\"opensearch\",\"number\":\"3.7.0\",\"build_type\":\"tar\","
                + "\"build_hash\":\"fixture\",\"build_date\":\"2026-01-01T00:00:00Z\","
                + "\"build_snapshot\":false,\"lucene_version\":\"10.4.0\","
                + "\"minimum_wire_compatibility_version\":\"2.19.0\","
                + "\"minimum_index_compatibility_version\":\"2.0.0\"}}")
                .getBytes(StandardCharsets.UTF_8);
        private final HttpServer source;
        private final HttpServer target;
        private final AtomicInteger originalRequests = new AtomicInteger();
        private final AtomicInteger forwardedRequests = new AtomicInteger();
        private final AtomicReference<ObservedRequest> observed = new AtomicReference<>();

        private RedirectServer(int status, boolean sameOrigin) throws IOException {
            source = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            try {
                target = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            } catch (IOException failure) {
                source.stop(0);
                throw failure;
            }
            target.createContext("/", this::forwarded);
            source.createContext("/", exchange -> {
                if ("/followed".equals(exchange.getRequestURI().getPath())) {
                    forwarded(exchange);
                    return;
                }
                try (exchange) {
                    originalRequests.incrementAndGet();
                    observed.set(new ObservedRequest(exchange.getRequestMethod(),
                            new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8),
                            Objects.requireNonNullElse(exchange.getRequestHeaders().getFirst("Authorization"), "")));
                    String destination = sameOrigin ? baseUrl() : url(target);
                    exchange.getResponseHeaders().set("Location", destination + "/followed");
                    reply(exchange, status);
                }
            });
            source.start();
            target.start();
        }

        private String baseUrl() {
            return url(source);
        }

        private static String url(HttpServer server) {
            return "http://127.0.0.1:" + server.getAddress().getPort();
        }

        private void forwarded(HttpExchange exchange) throws IOException {
            try (exchange) {
                forwardedRequests.incrementAndGet();
                exchange.getRequestBody().readAllBytes();
                reply(exchange, 200);
            }
        }

        private static void reply(HttpExchange exchange, int status) throws IOException {
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, ROOT.length);
            exchange.getResponseBody().write(ROOT);
        }

        private void assertOriginal(String method, String body, SearchAuth auth) {
            assertThat(originalRequests.getAndSet(0)).isEqualTo(1);
            assertThat(forwardedRequests.get()).isZero();
            assertThat(observed.get()).isEqualTo(new ObservedRequest(method, body, auth.authorizationHeaderValue()));
        }

        /** {@inheritDoc} */
        @Override
        public void close() {
            source.stop(0);
            target.stop(0);
        }
    }
}
