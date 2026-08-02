package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchAuth;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchConnector;

/** Tests the single-request Serverless index inventory used before selected-index creation. */
class OpenSearchSinkServerlessIndexListingTest {

    @Test
    void listExistingIndexNames_readsOneJsonInventory() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/_cat/indices", exchange -> {
            requests.incrementAndGet();
            assertThat(exchange.getRequestMethod()).isEqualTo("GET");
            assertThat(exchange.getRequestURI().getQuery()).isEqualTo("format=json&h=index");
            respond(exchange, 200, """
                    [
                      {"index":"tool-burp-settings"},
                      {"index":"tool-burp-traffic"}
                    ]
                    """);
        });
        OpenSearchConnector.closeAll();
        server.start();
        try {
            String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();

            Set<String> names = OpenSearchSink.listExistingIndexNames(
                    baseUrl, OpenSearchAuth.none());

            assertThat(names).containsExactly(
                    "tool-burp-settings",
                    "tool-burp-traffic");
            assertThat(requests).hasValue(1);
        } finally {
            OpenSearchConnector.closeAll();
            server.stop(0);
        }
    }

    @Test
    void usesServerlessIndexListing_acceptsExplicitAndDetectedAmazonServerless() {
        assertThat(OpenSearchSink.usesServerlessIndexListing(
                ConfigState.SearchDestination.OPEN_SEARCH_AMAZON,
                ConfigState.DEPLOYMENT_SERVERLESS,
                "https://example.invalid")).isTrue();
        assertThat(OpenSearchSink.usesServerlessIndexListing(
                ConfigState.SearchDestination.OPEN_SEARCH_AMAZON,
                ConfigState.DEPLOYMENT_AUTO,
                "https://collection.us-east-1.aoss.amazonaws.com")).isTrue();
    }

    @Test
    void usesServerlessIndexListing_rejectsHostedAndOtherDestinations() {
        assertThat(OpenSearchSink.usesServerlessIndexListing(
                ConfigState.SearchDestination.OPEN_SEARCH_AMAZON,
                ConfigState.DEPLOYMENT_HOSTED,
                "https://collection.us-east-1.aoss.amazonaws.com")).isFalse();
        assertThat(OpenSearchSink.usesServerlessIndexListing(
                ConfigState.SearchDestination.OPEN_SEARCH,
                ConfigState.DEPLOYMENT_SERVERLESS,
                "https://collection.us-east-1.aoss.amazonaws.com")).isFalse();
    }

    @Test
    void createSelectedIndexes_serverlessInventorySkipsPerIndexExistenceChecks() throws Exception {
        ConfigState.State previous = RuntimeConfig.getState();
        List<String> requests = new CopyOnWriteArrayList<>();
        AtomicInteger trafficCreates = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            requests.add(exchange.getRequestMethod() + " " + exchange.getRequestURI());
            if ("/_cat/indices".equals(exchange.getRequestURI().getPath())) {
                respond(exchange, 200, """
                        [{"index":"tool-burp-settings"}]
                        """);
                return;
            }
            if ("GET".equals(exchange.getRequestMethod())
                    && ("/tool-burp-settings/_settings".equals(exchange.getRequestURI().getPath())
                    || "/tool-burp-settings/_mapping".equals(exchange.getRequestURI().getPath()))) {
                respond(exchange, 403, "{\"error\":\"read denied\"}");
                return;
            }
            if ("PUT".equals(exchange.getRequestMethod())
                    && "/tool-burp-traffic".equals(exchange.getRequestURI().getPath())) {
                trafficCreates.incrementAndGet();
                String mapping = new String(
                        exchange.getRequestBody().readAllBytes(),
                        StandardCharsets.UTF_8);
                assertThat(mapping).contains("\"refresh_interval\":\"10s\"");
                respond(exchange, 200, "{\"acknowledged\":true}");
                return;
            }
            respond(exchange, 500, "{\"error\":\"unexpected request\"}");
        });
        OpenSearchConnector.closeAll();
        server.start();
        try {
            String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
            RuntimeConfig.updateState(amazonServerlessState(baseUrl));

            List<OpenSearchSink.IndexResult> results = OpenSearchSink.createSelectedIndexes(
                    baseUrl,
                    List.of(ConfigKeys.SRC_SETTINGS, ConfigKeys.SRC_TRAFFIC),
                    OpenSearchAuth.none(),
                    () -> true);

            assertThat(results).hasSize(2);
            assertThat(requests).containsExactly(
                    "GET /_cat/indices?format=json&h=index",
                    "GET /tool-burp-settings/_settings?flat_settings=true",
                    "GET /tool-burp-settings/_mapping",
                    "PUT /tool-burp-traffic");
            assertThat(requests).noneMatch(request -> request.startsWith("HEAD "));
            assertThat(trafficCreates).hasValue(1);
        } finally {
            RuntimeConfig.updateState(previous);
            OpenSearchConnector.closeAll();
            server.stop(0);
        }
    }

    @Test
    void createSelectedIndexes_inventoryFailureFallsBackToPerIndexCheck() throws Exception {
        ConfigState.State previous = RuntimeConfig.getState();
        List<String> requests = new CopyOnWriteArrayList<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            requests.add(exchange.getRequestMethod() + " " + exchange.getRequestURI());
            if ("/_cat/indices".equals(exchange.getRequestURI().getPath())) {
                respond(exchange, 500, "{\"error\":\"inventory unavailable\"}");
                return;
            }
            if ("HEAD".equals(exchange.getRequestMethod())
                    && "/tool-burp-traffic".equals(exchange.getRequestURI().getPath())) {
                exchange.sendResponseHeaders(404, -1L);
                exchange.close();
                return;
            }
            if ("PUT".equals(exchange.getRequestMethod())
                    && "/tool-burp-traffic".equals(exchange.getRequestURI().getPath())) {
                respond(exchange, 200, "{\"acknowledged\":true}");
                return;
            }
            respond(exchange, 500, "{\"error\":\"unexpected request\"}");
        });
        OpenSearchConnector.closeAll();
        server.start();
        try {
            String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
            RuntimeConfig.updateState(amazonServerlessState(baseUrl));

            List<OpenSearchSink.IndexResult> results = OpenSearchSink.createSelectedIndexes(
                    baseUrl,
                    List.of(ConfigKeys.SRC_TRAFFIC),
                    OpenSearchAuth.none(),
                    () -> true);

            assertThat(results).singleElement().satisfies(result ->
                    assertThat(result.status())
                            .isEqualTo(OpenSearchSink.IndexResult.Status.CREATED));
            assertThat(requests).containsExactly(
                    "GET /_cat/indices?format=json&h=index",
                    "HEAD /tool-burp-traffic",
                    "PUT /tool-burp-traffic");
        } finally {
            RuntimeConfig.updateState(previous);
            OpenSearchConnector.closeAll();
            server.stop(0);
        }
    }

    private static ConfigState.State amazonServerlessState(String baseUrl) {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_SETTINGS, ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(
                        false,
                        "",
                        false,
                        false,
                        true,
                        ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                        true,
                        ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                        true,
                        "https://opensearch.url:9200",
                        "",
                        "",
                        ConfigState.OPEN_SEARCH_TLS_VERIFY,
                        ConfigState.defaultOpenSearchOptions(),
                        ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey(),
                        baseUrl,
                        new ConfigState.OpenSearchAmazonOptions(
                                "None",
                                "",
                                "us-east-1",
                                "",
                                "",
                                "",
                                ConfigState.DEPLOYMENT_SERVERLESS,
                                ConfigState.OPEN_SEARCH_TLS_VERIFY,
                                "",
                                "",
                                ""),
                        "",
                        ConfigState.defaultElasticsearchOptions()),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (var responseBody = exchange.getResponseBody()) {
            responseBody.write(bytes);
        } finally {
            exchange.close();
        }
    }
}
