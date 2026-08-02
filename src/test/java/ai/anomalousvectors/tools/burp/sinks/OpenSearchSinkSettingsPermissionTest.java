package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchAuth;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchConnector;

class OpenSearchSinkSettingsPermissionTest {

    private static final String INDEX_NAME = "tool-burp-test";
    private static final String EXPECTED_INDEX_JSON = """
            {
              "settings": {},
              "mappings": {
                "properties": {
                  "message": { "type": "keyword" }
                }
              }
            }
            """;

    @Test
    void settingsPermissionDenied_compatibleMappingReturnsExists() throws Exception {
        ValidationOutcome outcome = validateWithMapping("""
                {
                  "tool-burp-test": {
                    "mappings": {
                      "properties": {
                        "message": { "type": "keyword" }
                      }
                    }
                  }
                }
                """);

        assertThat(outcome.result().status()).isEqualTo(OpenSearchSink.IndexResult.Status.EXISTS);
        assertThat(outcome.mappingRequests()).isEqualTo(1);
    }

    @Test
    void settingsPermissionDenied_incompatibleMappingReturnsFailed() throws Exception {
        ValidationOutcome outcome = validateWithMapping("""
                {
                  "tool-burp-test": {
                    "mappings": {
                      "properties": {
                        "message": { "type": "text" }
                      }
                    }
                  }
                }
                """);

        assertThat(outcome.result().status()).isEqualTo(OpenSearchSink.IndexResult.Status.FAILED);
        assertThat(outcome.result().error()).contains("mappings.properties.message.type");
        assertThat(outcome.mappingRequests()).isEqualTo(1);
    }

    private static ValidationOutcome validateWithMapping(String mappingJson) throws Exception {
        AtomicInteger mappingRequests = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(
                "/" + INDEX_NAME + "/_settings",
                exchange -> respond(exchange, 403, ""));
        server.createContext(
                "/" + INDEX_NAME + "/_mapping",
                exchange -> {
                    mappingRequests.incrementAndGet();
                    respond(exchange, 200, mappingJson);
                });
        OpenSearchConnector.closeAll();
        server.start();
        try {
            String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
            OpenSearchSink.IndexResult result = OpenSearchSink.validateExistingIndexSettings(
                    baseUrl,
                    "test",
                    INDEX_NAME,
                    EXPECTED_INDEX_JSON,
                    OpenSearchAuth.none(),
                    "OpenSearch");
            return new ValidationOutcome(result, mappingRequests.get());
        } finally {
            OpenSearchConnector.closeAll();
            server.stop(0);
        }
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

    private record ValidationOutcome(OpenSearchSink.IndexResult result, int mappingRequests) {
    }
}
