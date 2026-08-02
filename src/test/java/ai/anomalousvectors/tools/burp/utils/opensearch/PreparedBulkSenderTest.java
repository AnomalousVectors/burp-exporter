package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.BulkOutcomeBreakdown;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

class PreparedBulkSenderTest {

    @Test
    void push_emptyDocuments_returnsZero() {
        OpenSearchClientWrapper.BulkResult result =
                PreparedBulkSender.push("https://opensearch.url:9200", "idx", List.of());

        assertThat(result.successCount()).isZero();
        assertThat(result.failedItems).isEmpty();
    }

    @Test
    void parseBulkResponse_delegatesToSharedParser() {
        String body = "{\"items\":[{\"index\":{\"status\":201}},{\"index\":{\"status\":201}}]}";

        OpenSearchClientWrapper.BulkResult result =
                PreparedBulkSender.parseBulkResponse(body, 2, "traffic-idx");

        assertThat(result.successCount()).isEqualTo(2);
        assertThat(result.failedItems).isEmpty();
    }

    @Test
    void parseBulkResponse_blankBody_countsAllAttemptedAsFailed() {
        OpenSearchClientWrapper.BulkResult result =
                PreparedBulkSender.parseBulkResponse("  ", 3, "traffic-idx");

        assertThat(result.successCount()).isZero();
        assertThat(result.breakdown().failed()).isEqualTo(3);
        assertThat(result.failedItems).extracting(item -> Objects.requireNonNull(item).index())
                .containsExactly(0, 1, 2);
    }

    @Test
    void parseBulkResponse_malformedBody_countsAllAttemptedAsFailed() {
        OpenSearchClientWrapper.BulkResult result =
                PreparedBulkSender.parseBulkResponse("not-json", 2, "traffic-idx");

        assertThat(result.successCount()).isZero();
        assertThat(result.breakdown().failed()).isEqualTo(2);
        assertThat(result.failedItems).extracting(item -> Objects.requireNonNull(item).index())
                .containsExactly(0, 1);
    }

    @Test
    void parseBulkResponse_incompleteItems_marksOmittedAttemptsFailed() {
        String body = "{\"items\":[{\"index\":{\"status\":201}}]}";

        OpenSearchClientWrapper.BulkResult result =
                PreparedBulkSender.parseBulkResponse(body, 2, "traffic-idx");

        assertThat(result.successCount()).isEqualTo(1);
        assertThat(result.breakdown().failed()).isEqualTo(1);
        assertThat(result.failedItems).singleElement().satisfies(item -> {
            assertThat(item.index()).isEqualTo(1);
            assertThat(item.type()).isEqualTo("bulk_response_incomplete");
        });
    }

    @Test
    void ambiguousPartialBulkResult_normalizesToWholeBatchTransientFailure() {
        OpenSearchClientWrapper.BulkResult result = new OpenSearchClientWrapper.BulkResult(
                BulkOutcomeBreakdown.classified(1, 3),
                List.of(new OpenSearchClientWrapper.FailedItem(
                        1, "es_rejected_execution_exception", "queue full")),
                800_000L);

        assertThat(result.successCount()).isZero();
        assertThat(result.breakdown().failed()).isEqualTo(3);
        assertThat(result.maxSuccessfulRequestBytes()).isZero();
        assertThat(result.failedItems)
                .extracting(item -> Objects.requireNonNull(item).index())
                .containsExactly(0, 1, 2);
        assertThat(result.failedItems)
                .allSatisfy(item -> assertThat(item.type())
                        .isEqualTo("ambiguous_partial_bulk_result"));
    }

    @Test
    void bulkResult_success_retainsActualMaximumRequestBytes() {
        OpenSearchClientWrapper.BulkResult result = new OpenSearchClientWrapper.BulkResult(
                BulkOutcomeBreakdown.classified(2, 0), List.of(), 700_000L);

        assertThat(result.successCount()).isEqualTo(2);
        assertThat(result.maxSuccessfulRequestBytes()).isEqualTo(700_000L);
    }

    @Test
    void preparedDocument_hasBulkBytesForFastPath() throws Exception {
        Map<String, Object> doc = new LinkedHashMap<>();
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", "1");
        doc.put("meta", meta);

        PreparedExportDocument prepared = ExportDocumentIdentity.prepare("burp-exporter-test", "traffic", doc);

        assertThat(prepared.bulkNdjsonBytes()).isNotEmpty();
    }

    @Test
    void push_splitPartsRemapsFailuresToOriginalDocumentIndexes() throws Exception {
        ConfigState.State previous = RuntimeConfig.getState();
        AtomicInteger requestCount = new AtomicInteger();
        List<Integer> requestItemCounts = new CopyOnWriteArrayList<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/tool-burp-settings/_bulk", exchange -> {
            int request = requestCount.incrementAndGet();
            int itemCount = countBulkItems(exchange);
            requestItemCounts.add(itemCount);
            respondWithBulkItems(exchange, itemCount, request == 2 ? 0 : -1);
        });
        try {
            server.start();
            OpenSearchConnector.closeAll();
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(
                            false,
                            "",
                            false,
                            true,
                            true,
                            ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                            true,
                            ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                            true,
                            "http://127.0.0.1:" + server.getAddress().getPort(),
                            "",
                            "",
                            ConfigState.OPEN_SEARCH_TLS_VERIFY,
                            ConfigState.defaultOpenSearchOptions(),
                            ConfigState.SearchDestination.OPEN_SEARCH.configKey(),
                            "",
                            ConfigState.defaultOpenSearchAmazonOptions(),
                            "",
                            ConfigState.defaultElasticsearchOptions()),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null));
            RuntimeConfig.setExportRunning(true);
            BulkByteBudget.resetForStart();
            List<PreparedExportDocument> documents = java.util.stream.IntStream.range(0, 4)
                    .mapToObj(index -> ExportDocumentIdentity.prepare(
                            "tool-burp-settings",
                            "settings",
                            Map.of("project", Map.of(
                                    "ordinal", index,
                                    "payload", "x".repeat(400_000)))))
                    .toList();
            long liveBudget = BulkByteBudget.currentMaxBytes();
            long firstTwoBytes =
                    documents.get(0).resolvedBulkBytes() + documents.get(1).resolvedBulkBytes();
            long firstThreeBytes = firstTwoBytes + documents.get(2).resolvedBulkBytes();
            assertThat(firstTwoBytes).isLessThanOrEqualTo(liveBudget);
            assertThat(firstThreeBytes).isGreaterThan(liveBudget);

            OpenSearchClientWrapper.BulkResult result = PreparedBulkSender.push(
                    "http://127.0.0.1:" + server.getAddress().getPort(),
                    "tool-burp-settings",
                    documents);

            assertThat(requestCount.get()).isEqualTo(2);
            assertThat(requestItemCounts).containsExactly(2, 2);
            assertThat(result.successCount()).isEqualTo(3);
            assertThat(result.failedItems).singleElement().satisfies(item -> {
                assertThat(item.index()).isEqualTo(2);
                assertThat(item.type()).isEqualTo("mapper_parsing_exception");
            });
        } finally {
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.updateState(previous);
            BulkByteBudget.resetForStart();
            OpenSearchConnector.closeAll();
            server.stop(0);
        }
    }

    private static int countBulkItems(HttpExchange exchange) throws IOException {
        String body = new String(
                exchange.getRequestBody().readAllBytes(),
                StandardCharsets.UTF_8);
        return Math.toIntExact(body.lines().count() / 2L);
    }

    private static void respondWithBulkItems(
            HttpExchange exchange,
            int itemCount,
            int failedItemIndex) throws IOException {
        StringBuilder body = new StringBuilder("{\"errors\":")
                .append(failedItemIndex >= 0)
                .append(",\"items\":[");
        for (int index = 0; index < itemCount; index++) {
            if (index > 0) {
                body.append(',');
            }
            if (index == failedItemIndex) {
                body.append("{\"index\":{\"status\":400,\"error\":{")
                        .append("\"type\":\"mapper_parsing_exception\",")
                        .append("\"reason\":\"test failure\"}}}");
            } else {
                body.append("{\"index\":{\"status\":201,\"result\":\"created\"}}");
            }
        }
        body.append("]}");
        byte[] response = body.toString().getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, response.length);
        try (var responseBody = exchange.getResponseBody()) {
            responseBody.write(response);
        } finally {
            exchange.close();
        }
    }
}
