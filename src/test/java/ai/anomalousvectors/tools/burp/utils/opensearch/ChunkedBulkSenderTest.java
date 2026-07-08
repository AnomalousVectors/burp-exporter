package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import ai.anomalousvectors.tools.burp.sinks.TrafficQueueEntry;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

import org.apache.hc.client5.http.classic.methods.HttpPost;
import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.SecureCredentialStore;

/**
 * Unit tests for {@link ChunkedBulkSender}: URL building, response parsing, and push with
 * empty queue. Full drain and HTTP behaviour are covered by integration tests.
 */
class ChunkedBulkSenderTest {

    @Test
    void buildBulkUrl_normalizesTrailingSlash() {
        assertThat(ChunkedBulkSender.buildBulkUrl("https://opensearch.url:9200/", "my-index"))
                .isEqualTo("https://opensearch.url:9200/my-index/_bulk");
    }

    @Test
    void buildBulkUrl_noTrailingSlash() {
        assertThat(ChunkedBulkSender.buildBulkUrl("https://opensearch.url:9200", "tool-burp-traffic"))
                .isEqualTo("https://opensearch.url:9200/tool-burp-traffic/_bulk");
    }

    @Test
    void parseBulkResponse_emptyBody_returnsZeroSuccess() {
        ChunkedBulkSender.Result r = ChunkedBulkSender.parseBulkResponse("", 5);
        assertThat(r.successCount).isZero();
        assertThat(r.attemptedCount).isEqualTo(5);
    }

    @Test
    void parseBulkResponse_nullBody_returnsZeroSuccess() {
        ChunkedBulkSender.Result r = ChunkedBulkSender.parseBulkResponse(null, 3);
        assertThat(r.successCount).isZero();
        assertThat(r.attemptedCount).isEqualTo(3);
    }

    @Test
    void parseBulkResponse_validItems_countsSuccess() {
        String body = "{\"took\":1,\"errors\":false,\"items\":["
                + "{\"index\":{\"_index\":\"t\",\"status\":201}},"
                + "{\"index\":{\"_index\":\"t\",\"status\":200}}]}";
        ChunkedBulkSender.Result r = ChunkedBulkSender.parseBulkResponse(body, 2);
        assertThat(r.successCount).isEqualTo(2);
        assertThat(r.attemptedCount).isEqualTo(2);
        assertThat(r.isFullSuccess()).isTrue();
    }

    @Test
    void parseBulkResponse_classifiesCreatedAndUpdatedInBreakdown() {
        String body = "{\"took\":1,\"errors\":false,\"items\":["
                + "{\"index\":{\"_index\":\"t\",\"status\":201,\"result\":\"created\"}},"
                + "{\"index\":{\"_index\":\"t\",\"status\":200,\"result\":\"updated\"}}]}";
        ChunkedBulkSender.Result result = ChunkedBulkSender.parseBulkResponse(body, 2);

        assertThat(result.breakdown.created()).isEqualTo(1);
        assertThat(result.breakdown.updated()).isEqualTo(1);
        assertThat(result.successCount).isEqualTo(2);
    }

    @Test
    void parseBulkResponse_oneFailure_countsCorrectly() {
        String body = "{\"took\":1,\"errors\":true,\"items\":["
                + "{\"index\":{\"_index\":\"t\",\"status\":201}},"
                + "{\"index\":{\"_index\":\"t\",\"status\":400}}]}";
        ChunkedBulkSender.Result r = ChunkedBulkSender.parseBulkResponse(body, 2);
        assertThat(r.successCount).isEqualTo(1);
        assertThat(r.attemptedCount).isEqualTo(2);
        assertThat(r.isFullSuccess()).isFalse();
    }

    @Test
    void push_emptyQueue_returnsZeroAttempted_afterShortWait() {
        LinkedBlockingQueue<TrafficQueueEntry> queue = new LinkedBlockingQueue<>();
        ChunkedBulkSender.Result r = ChunkedBulkSender.push(
                "http://opensearch.url:9999", "test-index", "traffic", queue, 10, 5 * 1024 * 1024, 50);
        assertThat(r.attemptedCount).isZero();
        assertThat(r.successCount).isZero();
    }

    @Test
    void ndjsonQueueInputStream_stillWritesReservedFirstDoc_afterInitialDelay() throws Exception {
        LinkedBlockingQueue<TrafficQueueEntry> queue = new LinkedBlockingQueue<>();
        TrafficQueueEntry firstEntry = TrafficQueueEntry.from(trafficDoc("Repeater Tabs"));

        StreamHarness harness = newStreamHarness(
                queue,
                firstEntry,
                10,
                5 * 1024 * 1024L,
                1L);

        java.util.concurrent.TimeUnit.MILLISECONDS.sleep(5L);

        byte[] payload = harness.stream().readAllBytes();
        assertThat(payload).isNotEmpty();
        assertThat(new String(payload, StandardCharsets.UTF_8))
                .contains("\"burp\":{\"reporting_tool\":\"Repeater Tabs\"}");
        assertThat(harness.attempted().get()).isEqualTo(1);
    }

    @Test
    void ndjsonQueueInputStream_capturesAcceptedDocsForBatchFileEmit() throws Exception {
        LinkedBlockingQueue<TrafficQueueEntry> queue = new LinkedBlockingQueue<>();
        TrafficQueueEntry firstEntry = TrafficQueueEntry.from(trafficDoc("Repeater Tabs"));
        StreamHarness harness = newStreamHarness(queue, firstEntry, 10, 5 * 1024 * 1024L, 1L);

        harness.stream().readAllBytes();

        List<?> captured = capturedDocumentsForFileEmit(harness.stream());
        assertThat(captured).hasSize(1);
        PreparedExportDocument capturedDocument = (PreparedExportDocument) captured.getFirst();
        assertThat(capturedDocument.document())
                .extractingByKey("burp")
                .isEqualTo(Map.of("reporting_tool", "Repeater Tabs"));
    }

    @Test
    void ndjsonQueueInputStream_doesNotCaptureSizeCappedPutBackDoc() throws Exception {
        LinkedBlockingQueue<TrafficQueueEntry> queue = new LinkedBlockingQueue<>();
        TrafficQueueEntry firstEntry = TrafficQueueEntry.from(trafficDoc("Repeater Tabs"));
        TrafficQueueEntry secondEntry = TrafficQueueEntry.from(trafficDoc("Proxy"));
        queue.offer(secondEntry);
        long maxBytes = firstEntry.prepared().estimatedBulkBytes() + 1L;
        StreamHarness harness = newStreamHarness(queue, firstEntry, 10, maxBytes, TimeUnit.SECONDS.toNanos(1));

        harness.stream().readAllBytes();

        assertThat(capturedDocumentsForFileEmit(harness.stream())).hasSize(1);
        assertThat(queue).containsExactly(secondEntry);
    }

    @Test
    void addPreemptiveAuthHeader_setsBasicHeader_whenCredentialsConfigured() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(stateWithOpenSearchCreds("alice", "s3cr3t"));
            HttpPost post = new HttpPost("https://opensearch.url:9200/_bulk");

            ChunkedBulkSender.addPreemptiveAuthHeader(post);

            String expected = "Basic "
                    + Base64.getEncoder().encodeToString("alice:s3cr3t".getBytes(StandardCharsets.UTF_8));
            assertThat(post.getFirstHeader("Authorization")).isNotNull();
            assertThat(post.getFirstHeader("Authorization").getValue()).isEqualTo(expected);
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void addPreemptiveAuthHeader_doesNothing_whenCredentialsMissing() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(stateWithOpenSearchCreds("", ""));
            HttpPost post = new HttpPost("https://opensearch.url:9200/_bulk");

            ChunkedBulkSender.addPreemptiveAuthHeader(post);

            assertThat(post.getFirstHeader("Authorization")).isNull();
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void addPreemptiveAuthHeader_setsApiKeyHeader_whenTokenConfigured() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            SecureCredentialStore.saveApiKeyCredentials("os_api_token");
            RuntimeConfig.updateState(stateWithOpenSearchAuth("API key"));
            HttpPost post = new HttpPost("https://opensearch.url:9200/_bulk");

            ChunkedBulkSender.addPreemptiveAuthHeader(post);

            assertThat(post.getFirstHeader("Authorization")).isNotNull();
            assertThat(post.getFirstHeader("Authorization").getValue()).isEqualTo("ApiKey os_api_token");
        } finally {
            RuntimeConfig.updateState(previous);
            SecureCredentialStore.clearAll();
        }
    }

    @Test
    void addPreemptiveAuthHeader_setsBearerHeader_whenJwtConfigured() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            SecureCredentialStore.saveJwtCredentials("jwt-token");
            RuntimeConfig.updateState(stateWithOpenSearchAuth("Bearer token"));
            HttpPost post = new HttpPost("https://opensearch.url:9200/_bulk");

            ChunkedBulkSender.addPreemptiveAuthHeader(post);

            assertThat(post.getFirstHeader("Authorization")).isNotNull();
            assertThat(post.getFirstHeader("Authorization").getValue()).isEqualTo("Bearer jwt-token");
        } finally {
            RuntimeConfig.updateState(previous);
            SecureCredentialStore.clearAll();
        }
    }

    private static ConfigState.State stateWithOpenSearchCreds(String user, String pass) {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, "", true, "https://opensearch.url:9200", user, pass, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        );
    }

    private static ConfigState.State stateWithOpenSearchAuth(String authType) {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
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
                        new ConfigState.OpenSearchOptions(authType, "", "", "", "", "", "")),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        );
    }

    private static Map<String, Object> trafficDoc(String reportingTool) {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("burp", Map.of("reporting_tool", reportingTool));
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", "1");
        doc.put("meta", meta);
        return doc;
    }

    private static StreamHarness newStreamHarness(
            LinkedBlockingQueue<TrafficQueueEntry> queue,
            TrafficQueueEntry firstEntry,
            int maxBatch,
            long maxBytes,
            long maxWaitNanos) throws Exception {
        Class<?> streamClass = Class.forName(
                "ai.anomalousvectors.tools.burp.utils.opensearch.ChunkedBulkSender$NdjsonQueueInputStream");
        Constructor<?> constructor = streamClass.getDeclaredConstructor(
                java.util.concurrent.BlockingQueue.class,
                TrafficQueueEntry.class,
                int.class,
                long.class,
                long.class,
                AtomicInteger.class,
                AtomicLong.class);
        constructor.setAccessible(true);
        AtomicInteger attempted = new AtomicInteger();
        AtomicLong attemptedBytes = new AtomicLong();
        InputStream stream = (InputStream) constructor.newInstance(
                queue,
                firstEntry,
                maxBatch,
                maxBytes,
                maxWaitNanos,
                attempted,
                attemptedBytes);
        return new StreamHarness(stream, attempted, attemptedBytes);
    }

    private static List<?> capturedDocumentsForFileEmit(InputStream stream) throws Exception {
        Method method = stream.getClass().getDeclaredMethod("acceptedDocumentsForFileEmit");
        method.setAccessible(true);
        return (List<?>) method.invoke(stream);
    }

    private record StreamHarness(
            InputStream stream,
            AtomicInteger attempted,
            AtomicLong attemptedBytes) {
    }
}
