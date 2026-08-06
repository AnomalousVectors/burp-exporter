package ai.anomalousvectors.tools.burp.sinks;

import static ai.anomalousvectors.tools.burp.testutils.LazySchedulers.peek;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.LockSupport;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.testutils.TestPathSupport;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.BurpRuntimeMetadata;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;
import ai.anomalousvectors.tools.burp.utils.FileUtil;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.SecureCredentialStore;
import ai.anomalousvectors.tools.burp.utils.opensearch.IndexingRetryCoordinator;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchConnector;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Version;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.project.Project;

class ExportReporterLifecycleTest {

    @Test
    void resetForTests_stopsSchedulers_and_clearsProcessLocalState() {
        try {
            MontoyaApi api = mock(MontoyaApi.class);
            BurpSuite burpSuite = mock(BurpSuite.class);
            Version version = mock(Version.class);
            Project project = mock(Project.class);
            when(api.burpSuite()).thenReturn(burpSuite);
            when(api.project()).thenReturn(project);
            when(burpSuite.version()).thenReturn(version);
            when(project.id()).thenReturn("project-123");

            MontoyaApiProvider.set(api);
            BurpRuntimeMetadata.prime(api);
            RuntimeConfig.setExportRunning(true);
            SecureCredentialStore.saveOpenSearchCredentials("user", "pass");

            ExporterIndexStatsReporter.start();
            SettingsIndexReporter.start();
            FindingsIndexReporter.start();
            SitemapIndexReporter.start();
            ProxyWebSocketIndexReporter.startLivePoll();

            ExportReporterLifecycle.resetForTests();

            assertThat(peek(ExporterIndexStatsReporter.class, "SCHEDULER")).isNull();
            assertThat(peek(SettingsIndexReporter.class, "SCHEDULER")).isNull();
            assertThat(peek(FindingsIndexReporter.class, "SCHEDULER")).isNull();
            assertThat(peek(SitemapIndexReporter.class, "SCHEDULER")).isNull();
            assertThat(peek(ProxyWebSocketIndexReporter.class, "SCHEDULER")).isNull();
            assertThat(MontoyaApiProvider.get()).isNull();
            assertThat(BurpRuntimeMetadata.burpVersion()).isNull();
            assertThat(BurpRuntimeMetadata.projectId()).isNull();
            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(SecureCredentialStore.loadOpenSearchCredentials().username()).isEmpty();
            assertThat(SecureCredentialStore.loadOpenSearchCredentials().password()).isEmpty();
        } finally {
            ExportReporterLifecycle.resetForTests();
        }
    }

    @Test
    void stopAndClearPendingExportWork_clearsRetryAndTrafficBacklog() {
        try {
            RuntimeConfig.setExportRunning(true);

            String exporterIndexName = IndexNaming.indexNameForShortName("exporter");
            IndexingRetryCoordinator coordinator = IndexingRetryCoordinator.getInstance();
            coordinator.pushDocument("https://127.0.0.1:1", exporterIndexName, Map.of("message", Map.of("summary", "x")), "exporter");
            TrafficExportQueue.offer(Map.of("url", "https://example.com/", "status", 200));

            ExportReporterLifecycle.stopAndClearPendingExportWork();

            long deadline = System.currentTimeMillis() + 2_000;
            while (System.currentTimeMillis() < deadline
                    && (coordinator.getQueueSize(exporterIndexName) != 0
                    || TrafficExportQueue.getCurrentSize() != 0
                    || TrafficExportQueue.getCurrentSpillSize() != 0)) {
                LockSupport.parkNanos(50_000_000L);
            }

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(coordinator.getQueueSize(exporterIndexName)).isZero();
            assertThat(TrafficExportQueue.getCurrentSize()).isZero();
            assertThat(TrafficExportQueue.getCurrentSpillSize()).isZero();
        } finally {
            ExportReporterLifecycle.resetForTests();
        }
    }

    @Test
    void stopAndClearPendingExportWork_clearsRepeaterLiveMetadataTracker() {
        try {
            HttpRequestResponse exchange = requestResponse(
                    "GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA");
            RepeaterMetadataFields.Metadata metadata =
                    new RepeaterMetadataFields.Metadata("live-tab", "live-group");
            long now = System.currentTimeMillis();

            RepeaterLiveMetadataTracker.observe(exchange, metadata, now);

            assertThat(RepeaterLiveMetadataTracker.resolveRequestResolution(exchange.request(), now).metadata())
                    .isEqualTo(metadata);

            ExportReporterLifecycle.stopAndClearPendingExportWork();

            assertThat(RepeaterLiveMetadataTracker.resolveRequestResolution(exchange.request(), now).metadata())
                    .isEqualTo(RepeaterMetadataFields.Metadata.empty());
            assertThat(RepeaterLiveMetadataTracker.resolveExchangeResolution(
                    exchange.request(),
                    exchange.response(),
                    now).metadata()).isEqualTo(RepeaterMetadataFields.Metadata.empty());
        } finally {
            ExportReporterLifecycle.resetForTests();
        }
    }

    @Test
    void stopAndClearPendingExportWork_validatesArtifactsBeforeReleasingDirectoryLock()
            throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("file-stop-integrity")
                    .toAbsolutePath()
                    .normalize();
            RuntimeConfig.updateState(fileExportState(root));
            RuntimeConfig.setExportRunning(true);
            String indexKey = "traffic";
            List<FileExportService.FileInitResult> first =
                    FileExportService.createSelectedExportFiles(List.of(ConfigKeys.SRC_TRAFFIC));
            assertThat(first).allMatch(result -> result.status() != FileUtil.Status.FAILED);
            Files.writeString(
                    first.getFirst().path(),
                    "{\"external\":true}\n",
                    StandardOpenOption.APPEND);

            ExportReporterLifecycle.stopAndClearPendingExportWork();

            assertThat(FileExportStats.getArtifactIntegrity(indexKey))
                    .isEqualTo(FileExportStats.ArtifactIntegrity.FAILED);
            assertThat(FileExportStats.getLastError(indexKey))
                    .contains("integrity lost");
            assertThat(FileExportService.hasTrackedArtifacts()).isFalse();

            List<FileExportService.FileInitResult> second =
                    FileExportService.createSelectedExportFiles(List.of(ConfigKeys.SRC_TRAFFIC));
            assertThat(second).allMatch(result -> result.status() != FileUtil.Status.FAILED);
        } finally {
            ExportReporterLifecycle.resetForTests();
        }
    }

    @Test
    void awaitStopReclaim_returnsImmediately_whenNoAsyncCloseHasBeenFired() {
        // No releaseRunResourcesAsync() was triggered, so awaitStopReclaim must not block.
        // A 5 s budget is generous; the call should return in under 50 ms.
        long startNs = System.nanoTime();
        ExportReporterLifecycle.awaitStopReclaim(5_000L);
        long elapsedMs = (System.nanoTime() - startNs) / 1_000_000L;
        assertThat(elapsedMs).as("awaitStopReclaim should be a no-op when no daemon was fired")
                .isLessThan(500L);
    }

    @Test
    void releaseRunResourcesAsync_thenAwaitStopReclaim_joinsTheDaemonThread() {
        // Drain the OpenSearch client cache up front so the daemon's closeAll() is a no-op and
        // this test asserts the join contract rather than real-cluster TLS/reactor teardown
        // timing. Earlier integration tests in the same JVM may have populated the cache with
        // live clients whose close() can take several seconds.
        OpenSearchConnector.closeAll();
        ExportReporterLifecycle.awaitStopReclaim(30_000L);

        ExportReporterLifecycle.releaseRunResourcesAsync();

        long startNs = System.nanoTime();
        ExportReporterLifecycle.awaitStopReclaim(30_000L);
        long elapsedMs = (System.nanoTime() - startNs) / 1_000_000L;
        assertThat(elapsedMs).as("daemon must terminate within the budget when cache is empty")
                .isLessThan(30_000L);

        // After awaitStopReclaim, the tracked reference must have been consumed: a second call
        // must be a no-op rather than re-joining the same already-terminated thread.
        long secondStartNs = System.nanoTime();
        ExportReporterLifecycle.awaitStopReclaim(30_000L);
        long secondElapsedMs = (System.nanoTime() - secondStartNs) / 1_000_000L;
        assertThat(secondElapsedMs).as("second awaitStopReclaim should observe the cleared reference")
                .isLessThan(500L);
    }

    @Test
    void releaseRunResourcesAsync_isIndependent_acrossSuccessiveStopCycles() {
        // Two Stop cycles in succession is the realistic operator pattern (Start -> Stop ->
        // Start -> Stop). The second fire must replace the tracked thread reference; awaiting
        // after each fire must join only the corresponding daemon. Drain the cache first so
        // closeAll() work is bounded and not dominated by live-cluster reactor teardown.
        OpenSearchConnector.closeAll();
        ExportReporterLifecycle.awaitStopReclaim(30_000L);

        ExportReporterLifecycle.releaseRunResourcesAsync();
        ExportReporterLifecycle.awaitStopReclaim(30_000L);

        ExportReporterLifecycle.releaseRunResourcesAsync();
        long startNs = System.nanoTime();
        ExportReporterLifecycle.awaitStopReclaim(30_000L);
        long elapsedMs = (System.nanoTime() - startNs) / 1_000_000L;
        assertThat(elapsedMs).isLessThan(30_000L);
    }

    @Test
    void stopAndClearPendingExportWork_drainsAcceptedTrafficBeforeClearingQueues() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("repeater-tabs-stop-purge");
            RuntimeConfig.updateState(fileExportState(root));
            RuntimeConfig.setExportRunning(true);

            assertThat(TrafficExportQueue.offerAccepted(trafficDocument("https://example.test/repeater/1", "Tab 1")))
                    .isTrue();
            assertThat(TrafficExportQueue.offerAccepted(trafficDocument("https://example.test/repeater/2", "Tab 2")))
                    .isTrue();

            ExportReporterLifecycle.stopAndClearPendingExportWork();

            Path jsonlPath = root.resolve(IndexNaming.indexNameForShortName("traffic") + ".jsonl");
            assertThat(jsonlPath).exists();
            assertThat(Files.readAllLines(jsonlPath)).hasSize(2);
            assertThat(TrafficExportQueue.getCurrentSize()).isZero();
            assertThat(TrafficExportQueue.getCurrentSpillSize()).isZero();
        } finally {
            ExportReporterLifecycle.resetForTests();
        }
    }

    private static HttpRequestResponse requestResponse(String rawRequest, String rawResponse) {
        HttpRequest request = mock(HttpRequest.class);
        ByteArray requestBytes = byteArray(rawRequest);
        when(request.toByteArray()).thenReturn(requestBytes);

        HttpRequestResponse requestResponse = mock(HttpRequestResponse.class);
        when(requestResponse.request()).thenReturn(request);

        HttpResponse response = mock(HttpResponse.class);
        ByteArray responseBytes = byteArray(rawResponse);
        when(response.toByteArray()).thenReturn(responseBytes);
        when(requestResponse.response()).thenReturn(response);
        return requestResponse;
    }

    private static ByteArray byteArray(String value) {
        ByteArray bytes = mock(ByteArray.class);
        when(bytes.getBytes()).thenReturn(value.getBytes(StandardCharsets.UTF_8));
        return bytes;
    }

    private static ConfigState.State fileExportState(Path root) {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(
                        true,
                        root.toString(),
                        true,
                        false,
                        true,
                        ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                        false,
                        ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                        false,
                        "",
                        "",
                        "",
                        ConfigState.OPEN_SEARCH_TLS_VERIFY),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("repeater_tabs"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);
    }

    private static Map<String, Object> trafficDocument(String url, String repeaterTabName) {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", "1");
        meta.put("indexed_at", "2026-04-19T00:00:00Z");

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("url", url);
        request.put("method", "GET");
        request.put("path", "/repeater");

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status_code", 200);

        Map<String, Object> burp = new LinkedHashMap<>();
        burp.put("reporting_tool", "Repeater Tabs");

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("burp", burp);
        RepeaterMetadataFields.put(document, repeaterTabName, "Large Set");
        document.put("request", request);
        document.put("response", response);
        document.put("meta", meta);
        return document;
    }
}
