package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Answers;

import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.concurrent.LazyScheduler;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.websocket.Direction;

class ProxyWebSocketIndexReporterTest {

    @TempDir
    Path tempDir;

    @AfterEach
    public void resetRuntimeConfig() {
        ProxyWebSocketIndexReporter.stop();
        TrafficExportQueue.setDrainDisabledForTests(false);
        TrafficExportQueue.stopWorker();
        TrafficExportQueue.clearPendingWork();
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        RuntimeConfig.setExportRunning(false);
        MontoyaApiProvider.set(null);
    }

    @Test
    void buildDocument_includesExpectedWebSocketFields() {
        resetRuntimeConfig();
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));

        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(true);

        ProxyWebSocketMessage ws = mock(ProxyWebSocketMessage.class);
        HttpRequest upgrade = mock(HttpRequest.class);
        HttpService svc = mock(HttpService.class);
        ByteArray payload = mock(ByteArray.class);
        ByteArray editedPayload = mock(ByteArray.class);

        when(svc.host()).thenReturn("example.com");
        when(svc.port()).thenReturn(443);
        when(svc.secure()).thenReturn(true);

        when(upgrade.httpService()).thenReturn(svc);
        when(upgrade.url()).thenReturn("https://example.com/ws");
        when(upgrade.httpVersion()).thenReturn("HTTP/1.1");
        when(upgrade.path()).thenReturn("/ws");
        when(upgrade.method()).thenReturn("GET");
        when(upgrade.pathWithoutQuery()).thenReturn("/ws");
        when(upgrade.query()).thenReturn("");
        when(upgrade.fileExtension()).thenReturn("");
        when(upgrade.headers()).thenReturn(List.of());
        when(upgrade.parameters()).thenReturn(List.of());
        when(upgrade.body()).thenReturn(null);
        when(upgrade.markers()).thenReturn(List.of());
        when(upgrade.contentType()).thenReturn(null);

        when(payload.getBytes()).thenReturn("hello".getBytes(StandardCharsets.UTF_8));
        when(editedPayload.getBytes()).thenReturn("HELLO".getBytes(StandardCharsets.UTF_8));

        when(ws.upgradeRequest()).thenReturn(upgrade);
        when(ws.id()).thenReturn(12);
        when(ws.webSocketId()).thenReturn(7);
        when(ws.listenerPort()).thenReturn(8080);
        when(ws.payload()).thenReturn(payload);
        when(ws.editedPayload()).thenReturn(editedPayload);
        when(ws.direction()).thenReturn(Direction.CLIENT_TO_SERVER);
        when(ws.time()).thenReturn(ZonedDateTime.now());
        when(ws.annotations()).thenReturn(null);

        Map<String, Object> doc = ProxyWebSocketIndexReporter.buildDocument(api, ws);

        assertThat(doc).isNotNull();
        Map<?, ?> burp = nestedMap(doc, "burp");
        assertThat(burp.get("reporting_tool")).isEqualTo("Proxy WebSocket");
        assertThat(doc).doesNotContainKey("tool_type");
        Map<?, ?> websocket = nestedMap(doc, "websocket");
        Map<?, ?> payloadDoc = nestedMap(websocket, "payload");
        assertThat(websocket.get("is_websocket")).isEqualTo(true);
        assertThat(websocket.get("is_edited")).isEqualTo(true);
        assertThat(websocket.get("id")).isEqualTo(7);
        assertThat(websocket.get("message_id")).isEqualTo(12);
        assertThat(websocket.get("direction")).isEqualTo("CLIENT_TO_SERVER");
        Map<?, ?> proxy = nestedMap(burp, "proxy");
        assertThat(proxy.get("listener_port")).isEqualTo(8080);
        assertThat(payloadDoc.get("b64")).isNotNull();
        assertThat(payloadDoc.get("text")).isEqualTo("HELLO");
        assertThat(websocket.containsKey("original")).isFalse();
        assertThat(websocket.containsKey("edited_payload")).isFalse();
        assertThat(websocket.containsKey("original_payload")).isFalse();
        assertThat(doc).doesNotContainKey("ws_upgrade_request");
        assertThat(doc.get("request")).isInstanceOf(Map.class);
    }

    @Test
    void buildDocument_survivesMalformedUpgradeRequest_andReconstructsUrl() {
        resetRuntimeConfig();
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));

        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(true);

        ProxyWebSocketMessage ws = mock(ProxyWebSocketMessage.class);
        HttpRequest upgrade = mock(HttpRequest.class);
        HttpService svc = mock(HttpService.class);

        when(svc.host()).thenReturn("example.com");
        when(svc.port()).thenReturn(443);
        when(svc.secure()).thenReturn(true);

        when(upgrade.httpService()).thenReturn(svc);
        // Direct URL accessor throws, mimicking partially-bound Burp Repeater/WebSocket upgrades.
        when(upgrade.url()).thenThrow(new IllegalStateException("URL is invalid."));
        when(upgrade.path()).thenReturn("/ws");
        when(upgrade.method()).thenReturn("GET");
        when(upgrade.pathWithoutQuery()).thenReturn("/ws");
        when(upgrade.query()).thenReturn("");
        when(upgrade.fileExtension()).thenReturn("");
        when(upgrade.httpVersion()).thenReturn("HTTP/1.1");
        when(upgrade.headers()).thenReturn(List.of());
        when(upgrade.parameters()).thenReturn(List.of());
        when(upgrade.body()).thenReturn(null);
        when(upgrade.markers()).thenReturn(List.of());
        when(upgrade.contentType()).thenReturn(null);

        ByteArray payload = mock(ByteArray.class);
        when(payload.getBytes()).thenReturn("hi".getBytes(StandardCharsets.UTF_8));
        ByteArray editedPayload = mock(ByteArray.class);
        when(editedPayload.getBytes()).thenReturn("hi".getBytes(StandardCharsets.UTF_8));

        when(ws.upgradeRequest()).thenReturn(upgrade);
        when(ws.id()).thenReturn(1);
        when(ws.webSocketId()).thenReturn(1);
        when(ws.listenerPort()).thenReturn(443);
        when(ws.payload()).thenReturn(payload);
        when(ws.editedPayload()).thenReturn(editedPayload);
        when(ws.direction()).thenReturn(Direction.CLIENT_TO_SERVER);
        when(ws.time()).thenReturn(ZonedDateTime.now());
        when(ws.annotations()).thenReturn(null);

        Map<String, Object> doc = ProxyWebSocketIndexReporter.buildDocument(api, ws);

        assertThat(doc).isNotNull();
        Map<?, ?> request = nestedMap(doc, "request");
        assertThat(nestedMap(request, "url").get("raw")).isEqualTo("https://example.com/ws");
        assertThat(nestedMap(doc, "burp").get("reporting_tool")).isEqualTo("Proxy WebSocket");
        assertThat(doc).doesNotContainKey("tool_type");
        Map<?, ?> path = nestedMap(request, "path");
        assertThat(path.get("with_query")).isEqualTo("/ws");
        assertThat(request.get("method")).isEqualTo("GET");
    }

    @Test
    void trafficGates_splitProxyHistoryAndProxyLive() {
        resetRuntimeConfig();
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy_history"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        assertThat(ProxyWebSocketIndexReporter.trafficSelectionAllowsHistoricWebSockets()).isTrue();
        assertThat(ProxyWebSocketIndexReporter.trafficSelectionAllowsLiveProxyWebSocketPoll()).isFalse();

        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        assertThat(ProxyWebSocketIndexReporter.trafficSelectionAllowsHistoricWebSockets()).isFalse();
        assertThat(ProxyWebSocketIndexReporter.trafficSelectionAllowsLiveProxyWebSocketPoll()).isTrue();
    }

    @Test
    void refreshLivePollSchedule_stopsSchedulerWhenProxyDeselected() throws Exception {
        resetRuntimeConfig();
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));

        ProxyWebSocketIndexReporter.startLivePoll();
        assertThat(schedulerField().isStarted()).isTrue();

        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("repeater"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        ProxyWebSocketIndexReporter.refreshLivePollScheduleForCurrentState();

        assertThat(schedulerField().isStarted()).isFalse();
        assertThat(ProxyWebSocketIndexReporter.shouldRunLivePoll()).isFalse();
    }

    @Test
    void refreshLivePollSchedule_startsSchedulerWhenProxySelectedWhileExportRunning() throws Exception {
        resetRuntimeConfig();
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("repeater"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        assertThat(schedulerField().isStarted()).isFalse();

        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        ProxyWebSocketIndexReporter.refreshLivePollScheduleForCurrentState();

        assertEventuallySchedulerStarted();
    }

    @Test
    void refreshLivePollSchedule_seedsExistingHistoryWhenProxyReselected() throws Exception {
        resetRuntimeConfig();
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("repeater"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        ProxyWebSocketMessage existing = mock(ProxyWebSocketMessage.class);
        when(existing.webSocketId()).thenReturn(17);
        when(existing.id()).thenReturn(42);
        when(api.proxy().webSocketHistory()).thenReturn(List.of(existing));
        MontoyaApiProvider.set(api);

        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy_history", "proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        ProxyWebSocketIndexReporter.refreshLivePollScheduleForCurrentState();

        assertEventuallySchedulerStarted();
    }

    @Test
    void startLivePoll_doesNotStartWhileExportIsStarting() throws Exception {
        resetRuntimeConfig();
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.setExportStarting(true);
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));

        ProxyWebSocketIndexReporter.startLivePoll();

        assertThat(schedulerField().isStarted()).isFalse();
        assertThat(ProxyWebSocketIndexReporter.shouldRunLivePoll()).isFalse();
    }

    @Test
    void refreshLivePollSchedule_seedsHistoryOffCallerThreadBeforeStartingPoll() throws Exception {
        resetRuntimeConfig();
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        assertThat(schedulerField().isStarted()).isFalse();

        ProxyWebSocketIndexReporter.refreshLivePollScheduleForCurrentState();

        assertEventuallySchedulerStarted();
    }

    @Test
    void pushNewItemsOnly_scansSameSizeHistoryWhenTailChanges() throws Exception {
        resetRuntimeConfig();
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(true, tempDir.toString(), true, false,
                        false, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(true);
        ProxyWebSocketMessage existing = webSocketMessage(7, 1);
        ProxyWebSocketMessage rotated = webSocketMessage(7, 2);
        when(api.proxy().webSocketHistory()).thenReturn(List.of(existing)).thenReturn(List.of(rotated));
        MontoyaApiProvider.set(api);
        TrafficExportQueue.clearPendingWork();

        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            ProxyWebSocketIndexReporter.pushNewItemsOnly();
            assertThat(liveHistoryCursor()).isEqualTo(1);
            assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(1);

            ProxyWebSocketIndexReporter.pushNewItemsOnly();
            assertThat(liveHistoryCursor()).isEqualTo(1);
            assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(2);
        });
    }

    @Test
    void pushNewItemsOnly_retriesAfterRouteRejectionWhenProxyBecomesSelected() throws Exception {
        resetRuntimeConfig();
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("repeater"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(true);
        ProxyWebSocketMessage pending = webSocketMessage(5, 9);
        when(api.proxy().webSocketHistory()).thenReturn(List.of(pending));
        MontoyaApiProvider.set(api);
        TrafficExportQueue.clearPendingWork();

        ProxyWebSocketIndexReporter.pushNewItemsOnly();

        assertThat(liveHistoryCursor()).isZero();
        TrafficExportQueue.stopWorker();
        assertThat(TrafficExportQueue.getCurrentSize()).isZero();

        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            ProxyWebSocketIndexReporter.pushNewItemsOnly();
            assertThat(liveHistoryCursor()).isEqualTo(1);
            assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(1);
        });
    }

    @Test
    void pushNewItemsOnly_rescansFromStartWhenHistoryShrinks() throws Exception {
        resetRuntimeConfig();
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(true);
        MontoyaApiProvider.set(api);
        setLiveHistoryCursor(10);
        setLiveHistoryTailKey("1:10");
        List<ProxyWebSocketMessage> shrunk = List.of(webSocketMessage(2, 1), webSocketMessage(2, 2));
        when(api.proxy().webSocketHistory()).thenReturn(shrunk);
        TrafficExportQueue.clearPendingWork();

        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            ProxyWebSocketIndexReporter.pushNewItemsOnly();
            assertThat(liveHistoryCursor()).isEqualTo(2);
            assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(2);
        });
    }

    @Test
    void pushNewItemsOnly_withLargeSeededHistory_exportsOnlyTailAfterCursor() throws Exception {
        resetRuntimeConfig();
        ProxyWebSocketIndexReporter.stop();
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        java.util.ArrayList<ProxyWebSocketMessage> history = new java.util.ArrayList<>();
        for (int i = 1; i <= 100; i++) {
            history.add(webSocketMessage(1, i));
        }
        ProxyWebSocketMessage newest = webSocketMessage(1, 101);
        java.util.ArrayList<ProxyWebSocketMessage> extended = new java.util.ArrayList<>(history);
        extended.add(newest);

        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(true);
        when(api.proxy().webSocketHistory()).thenReturn(extended);
        MontoyaApiProvider.set(api);

        setLiveHistoryCursor(100);
        setLiveHistoryTailKey("1:100");
        assertThat(liveHistoryCursor()).isEqualTo(100);

        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            ProxyWebSocketIndexReporter.pushNewItemsOnly();
            assertThat(liveHistoryCursor()).isEqualTo(101);
            assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(1);
        });
    }

    @Test
    void startLivePoll_registersAfterHistoricSnapshotWhenBothProxySourcesSelected() throws Exception {
        resetRuntimeConfig();
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy_history", "proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        CountDownLatch historyReadStarted = new CountDownLatch(1);
        CountDownLatch allowHistoryReadToFinish = new CountDownLatch(1);
        when(api.proxy().webSocketHistory()).thenAnswer(invocation -> {
            historyReadStarted.countDown();
            assertThat(allowHistoryReadToFinish.await(2, TimeUnit.SECONDS)).isTrue();
            return List.of();
        });
        MontoyaApiProvider.set(api);

        ProxyWebSocketIndexReporter.pushHistoricSnapshotNow();
        assertThat(historyReadStarted.await(2, TimeUnit.SECONDS)).isTrue();
        assertThat(schedulerField().isStarted()).isFalse();

        ProxyWebSocketIndexReporter.startLivePoll();
        allowHistoryReadToFinish.countDown();

        assertEventuallySchedulerStarted();
    }

    private static LazyScheduler schedulerField() throws Exception {
        var field = ProxyWebSocketIndexReporter.class.getDeclaredField("SCHEDULER");
        field.setAccessible(true);
        return (LazyScheduler) field.get(null);
    }

    private static int liveHistoryCursor() throws Exception {
        var field = ProxyWebSocketIndexReporter.class.getDeclaredField("liveHistoryCursor");
        field.setAccessible(true);
        return field.getInt(null);
    }

    private static void setLiveHistoryCursor(int value) throws Exception {
        var field = ProxyWebSocketIndexReporter.class.getDeclaredField("liveHistoryCursor");
        field.setAccessible(true);
        field.setInt(null, value);
    }

    private static void setLiveHistoryTailKey(String value) throws Exception {
        var field = ProxyWebSocketIndexReporter.class.getDeclaredField("liveHistoryTailKey");
        field.setAccessible(true);
        field.set(null, value);
    }

    private static void assertEventuallySchedulerStarted() throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (System.nanoTime() < deadline) {
            if (schedulerField().isStarted()) {
                return;
            }
            java.util.concurrent.TimeUnit.MILLISECONDS.sleep(10);
        }
        assertThat(schedulerField().isStarted()).isTrue();
    }

    static ProxyWebSocketMessage webSocketMessage(int webSocketId, int messageId) {
        ProxyWebSocketMessage ws = mock(ProxyWebSocketMessage.class);
        HttpRequest upgrade = mock(HttpRequest.class);
        HttpService service = mock(HttpService.class);
        ByteArray payload = mock(ByteArray.class);
        when(service.host()).thenReturn("example.com");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);
        when(upgrade.httpService()).thenReturn(service);
        when(upgrade.url()).thenReturn("https://example.com/ws");
        when(upgrade.httpVersion()).thenReturn("HTTP/1.1");
        when(upgrade.path()).thenReturn("/ws");
        when(upgrade.method()).thenReturn("GET");
        when(upgrade.pathWithoutQuery()).thenReturn("/ws");
        when(upgrade.query()).thenReturn("");
        when(upgrade.fileExtension()).thenReturn("");
        when(upgrade.headers()).thenReturn(List.of());
        when(upgrade.parameters()).thenReturn(List.of());
        when(upgrade.body()).thenReturn(null);
        when(upgrade.markers()).thenReturn(List.of());
        when(upgrade.contentType()).thenReturn(null);
        when(payload.getBytes()).thenReturn(("message-" + messageId).getBytes(StandardCharsets.UTF_8));
        when(ws.upgradeRequest()).thenReturn(upgrade);
        when(ws.id()).thenReturn(messageId);
        when(ws.webSocketId()).thenReturn(webSocketId);
        when(ws.listenerPort()).thenReturn(443);
        when(ws.payload()).thenReturn(payload);
        when(ws.editedPayload()).thenReturn(null);
        when(ws.direction()).thenReturn(Direction.SERVER_TO_CLIENT);
        when(ws.time()).thenReturn(ZonedDateTime.now());
        when(ws.annotations()).thenReturn(null);
        return ws;
    }

    private static Map<?, ?> nestedMap(Map<?, ?> parent, String key) {
        assertThat(parent.get(key)).isInstanceOf(Map.class);
        return (Map<?, ?>) parent.get(key);
    }
}
