package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;

import ai.anomalousvectors.tools.burp.testutils.Reflect;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.websocket.Direction;
import burp.api.montoya.websocket.MessageHandler;
import burp.api.montoya.websocket.WebSocket;
import burp.api.montoya.websocket.WebSocketCreated;

class ToolWebSocketLiveHandlerTest {

    @BeforeEach
    @AfterEach
    public void resetRuntimeConfig() {
        TrafficExportQueue.setDrainDisabledForTests(false);
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
        RuntimeConfig.setExportStarting(false);
        MontoyaApiProvider.set(null);
        FileExportService.resetForTests();
        TrafficExportQueue.stopWorker();
        TrafficExportQueue.clearPendingWork();
    }

    @Test
    void buildLiveDocument_usesNullBurpWebSocketIds() {
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
        MontoyaApiProvider.set(api);
        when(api.scope().isInScope(anyString())).thenReturn(true);

        HttpRequest upgrade = mock(HttpRequest.class);
        HttpService service = mock(HttpService.class);
        when(upgrade.httpService()).thenReturn(service);
        when(service.host()).thenReturn("example.com");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);
        when(upgrade.url()).thenReturn("https://example.com/ws");
        when(upgrade.method()).thenReturn("GET");
        when(upgrade.path()).thenReturn("/ws");

        Map<String, Object> doc = ToolWebSocketLiveHandler.buildLiveDocument(
                ToolType.REPEATER,
                upgrade,
                "hello".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                Direction.CLIENT_TO_SERVER);

        assertThat(doc).isNotNull();
        Map<?, ?> websocket = (Map<?, ?>) doc.get("websocket");
        assertThat(websocket.get("is_websocket")).isEqualTo(true);
        assertThat(websocket.get("id")).isNull();
        assertThat(websocket.get("message_id")).isNull();
        assertThat(((Map<?, ?>) doc.get("burp")).get("reporting_tool")).isEqualTo("Repeater");
    }

    @Test
    void registeredHandlerHonorsRuntimeToolDeselectionForExistingSockets() throws Exception {
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

        WebSocketCreated creation = mock(WebSocketCreated.class);
        WebSocket webSocket = mock(WebSocket.class);
        ToolSource toolSource = mock(ToolSource.class);
        when(creation.toolSource()).thenReturn(toolSource);
        when(toolSource.toolType()).thenReturn(ToolType.REPEATER);
        when(creation.webSocket()).thenReturn(webSocket);
        ToolWebSocketLiveHandler.instance().handleWebSocketCreated(creation);
        ArgumentCaptor<MessageHandler> handlerCaptor = ArgumentCaptor.forClass(MessageHandler.class);
        verify(webSocket).registerMessageHandler(handlerCaptor.capture());

        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("intruder"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        var exportFrame = handlerCaptor.getValue().getClass()
                .getDeclaredMethod("exportFrame", byte[].class, Direction.class);
        exportFrame.setAccessible(true);
        exportFrame.invoke(
                handlerCaptor.getValue(),
                "hello".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                Direction.CLIENT_TO_SERVER);

        assertThat(TrafficExportQueue.getCurrentSize()).isZero();
    }

    @Test
    void handleWebSocketCreated_skipsProxyToolSource() {
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

        WebSocketCreated creation = mock(WebSocketCreated.class);
        WebSocket webSocket = mock(WebSocket.class);
        ToolSource toolSource = mock(ToolSource.class);
        when(creation.toolSource()).thenReturn(toolSource);
        when(toolSource.toolType()).thenReturn(ToolType.PROXY);
        when(creation.webSocket()).thenReturn(webSocket);

        ToolWebSocketLiveHandler.instance().handleWebSocketCreated(creation);

        verify(webSocket, never()).registerMessageHandler(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void handleWebSocketCreated_doesNotRegisterWhenExportIsOff() {
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("repeater"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));

        WebSocketCreated creation = mock(WebSocketCreated.class);
        WebSocket webSocket = mock(WebSocket.class);
        ToolSource toolSource = mock(ToolSource.class);
        when(creation.toolSource()).thenReturn(toolSource);
        when(toolSource.toolType()).thenReturn(ToolType.REPEATER);
        when(creation.webSocket()).thenReturn(webSocket);

        ToolWebSocketLiveHandler.instance().handleWebSocketCreated(creation);

        verify(webSocket, never()).registerMessageHandler(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void buildLiveDocument_returnsNullWhenOutOfScope() {
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                ConfigKeys.SCOPE_BURP,
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("repeater"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));

        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(false);
        MontoyaApiProvider.set(api);

        HttpRequest upgrade = mock(HttpRequest.class);
        HttpService service = mock(HttpService.class);
        when(upgrade.httpService()).thenReturn(service);
        when(service.host()).thenReturn("example.com");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);
        when(upgrade.url()).thenReturn("https://example.com/ws");

        assertThat(ToolWebSocketLiveHandler.buildLiveDocument(
                ToolType.REPEATER,
                upgrade,
                "hello".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                Direction.CLIENT_TO_SERVER)).isNull();
    }

    @Test
    void textMessageHandler_enqueuesFilteredDocumentWhenExportRunning() throws Exception {
        TrafficExportQueueTestSupport.configureRunningTraffic(List.of("repeater"));

        MessageHandler handler = registerRepeaterHandler();

        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(true);
        MontoyaApiProvider.set(api);
        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            invokeExportFrame(handler, "text-frame".getBytes(java.nio.charset.StandardCharsets.UTF_8), Direction.CLIENT_TO_SERVER);
            assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(1);
            Map<?, ?> websocket = nestedMap(queuedDocument(), "websocket");
            assertThat(nestedMap(websocket, "payload").get("text")).isEqualTo("text-frame");
        });
    }

    @Test
    void binaryMessageHandler_enqueuesBase64PayloadWhenExportRunning() throws Exception {
        TrafficExportQueueTestSupport.configureRunningTraffic(List.of("intruder"));

        MessageHandler handler = registerIntruderHandler();

        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(true);
        MontoyaApiProvider.set(api);
        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            invokeExportFrame(handler, new byte[] {(byte) 0xDE, (byte) 0xAD}, Direction.SERVER_TO_CLIENT);
            assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(1);
            Map<?, ?> payloadDoc = nestedMap(nestedMap(queuedDocument(), "websocket"), "payload");
            assertThat(payloadDoc.get("b64")).isNotNull();
            assertThat(payloadDoc.containsKey("length")).isTrue();
        });
    }

    private static void invokeExportFrame(MessageHandler handler, byte[] payload, Direction direction) throws Exception {
        var exportFrame = handler.getClass().getDeclaredMethod("exportFrame", byte[].class, Direction.class);
        exportFrame.setAccessible(true);
        exportFrame.invoke(handler, payload, direction);
    }

    private static MessageHandler registerRepeaterHandler() throws Exception {
        return registerHandler(ToolType.REPEATER);
    }

    private static MessageHandler registerIntruderHandler() throws Exception {
        return registerHandler(ToolType.INTRUDER);
    }

    private static MessageHandler registerHandler(ToolType toolType) throws Exception {
        WebSocketCreated creation = mock(WebSocketCreated.class);
        WebSocket webSocket = mock(WebSocket.class);
        ToolSource toolSource = mock(ToolSource.class);
        HttpRequest upgrade = mock(HttpRequest.class);
        HttpService service = mock(HttpService.class);
        when(creation.toolSource()).thenReturn(toolSource);
        when(toolSource.toolType()).thenReturn(toolType);
        when(creation.webSocket()).thenReturn(webSocket);
        when(creation.upgradeRequest()).thenReturn(upgrade);
        when(upgrade.httpService()).thenReturn(service);
        when(service.host()).thenReturn("example.com");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);
        when(upgrade.url()).thenReturn("https://example.com/ws");
        when(upgrade.method()).thenReturn("GET");
        when(upgrade.path()).thenReturn("/ws");
        when(upgrade.pathWithoutQuery()).thenReturn("/ws");
        when(upgrade.query()).thenReturn("");
        when(upgrade.fileExtension()).thenReturn("");
        when(upgrade.httpVersion()).thenReturn("HTTP/1.1");
        when(upgrade.headers()).thenReturn(List.of());
        when(upgrade.parameters()).thenReturn(List.of());
        when(upgrade.body()).thenReturn(null);
        when(upgrade.markers()).thenReturn(List.of());
        when(upgrade.contentType()).thenReturn(null);

        String toolTypeKey = RuntimeConfig.normalizedToolTypeKey(toolType);
        assertThat(RuntimeConfig.trafficExportGate().allowsToolType(toolTypeKey))
                .as("traffic export gate for %s", toolType)
                .isTrue();
        ToolWebSocketLiveHandler.instance().handleWebSocketCreated(creation);
        ArgumentCaptor<MessageHandler> handlerCaptor = ArgumentCaptor.forClass(MessageHandler.class);
        verify(webSocket).registerMessageHandler(handlerCaptor.capture());
        return handlerCaptor.getValue();
    }

    private static Map<String, Object> queuedDocument() throws Exception {
        LinkedBlockingQueue<?> queue =
                Reflect.getStatic(TrafficExportQueue.class, "queue", LinkedBlockingQueue.class);
        Map<String, Object> doc = queuedDocument(queue.peek());
        assertThat(doc).as("traffic export queue document").isNotNull();
        return doc;
    }

    private static Map<String, Object> queuedDocument(Object head) {
        if (head instanceof TrafficQueueEntry entry) {
            return entry.document();
        }
        return asStringObjectMap(head);
    }

    private static Map<String, Object> asStringObjectMap(Object head) {
        if (!(head instanceof Map<?, ?> source)) {
            return null;
        }
        Map<String, Object> out = new java.util.LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : source.entrySet()) {
            if (entry.getKey() instanceof String key) {
                out.put(key, entry.getValue());
            }
        }
        return out;
    }

    private static Map<?, ?> nestedMap(Map<?, ?> parent, String key) {
        assertThat(parent.get(key)).isInstanceOf(Map.class);
        return (Map<?, ?>) parent.get(key);
    }
}
