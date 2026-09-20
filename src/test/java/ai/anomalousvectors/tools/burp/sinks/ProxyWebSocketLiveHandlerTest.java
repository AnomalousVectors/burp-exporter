package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;

import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.testutils.Reflect;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.websocket.InterceptedTextMessage;
import burp.api.montoya.proxy.websocket.ProxyMessageHandler;
import burp.api.montoya.proxy.websocket.ProxyWebSocket;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreation;
import burp.api.montoya.proxy.websocket.TextMessageReceivedAction;
import burp.api.montoya.proxy.websocket.TextMessageToBeSentAction;
import burp.api.montoya.websocket.Direction;

class ProxyWebSocketLiveHandlerTest {

    @AfterEach
    void tearDown() {
        ProxyWebSocketLiveHandler.clearRunState();
        TrafficExportQueue.setDrainDisabledForTests(false);
        TrafficExportQueue.stopWorker();
        TrafficExportQueue.clearPendingWork();
        RuntimeConfig.setExportRunning(false);
        MontoyaApiProvider.set(null);
    }

    @Test
    void finalTextFrame_exportsOnceWithExactTypeAndObservableChangeStage() throws Exception {
        configureProxyExport();
        ProxyMessageHandler handler = registerHandler();
        InterceptedTextMessage received = textMessage("before", Direction.CLIENT_TO_SERVER);
        InterceptedTextMessage sent = textMessage("after", Direction.CLIENT_TO_SERVER);

        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            withTextActionFactories(() -> {
                handler.handleTextMessageReceived(received);
                assertThat(TrafficExportQueue.getCurrentSize()).isZero();

                handler.handleTextMessageToBeSent(sent);
                assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(1);
                Map<?, ?> websocket = nestedMap(queuedDocument(), "websocket");
                Map<?, ?> payload = nestedMap(websocket, "payload");
                assertThat(websocket.get("message_type")).isEqualTo("TEXT");
                assertThat(websocket.get("inferred_message_type")).isEqualTo("TEXT");
                assertThat(websocket.get("history_has_edited_payload")).isNull();
                assertThat(websocket.get("change_stages")).isEqualTo(List.of("RECEIVED_TO_SENT"));
                assertThat(payload.get("text")).isEqualTo("after");
            });
        });
    }

    @Test
    void clearRunState_discardsReceivedStageBeforeFinalCallback() throws Exception {
        configureProxyExport();
        ProxyMessageHandler handler = registerHandler();
        InterceptedTextMessage received = textMessage("before", Direction.SERVER_TO_CLIENT);
        InterceptedTextMessage sent = textMessage("after", Direction.SERVER_TO_CLIENT);

        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            withTextActionFactories(() -> {
                handler.handleTextMessageReceived(received);
                ProxyWebSocketLiveHandler.clearRunState();
                handler.handleTextMessageToBeSent(sent);

                Map<?, ?> websocket = nestedMap(queuedDocument(), "websocket");
                assertThat(websocket.get("change_stages")).isNull();
            });
        });
    }

    @Test
    void proxyDeselection_preventsFinalFrameExport() {
        configureProxyExport();
        ProxyMessageHandler handler = registerHandler();
        InterceptedTextMessage received = textMessage("before", Direction.CLIENT_TO_SERVER);
        withTextActionFactories(() -> {
            handler.handleTextMessageReceived(received);

            RuntimeConfig.updateState(new ConfigState.State(
                    List.of("traffic"),
                    "all",
                    List.of(),
                    new ConfigState.Sinks(
                            false,
                            null,
                            true,
                            "https://opensearch.url:9200",
                            null,
                            null,
                            false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    List.of("repeater"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null));
            handler.handleTextMessageToBeSent(textMessage("after", Direction.CLIENT_TO_SERVER));
        });

        assertThat(TrafficExportQueue.getCurrentSize()).isZero();
    }

    private static void configureProxyExport() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(
                        false,
                        null,
                        true,
                        "https://opensearch.url:9200",
                        null,
                        null,
                        false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        RuntimeConfig.setExportRunning(true);
        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(true);
        MontoyaApiProvider.set(api);
    }

    private static ProxyMessageHandler registerHandler() {
        ProxyWebSocketCreation creation = mock(ProxyWebSocketCreation.class);
        ProxyWebSocket webSocket = mock(ProxyWebSocket.class);
        HttpRequest upgrade = mock(HttpRequest.class);
        HttpRequest durableUpgrade = mock(HttpRequest.class);
        HttpService service = mock(HttpService.class);
        when(creation.proxyWebSocket()).thenReturn(webSocket);
        when(creation.upgradeRequest()).thenReturn(upgrade);
        when(upgrade.copyToTempFile()).thenReturn(durableUpgrade);
        stubUpgrade(durableUpgrade, service);

        ProxyWebSocketLiveHandler.instance().handleWebSocketCreation(creation);

        ArgumentCaptor<ProxyMessageHandler> captor = ArgumentCaptor.forClass(ProxyMessageHandler.class);
        verify(webSocket).registerProxyMessageHandler(captor.capture());
        return captor.getValue();
    }

    private static void stubUpgrade(HttpRequest upgrade, HttpService service) {
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
        when(upgrade.markers()).thenReturn(List.of());
    }

    private static InterceptedTextMessage textMessage(String payload, Direction direction) {
        InterceptedTextMessage message = mock(InterceptedTextMessage.class);
        Annotations annotations = mock(Annotations.class);
        when(message.payload()).thenReturn(payload);
        when(message.direction()).thenReturn(direction);
        when(message.annotations()).thenReturn(annotations);
        return message;
    }

    private static void withTextActionFactories(Runnable action) {
        try (MockedStatic<TextMessageReceivedAction> receivedActions =
                        mockStatic(TextMessageReceivedAction.class);
                MockedStatic<TextMessageToBeSentAction> sentActions =
                        mockStatic(TextMessageToBeSentAction.class)) {
            action.run();
        }
    }

    private static Map<String, Object> queuedDocument() {
        LinkedBlockingQueue<?> queue =
                Reflect.getStatic(TrafficExportQueue.class, "queue", LinkedBlockingQueue.class);
        Object head = queue.peek();
        if (head instanceof TrafficQueueEntry entry) {
            return entry.document();
        }
        if (!(head instanceof Map<?, ?> source)) {
            return Map.of();
        }
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : source.entrySet()) {
            if (entry.getKey() instanceof String key) {
                result.put(key, entry.getValue());
            }
        }
        return result;
    }

    private static Map<?, ?> nestedMap(Map<?, ?> parent, String key) {
        assertThat(parent.get(key)).isInstanceOf(Map.class);
        return (Map<?, ?>) parent.get(key);
    }
}
