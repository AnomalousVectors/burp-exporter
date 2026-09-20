package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;

import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.websocket.Direction;

class ProxyWebSocketIndexReporterTest {

    @AfterEach
    void tearDown() {
        ProxyWebSocketIndexReporter.stop();
        RuntimeConfig.setExportRunning(false);
        MontoyaApiProvider.set(null);
    }

    @Test
    void buildDocument_usesEffectiveHistoryPayloadWithoutFabricatingFrameType() {
        configureTrafficTools(List.of("proxy_history"));
        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(true);
        ProxyWebSocketMessage message = webSocketMessage("hello", "HELLO");

        Map<String, Object> document = ProxyWebSocketIndexReporter.buildDocument(api, message);

        Map<?, ?> burp = nestedMap(document, "burp");
        Map<?, ?> websocket = nestedMap(document, "websocket");
        Map<?, ?> payload = nestedMap(websocket, "payload");
        assertThat(burp.get("reporting_tool")).isEqualTo("Proxy WebSocket");
        assertThat(websocket.get("id")).isEqualTo(7);
        assertThat(websocket.get("message_id")).isEqualTo(12);
        assertThat(websocket.get("message_type")).isNull();
        assertThat(websocket.get("inferred_message_type")).isEqualTo("TEXT");
        assertThat(websocket.get("history_has_edited_payload")).isEqualTo(true);
        assertThat(websocket.get("change_stages")).isNull();
        assertThat(payload.get("text")).isEqualTo("HELLO");
        assertThat(websocket.containsKey("is_edited")).isFalse();
        assertThat(websocket.containsKey("original")).isFalse();
        assertThat(websocket.containsKey("edited_payload")).isFalse();
    }

    @Test
    void buildDocument_infersBinaryForHistoryBytesThatAreNotUtf8() {
        configureTrafficTools(List.of("proxy_history"));
        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(true);
        ProxyWebSocketMessage message = webSocketMessage(new byte[] {(byte) 0x80}, null);

        Map<String, Object> document = ProxyWebSocketIndexReporter.buildDocument(api, message);

        Map<?, ?> websocket = nestedMap(document, "websocket");
        assertThat(websocket.get("message_type")).isNull();
        assertThat(websocket.get("inferred_message_type")).isEqualTo("BINARY");
        assertThat(websocket.get("history_has_edited_payload")).isEqualTo(false);
    }

    @Test
    void historicSelection_requiresProxyHistorySource() {
        configureTrafficTools(List.of("proxy"));
        assertThat(ProxyWebSocketIndexReporter.trafficSelectionAllowsHistoricWebSockets()).isFalse();

        configureTrafficTools(List.of("proxy_history"));
        assertThat(ProxyWebSocketIndexReporter.trafficSelectionAllowsHistoricWebSockets()).isTrue();
    }

    private static void configureTrafficTools(List<String> tools) {
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
                tools,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
    }

    private static ProxyWebSocketMessage webSocketMessage(String payload, String edited) {
        return webSocketMessage(
                payload.getBytes(StandardCharsets.UTF_8),
                edited == null ? null : edited.getBytes(StandardCharsets.UTF_8),
                7,
                12);
    }

    private static ProxyWebSocketMessage webSocketMessage(byte[] payloadBytes, byte[] editedBytes) {
        return webSocketMessage(payloadBytes, editedBytes, 7, 12);
    }

    static ProxyWebSocketMessage webSocketMessage(int webSocketId, int messageId) {
        return webSocketMessage(
                ("message-" + messageId).getBytes(StandardCharsets.UTF_8),
                null,
                webSocketId,
                messageId);
    }

    private static ProxyWebSocketMessage webSocketMessage(
            byte[] payloadBytes,
            byte[] editedBytes,
            int webSocketId,
            int messageId) {
        ProxyWebSocketMessage message = mock(ProxyWebSocketMessage.class);
        HttpRequest upgrade = mock(HttpRequest.class);
        HttpService service = mock(HttpService.class);
        ByteArray payload = mock(ByteArray.class);
        ByteArray edited = editedBytes == null ? null : mock(ByteArray.class);
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
        when(upgrade.markers()).thenReturn(List.of());
        when(payload.getBytes()).thenReturn(payloadBytes);
        if (edited != null) {
            when(edited.getBytes()).thenReturn(editedBytes);
        }
        when(message.upgradeRequest()).thenReturn(upgrade);
        when(message.id()).thenReturn(messageId);
        when(message.webSocketId()).thenReturn(webSocketId);
        when(message.listenerPort()).thenReturn(8080);
        when(message.payload()).thenReturn(payload);
        when(message.editedPayload()).thenReturn(edited);
        when(message.direction()).thenReturn(Direction.CLIENT_TO_SERVER);
        when(message.time()).thenReturn(ZonedDateTime.now());
        return message;
    }

    private static Map<?, ?> nestedMap(Map<?, ?> parent, String key) {
        assertThat(parent.get(key)).isInstanceOf(Map.class);
        return (Map<?, ?>) parent.get(key);
    }
}
