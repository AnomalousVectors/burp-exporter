package ai.anomalousvectors.tools.burp.sinks;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.websocket.BinaryMessage;
import burp.api.montoya.websocket.BinaryMessageAction;
import burp.api.montoya.websocket.Direction;
import burp.api.montoya.websocket.MessageHandler;
import burp.api.montoya.websocket.TextMessage;
import burp.api.montoya.websocket.TextMessageAction;
import burp.api.montoya.websocket.WebSocket;
import burp.api.montoya.websocket.WebSocketCreated;
import burp.api.montoya.websocket.WebSocketCreatedHandler;

/**
 * Live WebSocket export for non-proxy Burp tools (Repeater, Intruder, Scanner, Extensions, etc.).
 *
 * <p>Live Proxy WebSocket frames are exported by {@link ProxyWebSocketLiveHandler}; historic
 * Proxy WebSocket frames are exported by {@link ProxyWebSocketIndexReporter}. This handler uses
 * {@code api.websockets()} and sets
 * {@code websocket.id} / {@code websocket.message_id} to null because Montoya live message types
 * do not expose Burp history identifiers.</p>
 */
public final class ToolWebSocketLiveHandler implements WebSocketCreatedHandler {

    private ToolWebSocketLiveHandler() {}

    /** Returns the singleton handler registered on {@code api.websockets()}. */
    public static WebSocketCreatedHandler instance() {
        return Holder.INSTANCE;
    }

    @Override
    public void handleWebSocketCreated(WebSocketCreated creation) {
        if (creation == null) {
            return;
        }
        ToolSource toolSource = creation.toolSource();
        ToolType toolType = toolSource == null ? null : toolSource.toolType();
        if (toolType == ToolType.PROXY) {
            return;
        }
        String toolTypeKey = RuntimeConfig.normalizedToolTypeKey(toolType);
        if (!RuntimeConfig.trafficExportGate().allowsToolType(toolTypeKey)) {
            return;
        }
        WebSocket webSocket = creation.webSocket();
        HttpRequest upgrade = creation.upgradeRequest();
        if (webSocket == null) {
            return;
        }
        webSocket.registerMessageHandler(new LiveMessageHandler(toolType, toolTypeKey, upgrade));
    }

    private static final class Holder {
        private static final ToolWebSocketLiveHandler INSTANCE = new ToolWebSocketLiveHandler();
    }

    private static final class LiveMessageHandler implements MessageHandler {

        private final ToolType toolType;
        private final String toolTypeKey;
        private final HttpRequest upgradeRequest;

        LiveMessageHandler(ToolType toolType, String toolTypeKey, HttpRequest upgradeRequest) {
            this.toolType = toolType;
            this.toolTypeKey = toolTypeKey;
            this.upgradeRequest = upgradeRequest;
        }

        @Override
        public TextMessageAction handleTextMessage(TextMessage message) {
            if (message != null) {
                String text = message.payload();
                byte[] bytes = text == null ? null : text.getBytes(StandardCharsets.UTF_8);
                exportFrame(bytes, message.direction(), "TEXT");
            }
            return message == null ? TextMessageAction.continueWith("") : TextMessageAction.continueWith(message);
        }

        @Override
        public BinaryMessageAction handleBinaryMessage(BinaryMessage message) {
            byte[] bytes = null;
            if (message != null && message.payload() != null) {
                bytes = message.payload().getBytes();
            }
            exportFrame(bytes, message == null ? null : message.direction(), "BINARY");
            return message == null
                    ? BinaryMessageAction.continueWith(ByteArray.byteArray(new byte[0]))
                    : BinaryMessageAction.continueWith(message);
        }

        private void exportFrame(byte[] payloadBytes, Direction direction, String messageType) {
            if (!RuntimeConfig.trafficExportGate().allowsToolType(toolTypeKey)) {
                return;
            }
            if (WebSocketTrafficDocumentBuilder.isFilteredByExportScope(
                    MontoyaApiProvider.get(), upgradeRequest, "ToolWebSocketLive")) {
                return;
            }
            Map<String, Object> doc = buildLiveDocument(
                    toolType, upgradeRequest, payloadBytes, direction, messageType);
            if (doc != null) {
                TrafficExportQueue.offer(doc);
            } else {
                String toolLabel = toolType == null ? toolTypeKey : toolType.toolName();
                Logger.logDebug("[ToolWebSocketLive] WebSocket frame document build returned null; tool="
                        + toolLabel);
            }
        }
    }

    /**
     * Builds a traffic-index WebSocket document for a live tool frame.
     *
     * @param toolType Burp tool that owns the socket
     * @param upgrade WebSocket upgrade request
     * @param payloadBytes frame payload bytes
     * @param direction frame direction
     * @return document map, or {@code null} when filtered or inputs are incomplete
     */
    static Map<String, Object> buildLiveDocument(
            ToolType toolType,
            HttpRequest upgrade,
            byte[] payloadBytes,
            Direction direction) {
        return buildLiveDocument(
                toolType,
                upgrade,
                payloadBytes,
                direction,
                WebSocketTrafficDocumentBuilder.inferPayloadType(payloadBytes));
    }

    static Map<String, Object> buildLiveDocument(
            ToolType toolType,
            HttpRequest upgrade,
            byte[] payloadBytes,
            Direction direction,
            String messageType) {
        MontoyaApi api = MontoyaApiProvider.get();
        HttpService service = upgrade == null ? null : upgrade.httpService();
        String wsTime = Instant.now().toString();
        String reporter = toolType == null ? null : toolType.toolName();
        return WebSocketTrafficDocumentBuilder.build(new WebSocketTrafficDocumentBuilder.Input(
                api,
                upgrade,
                "ToolWebSocketLive",
                reporter,
                null,
                service == null ? null : service.port(),
                null,
                null,
                direction == null ? null : direction.name(),
                payloadBytes,
                messageType,
                null,
                null,
                wsTime,
                null,
                null));
    }
}
