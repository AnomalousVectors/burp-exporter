package ai.anomalousvectors.tools.burp.sinks;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.websocket.BinaryMessageReceivedAction;
import burp.api.montoya.proxy.websocket.BinaryMessageToBeSentAction;
import burp.api.montoya.proxy.websocket.InterceptedBinaryMessage;
import burp.api.montoya.proxy.websocket.InterceptedTextMessage;
import burp.api.montoya.proxy.websocket.ProxyMessageHandler;
import burp.api.montoya.proxy.websocket.ProxyWebSocket;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreation;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreationHandler;
import burp.api.montoya.proxy.websocket.TextMessageReceivedAction;
import burp.api.montoya.proxy.websocket.TextMessageToBeSentAction;
import burp.api.montoya.websocket.Direction;

/** Captures final live Proxy WebSocket frames from Proxy-specific Montoya callbacks. */
public final class ProxyWebSocketLiveHandler implements ProxyWebSocketCreationHandler {

    static final String RECEIVED_TO_SENT = "RECEIVED_TO_SENT";
    private static final int MAX_PENDING_FRAMES_PER_CONNECTION = 1_024;
    private static final long MAX_PENDING_BYTES_PER_CONNECTION = 8L * 1_024L * 1_024L;
    private static final ProxyWebSocketLiveHandler INSTANCE = new ProxyWebSocketLiveHandler();
    private static final Set<LiveConnectionHandler> ACTIVE_HANDLERS = ConcurrentHashMap.newKeySet();

    private ProxyWebSocketLiveHandler() {}

    /**
     * Returns the singleton creation handler registered with the Proxy API.
     *
     * @return shared handler
     */
    public static ProxyWebSocketCreationHandler instance() {
        return INSTANCE;
    }

    /** Clears received-stage payloads without detaching handlers from open WebSockets. */
    public static void clearRunState() {
        for (LiveConnectionHandler handler : ACTIVE_HANDLERS) {
            handler.clearPending();
        }
    }

    /** {@inheritDoc} */
    @Override
    public void handleWebSocketCreation(ProxyWebSocketCreation creation) {
        if (creation == null) {
            return;
        }
        ProxyWebSocket webSocket = creation.proxyWebSocket();
        if (webSocket == null) {
            return;
        }
        HttpRequest upgrade = durableRequest(creation.upgradeRequest());
        LiveConnectionHandler handler = new LiveConnectionHandler(upgrade);
        ACTIVE_HANDLERS.add(handler);
        webSocket.registerProxyMessageHandler(handler);
    }

    private static HttpRequest durableRequest(HttpRequest request) {
        if (request == null) {
            return null;
        }
        try {
            return request.copyToTempFile();
        } catch (RuntimeException ignored) {
            return request;
        }
    }

    private static boolean captureEnabled() {
        return RuntimeConfig.isExportReady()
                && RuntimeConfig.trafficExportGate().includesToolType("proxy");
    }

    private static final class LiveConnectionHandler implements ProxyMessageHandler {

        private final HttpRequest upgradeRequest;
        private final Map<StageKey, Deque<byte[]>> receivedByStage = new java.util.EnumMap<>(StageKey.class);
        private int pendingFrames;
        private long pendingBytes;

        private LiveConnectionHandler(HttpRequest upgradeRequest) {
            this.upgradeRequest = upgradeRequest;
            for (StageKey key : StageKey.values()) {
                receivedByStage.put(key, new ArrayDeque<>());
            }
        }

        /** {@inheritDoc} */
        @Override
        public TextMessageReceivedAction handleTextMessageReceived(InterceptedTextMessage message) {
            if (message != null) {
                safely(() -> remember(
                        StageKey.of(message.direction(), true), textBytes(message.payload())));
                return TextMessageReceivedAction.continueWith(message);
            }
            return TextMessageReceivedAction.continueWith("");
        }

        /** {@inheritDoc} */
        @Override
        public TextMessageToBeSentAction handleTextMessageToBeSent(InterceptedTextMessage message) {
            if (message != null) {
                safely(() -> exportFinal(
                        StageKey.of(message.direction(), true),
                        textBytes(message.payload()),
                        message.direction(),
                        "TEXT",
                        message.annotations()));
                return TextMessageToBeSentAction.continueWith(message);
            }
            return TextMessageToBeSentAction.continueWith("");
        }

        /** {@inheritDoc} */
        @Override
        public BinaryMessageReceivedAction handleBinaryMessageReceived(InterceptedBinaryMessage message) {
            if (message != null) {
                safely(() -> remember(
                        StageKey.of(message.direction(), false), binaryBytes(message.payload())));
                return BinaryMessageReceivedAction.continueWith(message);
            }
            return BinaryMessageReceivedAction.continueWith(ByteArray.byteArray(new byte[0]));
        }

        /** {@inheritDoc} */
        @Override
        public BinaryMessageToBeSentAction handleBinaryMessageToBeSent(InterceptedBinaryMessage message) {
            if (message != null) {
                safely(() -> exportFinal(
                        StageKey.of(message.direction(), false),
                        binaryBytes(message.payload()),
                        message.direction(),
                        "BINARY",
                        message.annotations()));
                return BinaryMessageToBeSentAction.continueWith(message);
            }
            return BinaryMessageToBeSentAction.continueWith(ByteArray.byteArray(new byte[0]));
        }

        /** {@inheritDoc} */
        @Override
        public void onClose() {
            clearPending();
            ACTIVE_HANDLERS.remove(this);
        }

        private synchronized void remember(StageKey key, byte[] bytes) {
            if (!captureEnabled() || key == null) {
                return;
            }
            byte[] snapshot = bytes == null ? new byte[0] : bytes.clone();
            while (pendingFrames >= MAX_PENDING_FRAMES_PER_CONNECTION
                    || pendingBytes + snapshot.length > MAX_PENDING_BYTES_PER_CONNECTION) {
                if (!discardOldest()) {
                    return;
                }
            }
            receivedByStage.get(key).addLast(snapshot);
            pendingFrames++;
            pendingBytes += snapshot.length;
        }

        private void exportFinal(
                StageKey key,
                byte[] finalBytes,
                Direction direction,
                String messageType,
                Annotations annotations) {
            byte[] received = take(key);
            if (!captureEnabled()) {
                return;
            }
            List<String> changeStages = received == null
                    ? null
                    : (Arrays.equals(received, finalBytes) ? List.of() : List.of(RECEIVED_TO_SENT));
            Map<String, Object> document = WebSocketTrafficDocumentBuilder.build(
                    new WebSocketTrafficDocumentBuilder.Input(
                            MontoyaApiProvider.get(),
                            upgradeRequest,
                            "ProxyWebSocketLive",
                            "Proxy",
                            null,
                            null,
                            null,
                            null,
                            direction == null ? null : direction.name(),
                            finalBytes,
                            messageType,
                            null,
                            changeStages,
                            Instant.now().toString(),
                            annotationNotes(annotations),
                            annotationHighlight(annotations)));
            TrafficExportQueue.offerAccepted(document, TrafficRouteBucket.proxyWebSocketLive());
        }

        private synchronized byte[] take(StageKey key) {
            if (key == null) {
                return null;
            }
            byte[] value = receivedByStage.get(key).pollFirst();
            if (value != null) {
                pendingFrames--;
                pendingBytes -= value.length;
            }
            return value;
        }

        private synchronized boolean discardOldest() {
            for (StageKey key : StageKey.values()) {
                byte[] value = receivedByStage.get(key).pollFirst();
                if (value != null) {
                    pendingFrames--;
                    pendingBytes -= value.length;
                    return true;
                }
            }
            return false;
        }

        private synchronized void clearPending() {
            for (Deque<byte[]> pending : receivedByStage.values()) {
                pending.clear();
            }
            pendingFrames = 0;
            pendingBytes = 0L;
        }
    }

    private enum StageKey {
        CLIENT_TEXT,
        SERVER_TEXT,
        CLIENT_BINARY,
        SERVER_BINARY;

        private static StageKey of(Direction direction, boolean text) {
            if (direction == null) {
                return null;
            }
            if (direction == Direction.CLIENT_TO_SERVER) {
                return text ? CLIENT_TEXT : CLIENT_BINARY;
            }
            return text ? SERVER_TEXT : SERVER_BINARY;
        }
    }

    private static byte[] textBytes(String payload) {
        return payload == null ? new byte[0] : payload.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] binaryBytes(ByteArray payload) {
        return payload == null ? new byte[0] : payload.getBytes();
    }

    private static void safely(Runnable action) {
        try {
            action.run();
        } catch (RuntimeException e) {
            Logger.logError("[ProxyWebSocketLive] Frame observation failed safely: error="
                    + e.getClass().getSimpleName()
                    + "; Burp traffic continued.");
        }
    }

    private static String annotationNotes(Annotations annotations) {
        return annotations != null && annotations.hasNotes() ? annotations.notes() : null;
    }

    private static String annotationHighlight(Annotations annotations) {
        if (annotations == null || !annotations.hasHighlightColor() || annotations.highlightColor() == null) {
            return null;
        }
        return annotations.highlightColor().name();
    }
}
