package ai.anomalousvectors.tools.burp.sinks;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ai.anomalousvectors.tools.burp.utils.ScopeFilter;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Shared traffic-index document builder for WebSocket frame exports.
 *
 * <p>Proxy WebSocket history and live non-proxy WebSocket handlers differ in how they obtain ids
 * and timestamps, but the emitted {@code burp}, {@code request}, {@code websocket}, and
 * {@code meta} document shape is intentionally the same.</p>
 */
final class WebSocketTrafficDocumentBuilder {

    private static final String SCHEMA_VERSION = "1";

    private WebSocketTrafficDocumentBuilder() {}

    /** Placeholder {@code websocket} object for non-WebSocket HTTP traffic documents. */
    static Map<String, Object> notWebSocket() {
        Map<String, Object> websocket = new LinkedHashMap<>();
        websocket.put("is_websocket", false);
        return websocket;
    }

    record Input(
            MontoyaApi api,
            HttpRequest upgradeRequest,
            String logPrefix,
            String reporter,
            Object burpMessageId,
            Integer listenerPort,
            Object webSocketId,
            Object webSocketMessageId,
            String direction,
            byte[] payloadBytes,
            String messageType,
            Boolean historyHasEditedPayload,
            List<String> changeStages,
            String timestamp,
            String notes,
            String highlight) {
    }

    /**
     * Builds a traffic-index WebSocket frame document, or {@code null} when the upgrade is missing
     * or {@link #isFilteredByExportScope(MontoyaApi, HttpRequest, String)} rejects the URL.
     *
     * @param input frame and upgrade context; {@code null} yields {@code null}
     * @return nested document map, or {@code null} when filtered or input is {@code null}
     */
    static Map<String, Object> build(Input input) {
        if (input == null) {
            return null;
        }
        HttpRequest upgrade = input.upgradeRequest();
        HttpService service = upgrade == null ? null : upgrade.httpService();
        Map<String, Object> upgradeRequestDoc = upgrade == null
                ? null
                : RequestResponseDocBuilder.buildTrafficRequestDoc(upgrade);
        String url = upgrade == null
                ? null
                : RequestResponseDocBuilder.buildBestEffortUrl(
                        upgrade, service, upgradeRequestDoc, input.logPrefix());
        boolean burpInScope = safeBurpInScope(input.api(), url);
        if (isFilteredByExportScope(input.api(), upgrade, input.logPrefix())) {
            return null;
        }
        if (upgradeRequestDoc != null) {
            upgradeRequestDoc.put("url", HttpMessageDocSupport.urlObject(url, service));
            upgradeRequestDoc.put("protocol", TrafficProtocolFields.requestProtocol(
                    RequestResponseDocBuilder.safeRequestHttpVersion(upgrade)));
        }

        String wsTime = input.timestamp() == null ? java.time.Instant.now().toString() : input.timestamp();
        Map<String, Object> doc = new LinkedHashMap<>();
        Map<String, Object> burp = new LinkedHashMap<>();
        burp.put("reporting_tool", input.reporter());
        burp.put("is_in_scope", burpInScope);
        burp.put("message_id", input.burpMessageId());
        burp.put("notes", input.notes());
        burp.put("highlight", input.highlight());
        burp.put("timing", timingDoc(wsTime));
        burp.put("proxy", BurpProxyFields.withoutProxyHistoryEditMetadata(input.listenerPort()));
        doc.put("burp", burp);

        doc.put("request", upgradeRequestDoc);
        doc.put("response", null);

        Map<String, Object> websocket = new LinkedHashMap<>();
        websocket.put("is_websocket", true);
        websocket.put("id", input.webSocketId());
        websocket.put("message_id", input.webSocketMessageId());
        websocket.put("direction", input.direction());
        websocket.put("message_type", input.messageType());
        websocket.put("inferred_message_type", inferPayloadType(input.payloadBytes()));
        websocket.put("history_has_edited_payload", input.historyHasEditedPayload());
        websocket.put("change_stages", input.changeStages());
        websocket.put("time", wsTime);
        websocket.put("payload", buildPayloadDoc(input.payloadBytes()));
        doc.put("websocket", websocket);

        doc.put("meta", ExportMetaFields.meta(SCHEMA_VERSION));
        return doc;
    }

    /**
     * Returns {@code true} when {@link #build(Input)} would return {@code null} because the upgrade
     * is missing or {@link ScopeFilter} rejects the URL for the active scope configuration.
     *
     * <p>Callers treat this as an expected filter (silent skip), not a document build failure.</p>
     *
     * @param api Montoya API for Burp scope checks; may be {@code null}
     * @param upgrade WebSocket upgrade request
     * @param logPrefix reporter log prefix for URL fallback diagnostics
     * @return {@code true} when export should skip this frame
     */
    static boolean isFilteredByExportScope(MontoyaApi api, HttpRequest upgrade, String logPrefix) {
        if (upgrade == null) {
            return true;
        }
        Map<String, Object> upgradeRequestDoc = RequestResponseDocBuilder.buildTrafficRequestDoc(upgrade);
        HttpService service = upgrade.httpService();
        String url = RequestResponseDocBuilder.buildBestEffortUrl(
                upgrade, service, upgradeRequestDoc, logPrefix);
        boolean burpInScope = safeBurpInScope(api, url);
        return !ScopeFilter.shouldExport(RuntimeConfig.getState(), url, burpInScope);
    }

    static boolean safeBurpInScope(MontoyaApi api, String url) {
        if (url == null) {
            return false;
        }
        try {
            if (api == null) {
                return false;
            }
            var scope = api.scope();
            return scope != null && scope.isInScope(url);
        } catch (Throwable ignored) {
            return false;
        }
    }

    static Map<String, Object> buildPayloadDoc(byte[] bytes) {
        Map<String, Object> payloadDoc = new LinkedHashMap<>();
        payloadDoc.put("b64", bytes == null ? null : Base64.getEncoder().encodeToString(bytes));
        payloadDoc.put("text", decodeUtf8OrNull(bytes));
        payloadDoc.put("length", bytes == null ? 0 : bytes.length);
        return payloadDoc;
    }

    static String inferPayloadType(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "EMPTY";
        }
        return decodeUtf8OrNull(bytes) != null ? "TEXT" : "BINARY";
    }

    static String decodeUtf8OrNull(byte[] body) {
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            return decoder.decode(ByteBuffer.wrap(body)).toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }

    private static Map<String, Object> timingDoc(String wsTime) {
        Map<String, Object> timing = new LinkedHashMap<>();
        timing.put("end", wsTime);
        timing.put("req_sent_to_res_end", 0);
        timing.put("req_sent", wsTime);
        timing.put("req_sent_to_res_start", null);
        return timing;
    }
}
