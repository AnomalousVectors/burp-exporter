package ai.anomalousvectors.tools.burp.ui.text;

import java.util.Map;

final class ExportFieldTooltipsTraffic {

    private ExportFieldTooltipsTraffic() { }

    static final Map<String, String> DISPLAY_NAMES = Map.ofEntries(
            Map.entry("request.url.raw", "url.raw"),
            Map.entry("request.url.text", "url.text"),
            Map.entry("request.url.scheme", "url.scheme"),
            Map.entry("request.url.host", "url.host"),
            Map.entry("request.url.port", "url.port"),
            Map.entry("request.url.path", "url.path"),
            Map.entry("request.url.query", "url.query"),
            Map.entry("request.url.fragment", "url.fragment"),
            Map.entry("request.protocol.http_version", "protocol.http_version"),
            Map.entry("response.protocol.http_version", "protocol.http_version"),
            Map.entry("response.status.code", "status.code"),
            Map.entry("response.status.code_class", "status.code_class"),
            Map.entry("response.status.description", "status.description"),
            Map.entry("request.path.with_query", "path.with_query"),
            Map.entry("request.path.without_query", "path.without_query"),
            Map.entry("request.path.query", "path.query"),
            Map.entry("request.path.file_extension", "path.file_extension"),
            Map.entry("burp.repeater.tab_name", "repeater.tab_name"),
            Map.entry("burp.repeater.tab_group", "repeater.tab_group"),
            Map.entry("websocket.id", "websocket.id"),
            Map.entry("websocket.is_websocket", "websocket.is_websocket"),
            Map.entry("websocket.message_id", "websocket.message_id"),
            Map.entry("websocket.direction", "websocket.direction"),
            Map.entry("websocket.message_type", "websocket.message_type"),
            Map.entry("websocket.inferred_message_type", "websocket.inferred_message_type"),
            Map.entry("websocket.payload.b64", "websocket.payload.b64"),
            Map.entry("websocket.payload.text", "websocket.payload.text"),
            Map.entry("websocket.payload.length", "websocket.payload.length"),
            Map.entry("websocket.payload.truncated", "websocket.payload.truncated"),
            Map.entry("websocket.history_has_edited_payload", "websocket.history_has_edited_payload"),
            Map.entry("websocket.change_stages", "websocket.change_stages"),
            Map.entry("websocket.time", "websocket.time"));
    static String trafficDisplayName(String fieldKey) {
        if (fieldKey == null) {
            return null;
        }
        return DISPLAY_NAMES.getOrDefault(fieldKey, fieldKey);
    }

    static String trafficTooltip(String fieldKey) {
        String tooltip = trafficFieldTooltip(fieldKey);
        if (tooltip != null && (fieldKey.startsWith("request.") || fieldKey.startsWith("response."))) {
            String source = fieldKey.startsWith("request.")
                    ? "Live Proxy uses InterceptedResponse.initiatingRequest(); other live HTTP tools use HttpResponseReceived.initiatingRequest(), the request sent to the target. Request-only timeouts use the native Proxy request-to-be-sent view or HttpRequestToBeSent respectively. Explicit Proxy History and History-backed live stream snapshots use finalRequest(), including edits before sending. meta.capture.source distinguishes independent observations."
                    : "Live Proxy uses InterceptedResponse in handleResponseReceived; other live HTTP tools use HttpResponseReceived. Both capture the original server response before client-bound edits. Explicit Proxy History and History-backed live stream snapshots use the original server response. Stream snapshots may still be partial; meta.capture records their source, revision and observation deadline.";
            return tooltip.replace("</html>", "<br><br>" + Tooltips.escapeHtml(source) + "</html>");
        }
        return tooltip;
    }

    static String trafficFieldTooltip(String fieldKey) {
        return switch (fieldKey) {
            case "request.url.raw" -> Tooltips.textWithSource(
                    "Full request URL.",
                    "Traffic producers use RequestResponseDocBuilder.buildBestEffortUrl() and store the result in request.url.raw.");
            case "request.url.text" -> Tooltips.textWithSource(
                    "Full request URL indexed for text search, including long query strings.",
                    "HttpMessageDocSupport.urlObject() copies request.url.raw into request.url.text.");
            case "request.url.scheme" -> Tooltips.textWithSource(
                    "Request URL scheme: https or http.",
                    "HttpMessageDocSupport.urlObject() parses request.url.raw and falls back to HttpService.secure().");
            case "request.url.host" -> Tooltips.textWithSource(
                    "Target host parsed from the request URL.",
                    "HttpMessageDocSupport.urlObject() parses request.url.raw and falls back to HttpService.host().");
            case "request.url.port" -> Tooltips.textWithSource(
                    "Target port parsed from the request URL or HTTP service.",
                    "HttpMessageDocSupport.urlObject() uses an explicit URL port when present, otherwise HttpService.port().");
            case "request.protocol.http_version" -> Tooltips.textWithSource(
                    "HTTP version on the request line (for example HTTP/1.1).",
                    "Traffic producers use HttpRequest.httpVersion(); malformed requests fall back to the raw request line in RequestResponseDocBuilder.safeRequestHttpVersion().");
            case "request.headers.name" -> Tooltips.textWithSource(
                    "Normalized request header name.",
                    "HttpMessageDocSupport.headersToList() lower-cases HttpHeader.name() into request.headers.name.");
            case "request.headers.raw" -> Tooltips.textWithSource(
                    "Original request header name as Burp exposed it.",
                    "HttpMessageDocSupport.headersToList() copies HttpHeader.name() into request.headers.raw.");
            case "request.headers.value" -> Tooltips.textWithSource(
                    "Request header value.",
                    "HttpMessageDocSupport.headersToList() copies HttpHeader.value() into request.headers.value.");
            case "request.headers.ordinal" -> Tooltips.textWithSource(
                    "Zero-based request header order in the message.",
                    "HttpMessageDocSupport.headersToList() assigns ordinals while preserving duplicate header order.");
            case "response.protocol.http_version" -> Tooltips.textWithSource(
                    "HTTP version reported for the response.",
                    "RequestResponseDocBuilder.buildTrafficResponseDoc() uses only HttpResponse.httpVersion(); it does not copy request protocol data into response.protocol.http_version.");
            case "burp.reporting_tool" -> Tooltips.textWithSource(
                    "Burp tool display name.",
                    "Live HTTP uses ToolType.toolName() with request fallback; live stream recovery writes \"Proxy\" with meta.capture.source=proxy_history_stream. Explicit Proxy History writes \"Proxy History\"; Repeater Tabs and WebSocket producers retain their own labels.");
            case "burp.is_in_scope" -> Tooltips.textWithSource(
                    "Raw Burp Suite scope flag, not the extension's export-scope decision.",
                    "ProxyHistoryIndexReporter uses MontoyaApi.scope().isInScope(finalRequest URL); live HTTP uses the initiating sent request.isInScope(); ProxyWebSocketIndexReporter uses MontoyaApi.scope().isInScope(url) via safeBurpInScope().");
            case "burp.message_id" -> Tooltips.textWithSource(
                    "Source-specific Burp message identifier used for correlation.",
                    "Live Proxy uses native Proxy messageId(); other live HTTP tools use general HTTP messageId(). Neither is a UI History number, and equal numbers across these callback families do not identify the same exchange. Explicit Proxy History and History-backed live stream snapshots use their exact History row ID. meta.capture.source identifies the source. Live WebSocket handlers write null.");
            case "burp.timing.end" -> Tooltips.textWithSource(
                    "Absolute end timestamp for this traffic event.",
                    "History-backed observations and Repeater Tabs derive this from valid TimingData. Live HTTP callback observations use their source's response-received callback timestamp. For WebSocket messages, this is the frame/message time.");
            case "burp.timing.req_sent_to_res_end" -> Tooltips.textWithSource(
                    "Total observed exchange duration in milliseconds: request sent to end of response.",
                    "History-backed observations and Repeater Tabs use TimingData.timeBetweenRequestSentAndEndOfResponse(). Live HTTP callback observations subtract their source's callback timestamps; Proxy WebSocket writes 0 for individual frames.");
            case "burp.notes" -> Tooltips.textWithSource(
                    "User notes attached in Burp.",
                    "HTTP docs read their source annotations.notes() verbatim. Live HTTP prefers response annotations, falling back to request annotations only when the response exposes no annotations object. Historic WebSocket docs read ProxyWebSocketMessage.annotations(); live WebSocket handlers read final callback annotations. Notes are never modified or used for correlation.");
            case "burp.highlight" -> Tooltips.textWithSource(
                    "Burp highlight color.",
                    "HTTP docs read their source annotations.highlightColor().name(); live HTTP falls back to request annotations only when response annotations are unavailable. Historic WebSocket docs read ProxyWebSocketMessage.annotations(); live WebSocket handlers read final callback annotations. Highlights are read-only.");
            case "request.path.with_query" -> Tooltips.textWithSource(
                    "Request path and query portion.",
                    "RequestResponseDocBuilder.buildTrafficRequestDoc() uses HttpRequest.path().");
            case "request.path.without_query" -> Tooltips.textWithSource(
                    "Request path without the query string.",
                    "RequestResponseDocBuilder.buildTrafficRequestDoc() uses HttpRequest.pathWithoutQuery().");
            case "request.path.query" -> Tooltips.textWithSource(
                    "Raw query string from the request URL (without leading ?).",
                    "RequestResponseDocBuilder.buildTrafficRequestDoc() uses HttpRequest.query().");
            case "request.path.file_extension" -> Tooltips.textWithSource(
                    "File extension inferred from the request URL path.",
                    "RequestResponseDocBuilder.buildTrafficRequestDoc() uses HttpRequest.fileExtension().");
            case "request.method" -> Tooltips.textWithSource(
                    "HTTP method.",
                    "RequestResponseDocBuilder.buildTrafficRequestDoc() uses HttpRequest.method().");
            case "response.status.code" -> Tooltips.textWithSource(
                    "HTTP response status code; 0 means no response was available for this observation.",
                    "RequestResponseDocBuilder.buildTrafficResponseDoc() uses HttpResponse.statusCode(); orphan docs use sentinel response.status.code=0.");
            case "response.status.description" -> Tooltips.textWithSource(
                    "Obtain the HTTP reason phrase contained in the response for HTTP 1 messages.",
                    "RequestResponseDocBuilder.buildTrafficResponseDoc() uses HttpResponse.reasonPhrase(); request-only and empty-history docs use \"No response\".");
            case "response.status.code_class" -> Tooltips.textWithSource(
                    "HTTP status family derived from the status code (for example 2xx, 4xx).",
                    "RequestResponseDocBuilder.statusCodeClassName() maps HttpResponse.statusCode() to Burp StatusCodeClass.");
            case "response.headers.name" -> Tooltips.textWithSource(
                    "Normalized response header name.",
                    "HttpMessageDocSupport.headersToList() lower-cases HttpHeader.name() into response.headers.name.");
            case "response.headers.raw" -> Tooltips.textWithSource(
                    "Original response header name as Burp exposed it.",
                    "HttpMessageDocSupport.headersToList() copies HttpHeader.name() into response.headers.raw.");
            case "response.headers.value" -> Tooltips.textWithSource(
                    "Response header value.",
                    "HttpMessageDocSupport.headersToList() copies HttpHeader.value() into response.headers.value.");
            case "response.headers.ordinal" -> Tooltips.textWithSource(
                    "Zero-based response header order in the message.",
                    "HttpMessageDocSupport.headersToList() assigns ordinals while preserving duplicate header order.");
            case "burp.repeater.tab_name" -> Tooltips.textWithSource(
                    "Best-effort Repeater tab label for Repeater-origin traffic. "
                            + "Live Repeater traffic can intentionally leave this empty when Burp cannot safely disambiguate identical concurrent tabs.",
                    "RepeaterMetadataFields.put() writes burp.repeater.tab_name. RepeaterTabsIndexReporter infers "
                            + "the value from the selected Repeater tab during startup capture. TrafficHttpHandler "
                            + "uses short-lived correlation from Repeater editor rebinds for live Repeater traffic "
                            + "and writes null when correlation is ambiguous, unavailable, or Burp does not preserve "
                            + "a stable live tab identity.");
            case "burp.repeater.tab_group" -> Tooltips.textWithSource(
                    "Best-effort Repeater tab-group name when the selected tab belongs to a "
                            + "readable group. Live Repeater traffic can intentionally leave this "
                            + "empty for identical concurrent tabs or when no readable group label exists.",
                    "RepeaterMetadataFields.put() writes burp.repeater.tab_group. RepeaterTabsIndexReporter infers "
                            + "the value from the selected Repeater tab-header component during startup capture. "
                            + "TrafficHttpHandler uses short-lived correlation from Repeater editor rebinds for live "
                            + "Repeater traffic. Ungrouped tabs, non-Repeater traffic, ambiguous live matches, or UI "
                            + "layouts that do not expose a readable group label write null.");
            case "websocket.id" -> Tooltips.textWithSource(
                    "WebSocket conversation identifier from Burp Proxy WebSocket history.",
                    "ProxyWebSocketIndexReporter.buildDocument() uses ProxyWebSocketMessage.webSocketId(); live WebSocket handlers write null because Montoya live callback types do not expose Burp History ids.");
            case "websocket.is_websocket" -> Tooltips.textWithSource(
                    "Whether this traffic document represents a WebSocket message.",
                    "ProxyWebSocketIndexReporter, ProxyWebSocketLiveHandler, and ToolWebSocketLiveHandler write true; HTTP traffic producers write false.");
            case "websocket.message_id" -> Tooltips.textWithSource(
                    "WebSocket message identifier within the WebSocket conversation. This is distinct from websocket.id, which identifies the connection/conversation.",
                    "ProxyWebSocketIndexReporter.buildDocument() uses ProxyWebSocketMessage.id(); live WebSocket handlers write null.");
            case "websocket.direction" -> Tooltips.textWithSource(
                    "WebSocket message direction.",
                    "Historic and live WebSocket handlers use the Montoya direction name.");
            case "websocket.message_type" -> Tooltips.textWithSource(
                    "Exact WebSocket frame type when the live callback exposes it.",
                    "Live WebSocket callbacks write TEXT or BINARY. Proxy WebSocket History writes null because Montoya does not expose the original opcode there.");
            case "websocket.inferred_message_type" -> Tooltips.textWithSource(
                    "Best-effort payload classification independent of the WebSocket opcode.",
                    "WebSocketTrafficDocumentBuilder.inferPayloadType() returns EMPTY for no bytes, TEXT for strict UTF-8 decodes, otherwise BINARY.");
            case "websocket.payload.b64" -> Tooltips.textWithSource(
                    "Selected effective WebSocket payload bytes stored as Base64.",
                    "WebSocketTrafficDocumentBuilder.buildPayloadDoc() encodes the selected final payload bytes. Proxy WebSocket History prefers editedPayload(); live handlers pass their final callback payload.");
            case "websocket.payload.text" -> Tooltips.textWithSource(
                    "UTF-8 text view of the effective WebSocket payload when valid.",
                    "WebSocketTrafficDocumentBuilder.decodeUtf8OrNull() decodes the same bytes written to websocket.payload.b64.");
            case "websocket.payload.length" -> Tooltips.textWithSource(
                    "Effective WebSocket payload length in bytes.",
                    "WebSocketTrafficDocumentBuilder.buildPayloadDoc() records the selected final payload byte length.");
            case "websocket.payload.truncated" -> Tooltips.textWithSource(
                    "True when search/database export prefix-truncated this WebSocket payload to fit the live bulk byte budget. "
                            + "payload.length remains the original size; file export is not truncated by this path.",
                    "SearchBodyPrefixFitter.fitToLiveBudget() sets payload.truncated when shortening b64/text under BulkByteBudget pressure.");
            case "websocket.history_has_edited_payload" -> Tooltips.textWithSource(
                    "Whether Burp WebSocket History exposes a separate edited payload.",
                    "ProxyWebSocketIndexReporter uses ProxyWebSocketMessage.editedPayload() != null. Live callbacks write null because this History-only signal is unavailable.");
            case "websocket.change_stages" -> Tooltips.textWithSource(
                    "Observable live WebSocket stages at which payload bytes changed.",
                    "ProxyWebSocketLiveHandler compares received and final to-be-sent callback payloads once and writes RECEIVED_TO_SENT when they differ. An empty array means the exposed stages matched; null means the comparison was unavailable.");
            case "websocket.time" -> Tooltips.textWithSource(
                    "WebSocket message timestamp.",
                    "ProxyWebSocketIndexReporter uses ProxyWebSocketMessage.time(); live WebSocket handlers use an exporter timestamp at final callback time.");
            case "burp.proxy.history_id" -> Tooltips.textWithSource(
                    "Proxy History row identifier.",
                    "Explicit Proxy History and History-backed live stream snapshots use ProxyHttpRequestResponse.id(), the UI row id. Live HTTP callback observations write null: no History join, Notes marker or guessed ID.");
            case "burp.proxy.history_is_edited" -> Tooltips.textWithSource(
                    "Burp's row-level edited signal for a Proxy History item.",
                    "BurpProxyFields copies ProxyHttpRequestResponse.edited() for explicit Proxy History export and History-backed live stream recovery without inferring which side or stage changed. Live HTTP callback observations write null.");
            case "burp.proxy.request_change_stages" -> Tooltips.textWithSource(
                    "Observable live Proxy request stages at which complete message bytes changed.",
                    "HTTP producers write null because their selected API pair does not expose a safe comparison of native Proxy modification stages. Null does not mean unchanged.");
            case "burp.proxy.response_change_stages" -> Tooltips.textWithSource(
                    "Observable live Proxy response stages at which complete message bytes changed.",
                    "HTTP producers write null because their selected API pair does not expose a safe comparison of native Proxy modification stages. The exported payload remains the original server response, not a client-bound edited variant.");
            case "burp.proxy.listener_port" -> Tooltips.textWithSource(
                    "Proxy listener port used for the message.",
                    "Live Proxy reads the numeric port from its native request callback's listenerInterface(). Explicit Proxy History and History-backed live stream snapshots copy listenerPort() from their exact row. Other live HTTP tools and live WebSocket callbacks remain unknown; no port is guessed or joined by request contents. Historic WebSockets use ProxyWebSocketMessage.listenerPort().");
            case "burp.timing.req_sent" -> Tooltips.textWithSource(
                    "Request-sent timestamp.",
                    "Explicit Proxy History and History-backed live streams use TimingData.timeRequestSent() when valid. Live HTTP observations use their source's request-to-be-sent callback timestamp, not exact socket-write timing. Historic WebSocket frames use ProxyWebSocketMessage.time(); live WebSocket frames use the final callback time.");
            case "burp.timing.req_sent_to_res_start" -> Tooltips.textWithSource(
                    "Time to first response byte in milliseconds: request sent to start of response.",
                    "Explicit Proxy History, History-backed live streams, and Repeater Tabs use TimingData.timeBetweenRequestSentAndStartOfResponse(); live HTTP callback observations and WebSocket docs write null.");
            default -> ExportFieldTooltipsRequestResponse.requestResponseNestedTooltip(fieldKey);
        };
    }
}
