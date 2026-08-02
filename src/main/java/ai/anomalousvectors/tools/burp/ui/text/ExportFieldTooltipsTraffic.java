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
            Map.entry("websocket.payload.b64", "websocket.payload.b64"),
            Map.entry("websocket.payload.text", "websocket.payload.text"),
            Map.entry("websocket.payload.length", "websocket.payload.length"),
            Map.entry("websocket.payload.truncated", "websocket.payload.truncated"),
            Map.entry("websocket.is_edited", "websocket.is_edited"),
            Map.entry("websocket.time", "websocket.time"));
    static String trafficDisplayName(String fieldKey) {
        if (fieldKey == null) {
            return null;
        }
        return DISPLAY_NAMES.getOrDefault(fieldKey, fieldKey);
    }

    static String trafficTooltip(String fieldKey) {
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
                    "TrafficHttpHandler uses ToolType.toolName() from response.toolSource() with request fallback; ProxyHistoryIndexReporter writes \"Proxy History\"; RepeaterTabsIndexReporter writes \"Repeater Tabs\"; ProxyWebSocketIndexReporter writes \"Proxy WebSocket\"; ToolWebSocketLiveHandler uses ToolType.toolName() for non-proxy live WebSocket traffic.");
            case "burp.is_in_scope" -> Tooltips.textWithSource(
                    "Raw Burp Suite scope flag, not the extension's export-scope decision.",
                    "TrafficHttpHandler uses request.isInScope(); ProxyHistoryIndexReporter uses MontoyaApi.scope().isInScope(url); ProxyWebSocketIndexReporter uses MontoyaApi.scope().isInScope(url) via safeBurpInScope().");
            case "burp.message_id" -> Tooltips.textWithSource(
                    "Source-specific Burp message identifier used for correlation.",
                    "TrafficHttpHandler uses response.messageId() or request.messageId() for orphan docs; ProxyHistoryIndexReporter uses ProxyHttpRequestResponse.id(); ProxyWebSocketIndexReporter uses ProxyWebSocketMessage.id(); ToolWebSocketLiveHandler writes null for live non-proxy WebSocket frames.");
            case "burp.timing.end" -> Tooltips.textWithSource(
                    "Absolute end timestamp for this traffic event.",
                    "For HTTP traffic, this is response-end/response-received time: TrafficHttpHandler uses System.currentTimeMillis() when the response handler runs; ProxyHistoryIndexReporter and RepeaterTabsIndexReporter derive it from TimingData.timeRequestSent() plus timeBetweenRequestSentAndEndOfResponse(). For WebSocket messages, this is the frame/message time.");
            case "burp.timing.req_sent_to_res_end" -> Tooltips.textWithSource(
                    "Total observed exchange duration in milliseconds: request sent to end of response.",
                    "TrafficHttpHandler subtracts exporter-captured request/response-received timestamps; ProxyHistoryIndexReporter and RepeaterTabsIndexReporter use TimingData.timeBetweenRequestSentAndEndOfResponse(); ProxyWebSocketIndexReporter writes 0 for individual frames.");
            case "burp.notes" -> Tooltips.textWithSource(
                    "User notes attached in Burp.",
                    "HTTP docs read annotations.notes(); WebSocket docs read ProxyWebSocketMessage.annotations().notes().");
            case "burp.highlight" -> Tooltips.textWithSource(
                    "Burp highlight color.",
                    "HTTP docs read annotations.highlightColor().name(); WebSocket docs read ProxyWebSocketMessage.annotations().highlightColor().name().");
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
                    "Obtain the HTTP status code contained in the response.",
                    "RequestResponseDocBuilder.buildTrafficResponseDoc() uses HttpResponse.statusCode(); orphan docs use sentinel response.status.code=0.");
            case "response.status.description" -> Tooltips.textWithSource(
                    "Obtain the HTTP reason phrase contained in the response for HTTP 1 messages.",
                    "RequestResponseDocBuilder.buildTrafficResponseDoc() uses HttpResponse.reasonPhrase(); orphan docs use description=\"Timeout\"; empty-history docs use \"No response\".");
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
                    "ProxyWebSocketIndexReporter.buildDocument() uses ProxyWebSocketMessage.webSocketId(); ToolWebSocketLiveHandler writes null because Montoya live WebSocket message types do not expose Burp history ids.");
            case "websocket.is_websocket" -> Tooltips.textWithSource(
                    "Whether this traffic document represents a WebSocket message.",
                    "ProxyWebSocketIndexReporter and ToolWebSocketLiveHandler write true; HTTP traffic producers write false.");
            case "websocket.message_id" -> Tooltips.textWithSource(
                    "WebSocket message identifier within the WebSocket conversation. This is distinct from websocket.id, which identifies the connection/conversation.",
                    "ProxyWebSocketIndexReporter.buildDocument() uses ProxyWebSocketMessage.id(); ToolWebSocketLiveHandler writes null for live non-proxy frames.");
            case "websocket.direction" -> Tooltips.textWithSource(
                    "WebSocket message direction.",
                    "ProxyWebSocketIndexReporter.buildDocument() uses ProxyWebSocketMessage.direction().name().");
            case "websocket.message_type" -> Tooltips.textWithSource(
                    "Exporter payload classification for a WebSocket message.",
                    "WebSocketTrafficDocumentBuilder.inferPayloadType() returns EMPTY for no bytes, TEXT for strict UTF-8 decodes, otherwise BINARY.");
            case "websocket.payload.b64" -> Tooltips.textWithSource(
                    "Raw WebSocket payload stored as base64 (effective on-the-wire bytes).",
                    "ProxyWebSocketIndexReporter.buildDocument() uses editedPayload() when the frame was edited, otherwise payload().");
            case "websocket.payload.text" -> Tooltips.textWithSource(
                    "UTF-8 text view of the effective WebSocket payload when valid.",
                    "WebSocketTrafficDocumentBuilder.decodeUtf8OrNull() decodes the same bytes written to websocket.payload.b64.");
            case "websocket.payload.length" -> Tooltips.textWithSource(
                    "Effective WebSocket payload length in bytes.",
                    "WebSocketTrafficDocumentBuilder.buildPayloadDoc() uses editedPayload() when the frame was edited, otherwise payload().");
            case "websocket.payload.truncated" -> Tooltips.textWithSource(
                    "True when search/database export prefix-truncated this WebSocket payload to fit the live bulk byte budget. "
                            + "payload.length remains the original size; file export is not truncated by this path.",
                    "SearchBodyPrefixFitter.fitToLiveBudget() sets payload.truncated when shortening b64/text under BulkByteBudget pressure.");
            case "websocket.is_edited" -> Tooltips.textWithSource(
                    "Whether the WebSocket frame payload was edited.",
                    "ProxyWebSocketIndexReporter.buildDocument() uses ProxyWebSocketMessage.editedPayload() != null.");
            case "websocket.time" -> Tooltips.textWithSource(
                    "WebSocket message timestamp.",
                    "ProxyWebSocketIndexReporter uses ProxyWebSocketMessage.time(); ToolWebSocketLiveHandler uses an exporter timestamp at handler time.");
            case "burp.proxy.history_id" -> Tooltips.textWithSource(
                    "Proxy History row identifier.",
                    "ProxyHistoryIndexReporter uses ProxyHttpRequestResponse.id(); null on live HTTP, Repeater, and WebSocket documents. Use _exists_:burp.proxy.history_id to query snapshot history rows only.");
            case "burp.proxy.request_is_edited" -> Tooltips.textWithSource(
                    "Whether the HTTP request in this Proxy History row was edited.",
                    "BurpProxyFields checks ProxyHttpRequestResponse.edited(), then compares request() and finalRequest() bytes; false when the pair was not edited or only the response changed; null when the pair was edited but neither side's bytes differ.");
            case "burp.proxy.response_is_edited" -> Tooltips.textWithSource(
                    "Whether the HTTP response in this Proxy History row was edited.",
                    "BurpProxyFields checks ProxyHttpRequestResponse.edited(), then compares originalResponse() and response() bytes; false when the pair was not edited or only the request changed; null when the pair was edited but neither side's bytes differ.");
            case "burp.proxy.listener_port" -> Tooltips.textWithSource(
                    "Proxy listener port used for the message.",
                    "ProxyHistoryIndexReporter uses ProxyHttpRequestResponse.listenerPort(); ProxyWebSocketIndexReporter uses ProxyWebSocketMessage.listenerPort().");
            case "burp.timing.req_sent" -> Tooltips.textWithSource(
                    "Request-sent timestamp.",
                    "TrafficHttpHandler reuses the exporter timestamp captured when handleHttpRequestToBeSent runs; ProxyHistoryIndexReporter uses TimingData.timeRequestSent() with item.time() fallback; ProxyWebSocketIndexReporter reuses ProxyWebSocketMessage.time().");
            case "burp.timing.req_sent_to_res_start" -> Tooltips.textWithSource(
                    "Time to first response byte in milliseconds: request sent to start of response.",
                    "ProxyHistoryIndexReporter and RepeaterTabsIndexReporter use Burp TimingData.timeBetweenRequestSentAndStartOfResponse(); live HTTP and WebSocket docs write null because their handlers do not expose a separate response-start timestamp.");
            default -> ExportFieldTooltipsRequestResponse.requestResponseNestedTooltip(fieldKey);
        };
    }
}
