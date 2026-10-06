package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;

import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState.State;
import ai.anomalousvectors.tools.burp.utils.config.ExportFieldFilter;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.websocket.Direction;

/**
 * Round-trip tests: build representative traffic documents, filter like export, and assert shape.
 */
class ExportFieldFilterDocumentRoundTripTest {

    private final State previous = RuntimeConfig.getState();

    @AfterEach
    public void restoreRuntimeConfig() {
        RuntimeConfig.updateState(previous);
        RuntimeConfig.setExportRunning(false);
        MontoyaApiProvider.set(null);
    }

    @Test
    void httpTraffic_defaultSelection_preservesCoreNestedShape() {
        enableAllTrafficFields();
        Map<String, Object> built = buildSampleHttpDocument();
        Map<String, Object> filtered = ExportFieldFilter.filterDocument(built, "traffic");

        assertThat(filtered).containsKeys("meta", "burp", "request", "response", "websocket");
        assertThat(nestedMap(filtered, "websocket").get("is_websocket")).isEqualTo(false);
        Map<?, ?> request = nestedMap(filtered, "request");
        assertThat(request.containsKey("url")).isTrue();
        assertThat(request.containsKey("method")).isTrue();
        assertThat(request.containsKey("protocol")).isTrue();
        assertThat(nestedMap(filtered, "response").containsKey("status")).isTrue();
    }

    @Test
    void httpTraffic_partialSelection_keepsOnlyEnabledNestedLeaves() {
        RuntimeConfig.updateState(new State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                null,
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                Map.of("traffic", Set.of("request.url.raw", "websocket.is_websocket"))));

        Map<String, Object> built = buildSampleHttpDocument();
        Map<String, Object> filtered = ExportFieldFilter.filterDocument(built, "traffic");

        assertThat(filtered).containsKeys("meta", "request", "websocket");
        assertThat(nestedMap(filtered, "request").keySet().size()).isEqualTo(1);
        assertThat(nestedMap(nestedMap(filtered, "request"), "url").get("raw")).isEqualTo("https://example.com/path");
        assertThat(nestedMap(filtered, "websocket").keySet().size()).isEqualTo(1);
        assertThat(nestedMap(filtered, "websocket").get("is_websocket")).isEqualTo(false);
        assertThat(filtered).doesNotContainKeys("burp", "response");
    }

    @Test
    void httpTraffic_progressiveBodyFields_canBeSelectedIndependently() {
        RuntimeConfig.updateState(new State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                null,
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                Map.of("traffic", Set.of(
                        "request.body.decoded_b64",
                        "request.body.content_encoding.applied",
                        "request.body.content_encoding.remaining",
                        "request.body.content_encoding.complete"))));
        Map<String, Object> body = Map.of(
                "b64", "wire",
                "decoded_b64", "decoded",
                "text", "decoded text",
                "content_encoding", Map.of(
                        "applied", List.of("gzip"),
                        "remaining", List.of("br"),
                        "complete", false));
        Map<String, Object> document = Map.of(
                "meta", Map.of("schema_version", "1"),
                "request", Map.of("body", body));

        Map<String, Object> filtered = ExportFieldFilter.filterDocument(document, "traffic");

        Map<?, ?> filteredBody = nestedMap(nestedMap(filtered, "request"), "body");
        assertThat(filteredBody).hasSize(2);
        assertThat(filteredBody.containsKey("decoded_b64")).isTrue();
        assertThat(filteredBody.containsKey("content_encoding")).isTrue();
        assertThat(filteredBody.get("decoded_b64")).isEqualTo("decoded");
        Map<?, ?> encoding = nestedMap(filteredBody, "content_encoding");
        assertThat(encoding).hasSize(3);
        assertThat(encoding.containsKey("applied")).isTrue();
        assertThat(encoding.containsKey("remaining")).isTrue();
        assertThat(encoding.containsKey("complete")).isTrue();
        assertThat(encoding.get("applied")).isEqualTo(List.of("gzip"));
        assertThat(encoding.get("remaining")).isEqualTo(List.of("br"));
        assertThat(encoding.get("complete")).isEqualTo(false);
    }

    @Test
    void proxyWebSocket_defaultSelection_preservesNestedWebSocketAndRequest() {
        enableAllTrafficFields();
        Map<String, Object> built = buildSampleProxyWebSocketDocument();
        Map<String, Object> filtered = ExportFieldFilter.filterDocument(built, "traffic");

        Map<?, ?> websocket = nestedMap(filtered, "websocket");
        assertThat(websocket.get("is_websocket")).isEqualTo(true);
        assertThat(websocket.get("id")).isEqualTo(7);
        assertThat(websocket.get("direction")).isEqualTo("CLIENT_TO_SERVER");
        assertThat(nestedMap(websocket, "payload").get("text")).isEqualTo("hello");
        assertThat(nestedMap(filtered, "request").get("method")).isEqualTo("GET");
        assertThat(nestedMap(filtered, "burp").get("reporting_tool")).isEqualTo("Proxy WebSocket");
    }

    @Test
    void proxyWebSocket_partialSelection_omitsDisabledNestedBranches() {
        RuntimeConfig.updateState(new State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                null,
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                Map.of("traffic", Set.of(
                        "websocket.direction",
                        "websocket.payload.text",
                        "request.url.raw"))));

        Map<String, Object> built = buildSampleProxyWebSocketDocument();
        Map<String, Object> filtered = ExportFieldFilter.filterDocument(built, "traffic");

        assertThat(filtered).containsKeys("meta", "request", "websocket");
        assertThat(filtered).doesNotContainKey("burp");
        Map<?, ?> websocket = nestedMap(filtered, "websocket");
        assertThat(websocket.get("direction")).isEqualTo("CLIENT_TO_SERVER");
        assertThat(websocket.containsKey("id")).isFalse();
        assertThat(websocket.containsKey("message_id")).isFalse();
        assertThat(websocket.containsKey("is_edited")).isFalse();
        Map<?, ?> payload = nestedMap(websocket, "payload");
        assertThat(payload.get("text")).isEqualTo("hello");
        assertThat(payload.containsKey("b64")).isFalse();
        assertThat(payload.containsKey("length")).isFalse();
        Map<?, ?> request = nestedMap(filtered, "request");
        assertThat(nestedMap(request, "url").get("raw")).isEqualTo("https://example.com/ws");
        assertThat(request.containsKey("method")).isFalse();
        assertThat(request.containsKey("headers")).isFalse();
        assertThat(request.containsKey("parameters")).isFalse();
    }

    @Test
    void toolWebSocket_defaultSelection_preservesNullIdsAndPayload() {
        enableAllTrafficFields();
        Map<String, Object> built = buildSampleToolWebSocketDocument();
        Map<String, Object> filtered = ExportFieldFilter.filterDocument(built, "traffic");

        Map<?, ?> websocket = nestedMap(filtered, "websocket");
        assertThat(websocket.get("is_websocket")).isEqualTo(true);
        assertThat(websocket.get("id")).isNull();
        assertThat(websocket.get("message_id")).isNull();
        assertThat(nestedMap(websocket, "payload").get("text")).isEqualTo("ping");
        assertThat(nestedMap(filtered, "burp").get("reporting_tool")).isEqualTo("Repeater");
    }

    @Test
    void toolWebSocket_partialSelection_keepsEnabledWebSocketLeavesOnly() {
        RuntimeConfig.updateState(new State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                null,
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("repeater"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                Map.of("traffic", Set.of("websocket.payload.text", "burp.reporting_tool"))));

        Map<String, Object> built = buildSampleToolWebSocketDocument();
        Map<String, Object> filtered = ExportFieldFilter.filterDocument(built, "traffic");

        assertThat(filtered).containsKeys("meta", "burp", "websocket");
        assertThat(filtered).doesNotContainKey("request");
        assertThat(nestedMap(filtered, "burp").get("reporting_tool")).isEqualTo("Repeater");
        Map<?, ?> websocket = nestedMap(filtered, "websocket");
        assertThat(nestedMap(websocket, "payload").get("text")).isEqualTo("ping");
        assertThat(websocket.containsKey("direction")).isFalse();
        assertThat(websocket.containsKey("id")).isFalse();
        assertThat(websocket.containsKey("time")).isFalse();
    }

    @Test
    void prepareExport_appliesSameFilterAsDirectCall() {
        enableAllTrafficFields();
        Map<String, Object> built = buildSampleProxyWebSocketDocument();
        RuntimeConfig.updateState(new State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                null,
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                Map.of("traffic", Set.of("websocket.direction", "meta.schema_version"))));

        PreparedExportDocument prepared = ExportDocumentIdentity.prepare("traffic-index", "traffic", built);
        Map<String, Object> filtered = ExportFieldFilter.filterDocument(built, "traffic");

        assertThat(prepared.document().get("websocket")).isEqualTo(filtered.get("websocket"));
        assertThat(nestedMap(prepared.document(), "meta").get("schema_version"))
                .isEqualTo(nestedMap(filtered, "meta").get("schema_version"));
        assertThat(nestedMap(prepared.document(), "meta").containsKey("export_id")).isFalse();
        assertThat(prepared.document()).doesNotContainKeys("burp", "request");
    }

    private static void enableAllTrafficFields() {
        RuntimeConfig.updateState(new State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                null,
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                null));
    }

    private static Map<String, Object> buildSampleHttpDocument() {
        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(true);
        MontoyaApiProvider.set(api);

        HttpRequest request = mock(HttpRequest.class);
        HttpService service = mock(HttpService.class);
        HttpResponseReceived response = mock(HttpResponseReceived.class);
        when(service.host()).thenReturn("example.com");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);
        when(request.url()).thenReturn("https://example.com/path");
        when(request.httpService()).thenReturn(service);
        when(request.httpVersion()).thenReturn("HTTP/1.1");
        when(request.method()).thenReturn("GET");
        when(request.path()).thenReturn("/path");
        when(request.pathWithoutQuery()).thenReturn("/path");
        when(request.query()).thenReturn("");
        when(request.fileExtension()).thenReturn("");
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.body()).thenReturn(null);
        when(request.bodyOffset()).thenReturn(0);
        when(request.markers()).thenReturn(List.of());
        when(request.contentType()).thenReturn(ContentType.NONE);

        when(response.initiatingRequest()).thenReturn(request);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.reasonPhrase()).thenReturn("OK");
        when(response.httpVersion()).thenReturn("HTTP/1.1");
        when(response.headers()).thenReturn(List.of());
        when(response.cookies()).thenReturn(List.of());
        when(response.mimeType()).thenReturn(MimeType.HTML);
        when(response.statedMimeType()).thenReturn(MimeType.HTML);
        when(response.inferredMimeType()).thenReturn(MimeType.HTML);
        when(response.body()).thenReturn(null);
        when(response.bodyOffset()).thenReturn(0);
        when(response.bodyToString()).thenReturn("");
        when(response.markers()).thenReturn(List.of());
        when(response.attributes(any(AttributeType[].class))).thenReturn(List.of());

        return new TrafficHttpHandler().buildDocument(response, request, true);
    }

    private static Map<String, Object> buildSampleProxyWebSocketDocument() {
        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(true);
        MontoyaApiProvider.set(api);

        ProxyWebSocketMessage ws = mock(ProxyWebSocketMessage.class);
        HttpRequest upgrade = mock(HttpRequest.class);
        HttpService svc = mock(HttpService.class);
        ByteArray payload = mock(ByteArray.class);
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
        when(ws.upgradeRequest()).thenReturn(upgrade);
        when(ws.id()).thenReturn(12);
        when(ws.webSocketId()).thenReturn(7);
        when(ws.listenerPort()).thenReturn(8080);
        when(ws.payload()).thenReturn(payload);
        when(ws.editedPayload()).thenReturn(null);
        when(ws.direction()).thenReturn(Direction.CLIENT_TO_SERVER);
        when(ws.time()).thenReturn(ZonedDateTime.now());
        when(ws.annotations()).thenReturn(null);
        return ProxyWebSocketIndexReporter.buildDocument(api, ws);
    }

    private static Map<String, Object> buildSampleToolWebSocketDocument() {
        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(true);
        MontoyaApiProvider.set(api);

        HttpRequest upgrade = mock(HttpRequest.class);
        HttpService service = mock(HttpService.class);
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

        return ToolWebSocketLiveHandler.buildLiveDocument(
                ToolType.REPEATER,
                upgrade,
                "ping".getBytes(StandardCharsets.UTF_8),
                Direction.SERVER_TO_CLIENT);
    }

    private static Map<?, ?> nestedMap(Map<?, ?> parent, String key) {
        assertThat(parent.get(key)).isInstanceOf(Map.class);
        return (Map<?, ?>) parent.get(key);
    }
}
