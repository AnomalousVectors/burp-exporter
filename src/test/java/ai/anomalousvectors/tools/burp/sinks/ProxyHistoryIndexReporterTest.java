package ai.anomalousvectors.tools.burp.sinks;

import static ai.anomalousvectors.tools.burp.testutils.Reflect.callStatic;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.mockito.Answers;

import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Unit tests for {@link ProxyHistoryIndexReporter}: no-op paths when proxy_history
 * is not selected or export is not running (no OpenSearch or MontoyaApi required).
 */
class ProxyHistoryIndexReporterTest {

    private static void resetRuntimeConfig() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(), "all", List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        ));
        RuntimeConfig.setExportRunning(false);
    }

    @Test
    void buildDocument_returnsNull_whenBurpScopeRejectsProxyHistoryItem() {
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_BURP,
                    List.of(),
                    null,
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    List.of("proxy_history"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null));
            MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
            when(api.scope().isInScope(anyString())).thenReturn(false);

            Object doc = callStatic(
                    ProxyHistoryIndexReporter.class,
                    "buildDocument",
                    proxyHistoryItem("https://out.example/smoke"),
                RuntimeConfig.getState(),
                new ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotScopeCache(api),
                new AtomicInteger());

            assertThat(doc).isNull();
        } finally {
            resetRuntimeConfig();
        }
    }

    @Test
    void buildDocument_returnsNull_whenCustomScopeRejectsProxyHistoryItem() {
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_CUSTOM,
                    List.of(new ConfigState.ScopeEntry("in.example", ConfigState.Kind.STRING)),
                    null,
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    List.of("proxy_history"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null));
            MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
            when(api.scope().isInScope(anyString())).thenReturn(true);

            Object doc = callStatic(
                    ProxyHistoryIndexReporter.class,
                    "buildDocument",
                    proxyHistoryItem("https://out.example/smoke"),
                RuntimeConfig.getState(),
                new ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotScopeCache(api),
                new AtomicInteger());

            assertThat(doc).isNull();
        } finally {
            resetRuntimeConfig();
        }
    }

    @Test
    void buildDocument_returnsDocument_whenCustomScopeAcceptsProxyHistoryItem() {
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_CUSTOM,
                    List.of(new ConfigState.ScopeEntry("in.example", ConfigState.Kind.STRING)),
                    null,
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    List.of("proxy_history"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null));
            MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
            when(api.scope().isInScope(anyString())).thenReturn(false);

            Object doc = callStatic(
                    ProxyHistoryIndexReporter.class,
                    "buildDocument",
                    proxyHistoryItem("https://in.example/smoke"),
                RuntimeConfig.getState(),
                new ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotScopeCache(api),
                new AtomicInteger());

            assertThat(doc).isInstanceOf(Map.class);
        } finally {
            resetRuntimeConfig();
        }
    }

    @Test
    void pushSnapshotNow_doesNotThrow_whenProxyHistoryNotInTrafficTypes() {
        try {
            RuntimeConfig.setExportRunning(true);
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of("traffic"), "all", List.of(),
                    new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    List.of("proxy", "repeater"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));
            assertThatCode(() -> ProxyHistoryIndexReporter.pushSnapshotNow()).doesNotThrowAnyException();
        } finally {
            resetRuntimeConfig();
        }
    }

    @Test
    void pushSnapshotNow_doesNotThrow_whenExportNotRunning() {
        try {
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of("traffic"), "all", List.of(),
                    new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    List.of("proxy_history"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));
            assertThatCode(() -> ProxyHistoryIndexReporter.pushSnapshotNow()).doesNotThrowAnyException();
        } finally {
            resetRuntimeConfig();
        }
    }

    @Test
    void pushSnapshotNow_returnsImmediately_withoutBlocking() throws InterruptedException {
        try {
            RuntimeConfig.setExportRunning(true);
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of("traffic"), "all", List.of(),
                    new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    List.of("proxy_history"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));
            long start = System.currentTimeMillis();
            ProxyHistoryIndexReporter.pushSnapshotNow();
            long elapsed = System.currentTimeMillis() - start;
            assertThat(elapsed).isLessThan(500);
        } finally {
            resetRuntimeConfig();
        }
    }

    @Test
    void buildDocument_survivesMalformedRequest_andReconstructsUrl() {
        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(false);

        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenThrow(new IllegalStateException("URL is invalid."));
        when(request.method()).thenReturn("POST");
        when(request.path()).thenReturn("/api/orders");
        when(request.pathWithoutQuery()).thenReturn("/api/orders");
        when(request.query()).thenReturn("");
        when(request.fileExtension()).thenReturn("");
        when(request.httpVersion()).thenReturn("HTTP/1.1");
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.body()).thenReturn(null);
        when(request.markers()).thenReturn(List.of());
        when(request.contentType()).thenReturn(null);

        HttpService service = mock(HttpService.class);
        when(service.host()).thenReturn("shop.example.com");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);

        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        when(item.finalRequest()).thenReturn(request);
        when(item.httpService()).thenReturn(service);
        when(item.id()).thenReturn(42);
        when(item.listenerPort()).thenReturn(8080);
        when(item.edited()).thenReturn(false);
        when(item.annotations()).thenReturn(null);
        when(item.response()).thenReturn(null);

        Map<?, ?> doc = (Map<?, ?>) callStatic(
                ProxyHistoryIndexReporter.class,
                "buildDocument",
                item,
                RuntimeConfig.getState(),
                new ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotScopeCache(api),
                new AtomicInteger());

        assertThat(doc).isNotNull();
        Map<?, ?> requestDoc = map(doc.get("request"));
        Map<?, ?> burp = map(doc.get("burp"));
        Map<?, ?> proxy = map(burp.get("proxy"));
        Map<?, ?> websocket = map(doc.get("websocket"));
        Map<?, ?> urlDoc = nestedMap(requestDoc, "url");
        assertThat(urlDoc.get("raw")).isEqualTo("https://shop.example.com/api/orders");
        assertThat(urlDoc.get("scheme")).isEqualTo("https");
        assertThat(urlDoc.get("host")).isEqualTo("shop.example.com");
        assertThat(urlDoc.get("port")).isEqualTo(443);
        assertThat(requestDoc.get("method")).isEqualTo("POST");
        assertThat(requestDoc.containsKey("edited")).isFalse();
        assertThat(burp.get("reporting_tool")).isEqualTo("Proxy History");
        assertThat(proxy.containsKey("is_edited")).isFalse();
        assertThat(proxy.get("request_is_edited")).isEqualTo(false);
        assertThat(proxy.get("response_is_edited")).isEqualTo(false);
        assertThat(websocket.get("is_websocket")).isEqualTo(false);
        assertThat(doc.containsKey("tool_type")).isFalse();
        Map<?, ?> path = nestedMap(requestDoc, "path");
        assertThat(path.get("with_query")).isEqualTo("/api/orders");
        assertThat(path.get("without_query")).isEqualTo("/api/orders");
        assertThat(burp.get("is_in_scope")).isEqualTo(false);
    }

    @Test
    void emptyResponseDoc_matchesCurrentTrafficResponseShape() {
        Map<?, ?> responseDoc = map(callStatic(RequestResponseDocBuilder.class, "emptyTrafficResponseDoc"));

        assertContainsKeys(responseDoc,
                "status", "protocol", "headers", "cookies", "mime_type", "body");
        assertThat(responseDoc.containsKey("header")).isFalse();
        assertThat(responseDoc.containsKey("markers")).isFalse();
        Map<?, ?> status = nestedMap(responseDoc, "status");
        assertContainsKeys(status, "code", "code_class", "description");
        Map<?, ?> protocol = nestedMap(responseDoc, "protocol");
        assertContainsKeys(protocol, "http_version");
        assertMissingKeys(responseDoc, "header_names", "body_length", "body_offset");
        Map<?, ?> mimeType = nestedMap(responseDoc, "mime_type");
        assertContainsKeys(mimeType, "burp", "stated", "inferred_body");
        assertThat(mimeType.get("burp")).isNull();
        assertThat(mimeType.get("stated")).isNull();
        assertThat(mimeType.get("inferred_body")).isNull();

        Map<?, ?> body = nestedMap(responseDoc, "body");
        assertThat(body.get("length")).isEqualTo(0);
        assertThat(body.get("offset")).isEqualTo(0);
        assertThat(body.get("b64")).isNull();
        assertThat(body.get("text")).isNull();
        assertContainsKeys(body, "markers");
    }

    private static Map<?, ?> nestedMap(Map<?, ?> parent, String key) {
        return map(parent.get(key));
    }

    private static Map<?, ?> map(Object value) {
        assertThat(value).isInstanceOf(Map.class);
        return (Map<?, ?>) value;
    }

    private static ProxyHttpRequestResponse proxyHistoryItem(String url) {
        URI uri = URI.create(url);
        String query = uri.getQuery() == null ? "" : uri.getQuery();
        String path = uri.getRawPath() == null || uri.getRawPath().isBlank() ? "/" : uri.getRawPath();
        String pathWithQuery = query.isBlank() ? path : path + "?" + query;

        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn(url);
        when(request.method()).thenReturn("GET");
        when(request.path()).thenReturn(pathWithQuery);
        when(request.pathWithoutQuery()).thenReturn(path);
        when(request.query()).thenReturn(query);
        when(request.fileExtension()).thenReturn("");
        when(request.httpVersion()).thenReturn("HTTP/1.1");
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.body()).thenReturn(null);
        when(request.markers()).thenReturn(List.of());
        when(request.contentType()).thenReturn(null);

        HttpService service = mock(HttpService.class);
        when(service.host()).thenReturn(uri.getHost());
        when(service.port()).thenReturn(uri.getPort() < 0 ? 443 : uri.getPort());
        when(service.secure()).thenReturn("https".equalsIgnoreCase(uri.getScheme()));

        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        when(item.finalRequest()).thenReturn(request);
        when(item.httpService()).thenReturn(service);
        when(item.id()).thenReturn(99);
        when(item.listenerPort()).thenReturn(8080);
        when(item.edited()).thenReturn(false);
        when(item.annotations()).thenReturn(null);
        when(item.response()).thenReturn(null);
        return item;
    }

    private static void assertContainsKeys(Map<?, ?> map, String... keys) {
        for (String key : keys) {
            assertThat(map.containsKey(key)).isTrue();
        }
    }

    private static void assertMissingKeys(Map<?, ?> map, String... keys) {
        for (String key : keys) {
            assertThat(map.containsKey(key)).isFalse();
        }
    }
}
