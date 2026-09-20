package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;

import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

class WebSocketTrafficDocumentBuilderScopeTest {

    @AfterEach
    public void resetRuntime() {
        RuntimeConfig.setExportRunning(false);
        MontoyaApiProvider.set(null);
    }

    @Test
    void isFilteredByExportScope_trueWhenUpgradeNull() {
        assertThat(WebSocketTrafficDocumentBuilder.isFilteredByExportScope(
                mock(MontoyaApi.class), null, "[test]")).isTrue();
    }

    @Test
    void isFilteredByExportScope_trueWhenUrlOutOfBurpScope() {
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_BURP,
                List.of(),
                null,
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("repeater"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));

        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(false);
        MontoyaApiProvider.set(api);

        HttpRequest upgrade = mockUpgradeRequest("https://example.com/ws");

        assertThat(WebSocketTrafficDocumentBuilder.isFilteredByExportScope(api, upgrade, "[test]")).isTrue();
        assertThat(WebSocketTrafficDocumentBuilder.build(new WebSocketTrafficDocumentBuilder.Input(
                api,
                upgrade,
                "[test]",
                "Repeater",
                null,
                null,
                null,
                null,
                "CLIENT_TO_SERVER",
                "hi".getBytes(StandardCharsets.UTF_8),
                "TEXT",
                null,
                null,
                "2024-01-01T00:00:00Z",
                null,
                null))).isNull();
    }

    @Test
    void isFilteredByExportScope_trueWhenCustomScopeDoesNotMatchUrl() {
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_CUSTOM,
                List.of(new ConfigState.ScopeEntry("other.test", ConfigState.Kind.STRING)),
                null,
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("repeater"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));

        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(true);
        MontoyaApiProvider.set(api);

        HttpRequest upgrade = mockUpgradeRequest("https://example.com/ws");

        assertThat(WebSocketTrafficDocumentBuilder.isFilteredByExportScope(api, upgrade, "[test]")).isTrue();
    }

    @Test
    void isFilteredByExportScope_falseWhenInScopeAndTrafficEnabled() {
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                null,
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("repeater"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));

        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(true);
        MontoyaApiProvider.set(api);

        HttpRequest upgrade = mockUpgradeRequest("https://example.com/ws");

        assertThat(WebSocketTrafficDocumentBuilder.isFilteredByExportScope(api, upgrade, "[test]")).isFalse();
        assertThat(WebSocketTrafficDocumentBuilder.build(new WebSocketTrafficDocumentBuilder.Input(
                api,
                upgrade,
                "[test]",
                "Repeater",
                null,
                null,
                null,
                null,
                "CLIENT_TO_SERVER",
                "hi".getBytes(StandardCharsets.UTF_8),
                "TEXT",
                null,
                null,
                "2024-01-01T00:00:00Z",
                null,
                null))).isNotNull();
    }

    private static HttpRequest mockUpgradeRequest(String url) {
        HttpRequest upgrade = mock(HttpRequest.class);
        HttpService service = mock(HttpService.class);
        when(upgrade.httpService()).thenReturn(service);
        when(service.host()).thenReturn("example.com");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);
        when(upgrade.url()).thenReturn(url);
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
        return upgrade;
    }
}
