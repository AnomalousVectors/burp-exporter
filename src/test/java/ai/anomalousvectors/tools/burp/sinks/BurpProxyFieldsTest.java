package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Map;

import org.junit.jupiter.api.Test;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;

class BurpProxyFieldsTest {

    @Test
    void forProxyHistory_copiesRowLevelSignalWithoutInferringStages() {
        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        when(item.id()).thenReturn(42);
        when(item.listenerPort()).thenReturn(8080);
        when(item.edited()).thenReturn(true);

        Map<String, Object> proxy = BurpProxyFields.forProxyHistory(item);

        assertThat(proxy.get("history_id")).isEqualTo(42);
        assertThat(proxy.get("listener_port")).isEqualTo(8080);
        assertThat(proxy.get("history_is_edited")).isEqualTo(true);
        assertThat(proxy.get("request_change_stages")).isNull();
        assertThat(proxy.get("response_change_stages")).isNull();
    }

    @Test
    void withoutProxyHistoryEditMetadata_setsHistoryAndStageFieldsNull() {
        Map<String, Object> proxy = BurpProxyFields.withoutProxyHistoryEditMetadata(9090);

        assertThat(proxy.get("history_id")).isNull();
        assertThat(proxy.get("listener_port")).isEqualTo(9090);
        assertThat(proxy.get("history_is_edited")).isNull();
        assertThat(proxy.get("request_change_stages")).isNull();
        assertThat(proxy.get("response_change_stages")).isNull();
    }

}
