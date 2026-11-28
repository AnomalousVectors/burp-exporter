package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.ProxyWebSocketMessage;

/** Ensures preconstruction estimates never copy payload bytes. */
class SnapshotMemoryEstimateTest {
    @Test
    void httpAndProxyEstimatesUseFinalRequestAndLengthsWithoutCopies() {
        ByteArray body = mock(ByteArray.class);
        when(body.length()).thenReturn(100);
        HttpRequest request = mock(HttpRequest.class);
        HttpResponse response = mock(HttpResponse.class);
        when(request.body()).thenReturn(body);
        when(response.body()).thenReturn(body);
        HttpRequestResponse exchange = mock(HttpRequestResponse.class);
        when(exchange.request()).thenReturn(request);
        when(exchange.response()).thenReturn(response);
        ProxyHttpRequestResponse proxy = mock(ProxyHttpRequestResponse.class);
        when(proxy.finalRequest()).thenReturn(request);
        when(proxy.response()).thenReturn(response);

        assertThat(SnapshotMemoryEstimate.exchange(exchange)).isEqualTo(65_536L + 1_600L);
        assertThat(SnapshotMemoryEstimate.proxy(proxy)).isEqualTo(SnapshotMemoryEstimate.exchange(exchange));
        verify(body, never()).getBytes();
        verify(request, never()).toByteArray();
        verify(response, never()).toByteArray();
        verify(proxy, never()).request();
    }

    @Test
    void webSocketEstimateUsesEditedPayloadWithoutCopyingIt() {
        ByteArray edited = mock(ByteArray.class);
        when(edited.length()).thenReturn(1_000);
        ProxyWebSocketMessage message = mock(ProxyWebSocketMessage.class);
        when(message.editedPayload()).thenReturn(edited);
        assertThat(SnapshotMemoryEstimate.webSocket(message)).isEqualTo(65_536L + 8_000L);
        verify(message, never()).payload();
        verify(edited, never()).getBytes();
    }
}
