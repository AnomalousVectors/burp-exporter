package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import burp.api.montoya.http.message.responses.HttpResponse;

class ProxyObservedStageFieldsTest {

    @Test
    void requestStages_distinguishUnchangedChangedAndUnavailableComparisons() {
        assertThat(ProxyLiveMetadataCorrelator.changeStages(
                        new byte[] {1}, new byte[] {1}, "RECEIVED_TO_SENT"))
                .isEmpty();
        assertThat(ProxyLiveMetadataCorrelator.changeStages(
                        new byte[] {1}, new byte[] {2}, "RECEIVED_TO_SENT"))
                .isEqualTo(List.of("RECEIVED_TO_SENT"));
        assertThat(ProxyLiveMetadataCorrelator.changeStages(
                        null, new byte[] {2}, "RECEIVED_TO_SENT"))
                .isNull();
    }

    @Test
    void responseStages_reportEachObservableBoundaryInOrder() {
        assertThat(ProxyLiveMetadataCorrelator.responseChangeStages(
                        new byte[] {1}, new byte[] {2}, new byte[] {3}))
                .isEqualTo(List.of("UPSTREAM_TO_RECEIVED", "RECEIVED_TO_SENT"));
        assertThat(ProxyLiveMetadataCorrelator.responseChangeStages(
                        new byte[] {1}, new byte[] {1}, new byte[] {2}))
                .isEqualTo(List.of("RECEIVED_TO_SENT"));
        assertThat(ProxyLiveMetadataCorrelator.responseChangeStages(
                        new byte[] {1}, new byte[] {1}, new byte[] {1}))
                .isEmpty();
        assertThat(ProxyLiveMetadataCorrelator.responseChangeStages(
                        new byte[] {1}, null, new byte[] {1}))
                .isNull();
    }

    @Test
    void finalResponse_replacesTheUpstreamResponseDocument() {
        HttpResponse response = org.mockito.Mockito.mock(HttpResponse.class);
        org.mockito.Mockito.when(response.statusCode()).thenReturn((short) 299);
        org.mockito.Mockito.when(response.reasonPhrase()).thenReturn("Final");
        org.mockito.Mockito.when(response.httpVersion()).thenReturn("HTTP/1.1");
        org.mockito.Mockito.when(response.headers()).thenReturn(List.of());
        org.mockito.Mockito.when(response.cookies()).thenReturn(List.of());
        org.mockito.Mockito.when(response.markers()).thenReturn(List.of());
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("response", Map.of("status", Map.of("code", 200)));

        ProxyLiveMetadataCorrelator.applyFinalResponse(document, response);

        Map<?, ?> responseDocument = (Map<?, ?>) document.get("response");
        Map<?, ?> status = (Map<?, ?>) responseDocument.get("status");
        assertThat(status.get("code")).isEqualTo(299);
        assertThat(status.get("description")).isEqualTo("Final");
    }
}
