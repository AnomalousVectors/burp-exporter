package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import ai.anomalousvectors.tools.burp.utils.config.ConfigJsonMapper;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.ExportFieldFilter;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.responses.HttpResponse;

/** Verifies explicit response-only media omission before payload materialization. */
class VideoResponseBodyPolicyTest {
    private final ConfigState.State saved = RuntimeConfig.getState();
    private final byte[] payload = {0, 1, 2, 3, 4};
    private final ByteArray bytes = mock(ByteArray.class);

    @AfterEach
    void restore() { RuntimeConfig.updateState(saved); }

    @Test
    void videoRetainsMetadataWithoutReadingBytesOrHidingOmission() throws Exception {
        RuntimeConfig.updateState(ConfigJsonMapper.parseState("{}"));
        HttpResponse response = response(" VIDEO/MP4; codecs=avc1");
        Map<String, Object> document = RequestResponseDocBuilder.buildTrafficResponseDoc(response);
        Map<?, ?> body = (Map<?, ?>) document.get("body");
        assertThat(body.get("length")).isEqualTo(payload.length);
        assertThat(body.get("omitted")).isEqualTo(true);
        assertThat(body.get("omission_reason")).isEqualTo("video_response_body_disabled");
        assertThat(body.get("b64")).isNull();
        assertThat(document.get("headers")).isNotNull();
        verify(bytes, never()).getBytes();
        ConfigState.State current = RuntimeConfig.getState();
        RuntimeConfig.updateState(new ConfigState.State(current.dataSources(), current.scopeType(),
                current.customEntries(), current.sinks(), current.settingsSub(), current.trafficToolTypes(),
                current.findingsSeverities(), current.exporterSubOptions(), current.exporterStatsIntervalSeconds(),
                current.indexNameBaseTemplate(), Map.of("traffic", Set.of()), current.uiPreferences()));
        Map<String, Object> filtered = ExportFieldFilter.filterDocument(Map.of("response", document), "traffic");
        Map<?, ?> retained = (Map<?, ?>) ((Map<?, ?>) filtered.get("response")).get("body");
        assertThat(retained.containsKey("omitted")).isTrue();
        assertThat(retained.containsKey("omission_reason")).isTrue();
    }

    @Test
    void removedConfigOptionCannotEnableVideoBodiesAcrossResponseShapes() throws Exception {
        var parsed = ConfigJsonMapper.parse("{\"capture\":{\"includeVideoResponseBodies\":true}}");
        assertThat(parsed.report().warnings()).anyMatch(w -> w.jsonPath().equals("capture"));
        RuntimeConfig.updateState(parsed.state());
        RuntimeConfig.updateStatsChartStyle(1);
        assertThat(ConfigJsonMapper.build(RuntimeConfig.getState())).doesNotContain("capture", "includeVideoResponseBodies");
        for (Map<String, Object> document : List.of(
                RequestResponseDocBuilder.buildTrafficResponseDoc(response("video/mp4")),
                RequestResponseDocBuilder.buildResponseDoc(response("video/mp4")))) {
            Map<?, ?> body = (Map<?, ?>) document.get("body");
            assertThat(body.get("omitted")).isEqualTo(true);
            assertThat(body.get("omission_reason")).isEqualTo("video_response_body_disabled");
            assertThat(body.get("b64")).isNull();
        }
        verify(bytes, never()).getBytes();
    }

    @ParameterizedTest
    @ValueSource(strings={"application/grpc", "application/octet-stream", "application/x-ndjson",
            "multipart/mixed; boundary=x", "application/vnd.apple.mpegurl", "text/event-stream"})
    void applicationPayloadsAreNotExcludedEvenWhenBurpInfersVideo(String contentType) throws Exception {
        RuntimeConfig.updateState(ConfigJsonMapper.parseState("{}"));
        Map<?, ?> body = (Map<?, ?>) RequestResponseDocBuilder.buildTrafficResponseDoc(response(contentType)).get("body");
        assertThat(body.get("b64")).isEqualTo(Base64.getEncoder().encodeToString(payload));
        assertThat(body.containsKey("omitted")).isFalse();
    }

    private HttpResponse response(String contentType) {
        HttpResponse response = mock(HttpResponse.class);
        HttpHeader header = mock(HttpHeader.class);
        when(header.name()).thenReturn("Content-Type");
        when(header.value()).thenReturn(contentType);
        when(response.headers()).thenReturn(List.of(header));
        when(response.statusCode()).thenReturn((short) 200);
        when(response.httpVersion()).thenReturn("HTTP/2");
        when(response.mimeType()).thenReturn(MimeType.VIDEO);
        when(bytes.length()).thenReturn(payload.length);
        when(bytes.getBytes()).thenReturn(payload);
        when(response.body()).thenReturn(bytes);
        return response;
    }
}
