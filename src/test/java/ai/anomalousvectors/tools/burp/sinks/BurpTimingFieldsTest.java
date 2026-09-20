package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.Map;

import org.junit.jupiter.api.Test;

import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

class BurpTimingFieldsTest {

    @Test
    void fromHandlerEpochMillis_nullRequestSent_preservesEndOnly() {
        Map<String, Object> timing = BurpTimingFields.fromHandlerEpochMillis(null, 1_700_000_000_000L);

        assertThat(timing.get("req_sent")).isNull();
        assertThat(timing.get("req_sent_to_res_start")).isNull();
        assertThat(timing.get("req_sent_to_res_end")).isNull();
        assertThat(timing.get("end")).isEqualTo(Instant.ofEpochMilli(1_700_000_000_000L).toString());
    }

    @Test
    void fromHandlerEpochMillis_computesDurationWhenBothEpochsPresent() {
        long start = 1_000L;
        long end = 2_500L;
        Map<String, Object> timing = BurpTimingFields.fromHandlerEpochMillis(start, end);

        assertThat(timing.get("req_sent")).isEqualTo(Instant.ofEpochMilli(start).toString());
        assertThat(timing.get("end")).isEqualTo(Instant.ofEpochMilli(end).toString());
        assertThat(timing.get("req_sent_to_res_end")).isEqualTo(1500L);
    }

    @Test
    void fromProxyHistory_doesNotRelabelRequestReceivedTimeAsRequestSentTime() {
        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        TimingData timingData = mock(TimingData.class);
        ZonedDateTime proxyTime = ZonedDateTime.parse("2024-06-01T12:00:00Z");

        when(item.timingData()).thenReturn(timingData);
        when(timingData.timeRequestSent()).thenReturn(null);
        when(timingData.timeBetweenRequestSentAndStartOfResponse()).thenReturn(null);
        when(timingData.timeBetweenRequestSentAndEndOfResponse()).thenReturn(null);
        when(item.time()).thenReturn(proxyTime);

        Map<String, Object> timing = BurpTimingFields.fromProxyHistory(item);

        assertThat(timing.get("req_sent")).isNull();
        assertThat(timing.get("end")).isNull();
    }

    @Test
    void fromProxyHistory_epochSentinelLeavesAllTimingUnavailable() {
        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        TimingData timingData = mock(TimingData.class);

        when(item.timingData()).thenReturn(timingData);
        when(timingData.timeRequestSent())
                .thenReturn(ZonedDateTime.ofInstant(Instant.EPOCH, java.time.ZoneOffset.UTC));
        when(timingData.timeBetweenRequestSentAndStartOfResponse()).thenReturn(Duration.ZERO);
        when(timingData.timeBetweenRequestSentAndEndOfResponse()).thenReturn(Duration.ZERO);

        Map<String, Object> timing = BurpTimingFields.fromProxyHistory(item);

        assertThat(timing.values()).containsOnlyNulls();
    }

    @Test
    void fromProxyHistory_usesValidTimingData() {
        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        TimingData timingData = mock(TimingData.class);
        ZonedDateTime sent = ZonedDateTime.parse("2024-06-01T10:00:00Z");

        when(item.timingData()).thenReturn(timingData);
        when(timingData.timeRequestSent()).thenReturn(sent);
        when(timingData.timeBetweenRequestSentAndStartOfResponse()).thenReturn(Duration.ofMillis(40));
        when(timingData.timeBetweenRequestSentAndEndOfResponse()).thenReturn(Duration.ofMillis(120));

        Map<String, Object> timing = BurpTimingFields.fromProxyHistory(item);

        assertThat(timing.get("req_sent")).isEqualTo(sent.toInstant().toString());
        assertThat(timing.get("req_sent_to_res_start")).isEqualTo(40);
        assertThat(timing.get("req_sent_to_res_end")).isEqualTo(120);
        assertThat(timing.get("end")).isEqualTo(sent.plus(Duration.ofMillis(120)).toInstant().toString());
    }

    @Test
    void mergeProxyHistoryOverLive_preservesLiveTimingForEpochSentinel() {
        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        TimingData timingData = mock(TimingData.class);
        Map<String, Object> live = BurpTimingFields.fromHandlerEpochMillis(
                1_700_000_000_000L,
                1_700_000_000_125L);

        when(item.timingData()).thenReturn(timingData);
        when(timingData.timeRequestSent())
                .thenReturn(ZonedDateTime.ofInstant(Instant.EPOCH, java.time.ZoneOffset.UTC));
        when(timingData.timeBetweenRequestSentAndStartOfResponse()).thenReturn(Duration.ZERO);
        when(timingData.timeBetweenRequestSentAndEndOfResponse()).thenReturn(Duration.ZERO);

        Map<String, Object> timing = BurpTimingFields.mergeProxyHistoryOverLive(live, item);

        assertThat(timing).isEqualTo(live);
    }

    @Test
    void from_usesMontoyaTimingDataWhenPresent() {
        HttpRequestResponse item = mock(HttpRequestResponse.class);
        TimingData timingData = mock(TimingData.class);
        ZonedDateTime sent = ZonedDateTime.parse("2024-06-01T10:00:00Z");

        when(item.timingData()).thenReturn(java.util.Optional.of(timingData));
        when(timingData.timeRequestSent()).thenReturn(sent);
        when(timingData.timeBetweenRequestSentAndStartOfResponse()).thenReturn(Duration.ofMillis(40));
        when(timingData.timeBetweenRequestSentAndEndOfResponse()).thenReturn(Duration.ofMillis(120));

        Map<String, Object> timing = BurpTimingFields.from(item);

        assertThat(timing.get("req_sent")).isEqualTo(sent.toInstant().toString());
        assertThat(timing.get("req_sent_to_res_start")).isEqualTo(40);
        assertThat(timing.get("req_sent_to_res_end")).isEqualTo(120);
        assertThat(timing.get("end")).isEqualTo(sent.plus(Duration.ofMillis(120)).toInstant().toString());
    }

    @Test
    void from_nullItem_returnsEmptyTimingKeys() {
        Map<String, Object> timing = BurpTimingFields.from(null);

        assertThat(timing).containsKeys("req_sent", "end", "req_sent_to_res_start", "req_sent_to_res_end");
        assertThat(timing.get("req_sent")).isNull();
        assertThat(timing.get("end")).isNull();
    }
}
