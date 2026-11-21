package ai.anomalousvectors.tools.burp.ui.text;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ProxyTrafficSourceTooltipsTest {
    @Test
    void groupHelpDistinguishesLiveMetadataAndCaptureLimits() {
        assertThat(ExportFieldSectionTooltips.sectionTooltipFor("traffic", "burp.proxy"))
                .contains("Live Proxy HTTP", "listener port", "History-backed")
                .doesNotContain("not used for live");
        assertThat(ExportFieldSectionTooltips.sectionTooltipFor("traffic", "websocket"))
                .contains("live callbacks leave them unknown");
        assertThat(ExportFieldSectionTooltips.sectionTooltipFor("traffic", "response.body"))
                .contains("Video payloads are omitted in both destinations", "database size fitting");
        assertThat(ExportFieldTooltipsTraffic.trafficTooltip("burp.timing.req_sent_to_res_start"))
                .contains("History-backed live streams", "callback observations and WebSocket docs write null");
    }

    @Test
    void fieldSources_distinguishPayloadDirectionsAndAllIdNamespaces() {
        assertThat(ExportFieldTooltipsTraffic.trafficTooltip("burp.message_id"))
                .contains("native Proxy messageId()", "general HTTP messageId()",
                        "Neither is a UI History number", "meta.capture.source");
        assertThat(ExportFieldTooltipsTraffic.trafficTooltip("burp.proxy.history_id"))
                .contains("ProxyHttpRequestResponse.id()", "UI row id");
        assertThat(ExportFieldTooltipsTraffic.trafficTooltip("request.body.b64"))
                .contains("finalRequest()", "including edits before sending", "History-backed live stream");
        assertThat(ExportFieldTooltipsTraffic.trafficTooltip("response.status.code"))
                .contains("original server response", "before client-bound edits", "may still be partial");
        assertThat(ExportFieldTooltipsTraffic.trafficTooltip("burp.proxy.response_change_stages"))
                .contains("write null", "original server response");
    }

    @Test
    void captureFieldsExplainIndependentImmutableObservationsAndUnknownCompletion() {
        assertThat(ExportFieldTooltips.tooltipFor("traffic", "meta.capture.id"))
                .contains("does not join independently captured live traffic");
        assertThat(ExportFieldTooltips.tooltipFor("traffic", "meta.capture.revision"))
                .contains("Search destinations retain the latest admitted revision", "Files append snapshots");
        assertThat(ExportFieldTooltips.tooltipFor("traffic", "meta.capture.response_state"))
                .contains("silence is not completion");
        assertThat(ExportFieldTooltipsTraffic.trafficTooltip("burp.proxy.listener_port"))
                .contains("listenerInterface()", "History-backed live stream",
                        "Other live HTTP tools", "no port is guessed");
        assertThat(ExportFieldTooltips.tooltipFor("traffic", "meta.capture.source"))
                .contains("live_proxy_callback", "live_http_callback", "proxy_history_stream");
    }
}
