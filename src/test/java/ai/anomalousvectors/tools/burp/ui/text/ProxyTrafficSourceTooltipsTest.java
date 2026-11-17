package ai.anomalousvectors.tools.burp.ui.text;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ProxyTrafficSourceTooltipsTest {
    @Test
    void fieldSources_distinguishPayloadDirectionsAndAllIdNamespaces() {
        assertThat(ExportFieldTooltipsTraffic.trafficTooltip("burp.message_id"))
                .contains("general HTTP messageId()", "not a UI History number", "meta.capture.source");
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
                .contains("retained separately, not overwritten");
        assertThat(ExportFieldTooltips.tooltipFor("traffic", "meta.capture.response_state"))
                .contains("silence is not completion");
        assertThat(ExportFieldTooltipsTraffic.trafficTooltip("burp.proxy.listener_port"))
                .contains("History-backed live stream", "Ordinary live HTTP observations", "no port is guessed");
    }
}
