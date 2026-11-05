package ai.anomalousvectors.tools.burp.ui.text;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ProxyTrafficSourceTooltipsTest {
    @Test
    void fieldSources_distinguishPayloadDirectionsAndAllIdNamespaces() {
        assertThat(ExportFieldTooltipsTraffic.trafficTooltip("burp.message_id"))
                .contains("general HTTP response.messageId()", "not a UI History number");
        assertThat(ExportFieldTooltipsTraffic.trafficTooltip("burp.proxy.history_id"))
                .contains("ProxyHttpRequestResponse.id()", "UI row id");
        assertThat(ExportFieldTooltipsTraffic.trafficTooltip("request.body.b64"))
                .contains("finalRequest()", "before sending to the target");
        assertThat(ExportFieldTooltipsTraffic.trafficTooltip("response.status.code"))
                .contains("originalResponse()", "before later Burp response edits");
        assertThat(ExportFieldTooltipsTraffic.trafficTooltip("burp.proxy.response_change_stages"))
                .contains("write null", "original server response");
    }
}
