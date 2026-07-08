package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;

import org.apache.hc.core5.http.HttpHost;
import org.junit.jupiter.api.Test;

class OpenSearchClassicHttpSupportTest {

    @Test
    void hostForBaseUrl_stripsTrailingSlash() {
        HttpHost host = OpenSearchClassicHttpSupport.hostForBaseUrl("https://opensearch.url:9200/");

        assertThat(host.getSchemeName()).isEqualTo("https");
        assertThat(host.getHostName()).isEqualTo("opensearch.url");
        assertThat(host.getPort()).isEqualTo(9200);
    }

    @Test
    void bulkPathForIndex_returnsRelativeBulkPath() {
        assertThat(OpenSearchClassicHttpSupport.bulkPathForIndex("tool-burp-traffic"))
                .isEqualTo("/tool-burp-traffic/_bulk");
    }
}
