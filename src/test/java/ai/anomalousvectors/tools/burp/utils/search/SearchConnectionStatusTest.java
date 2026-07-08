package ai.anomalousvectors.tools.burp.utils.search;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class SearchConnectionStatusTest {

    @Test
    void formattedStatus_usesDestinationNameForVersionLine() {
        SearchConnectionStatus status = new SearchConnectionStatus(
                "Elasticsearch",
                true,
                "",
                "8.14.3",
                "Connection successful",
                "Success",
                "Successful",
                "System trust store");

        assertThat(status.formattedStatus())
                .contains("Elasticsearch version: 8.14.3")
                .doesNotContain("OpenSearch version");
    }
}
