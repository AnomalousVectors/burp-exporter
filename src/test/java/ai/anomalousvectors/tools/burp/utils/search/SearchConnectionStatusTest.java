package ai.anomalousvectors.tools.burp.utils.search;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class SearchConnectionStatusTest {

    @Test
    void constructor_normalizesAndBoundsDestinationTextBeforeFormatting() {
        SearchConnectionStatus status = new SearchConnectionStatus(
                "OpenSearch\r\nforged",
                false,
                "dist\nforged",
                "1.0\rforged",
                "uuid\nforged",
                "HTTP 500\r\n[ERROR] forged Authorization: Bearer raw-token",
                "Failed\nforged",
                "Attempted\rforged",
                "Trust failed\nforged");

        assertThat(status.formattedStatus())
                .doesNotContain("\r", "raw-token")
                .contains("OpenSearch forged version: dist forged 1.0 forged")
                .contains("Details: HTTP 500 [ERROR] forged Authorization: Bearer ***");
    }

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

    @Test
    void formattedStatus_addsCredentialExpiryHintOnAuthFailure() {
        SearchConnectionStatus status = new SearchConnectionStatus(
                "OpenSearch",
                false,
                "",
                "",
                "HTTP 401 Unauthorized",
                "Success",
                "Failed",
                "System trust store");

        assertThat(status.formattedStatus())
                .contains("Authentication: Failed")
                .contains("Details: HTTP 401 Unauthorized")
                .contains("bearer/API key/session token may have expired");
    }
}
