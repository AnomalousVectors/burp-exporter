package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.search.SearchConnectionStatus;

/**
 * Unit tests for {@link SearchDestinationFailureKind}.
 */
class SearchDestinationFailureKindTest {

    @Test
    void classify_http504WithAuthAttempted_isCapacity() {
        SearchConnectionStatus status = new SearchConnectionStatus(
                "Amazon OpenSearch",
                false,
                "",
                "",
                "HTTP 504 Gateway Time-out on /",
                "Failed",
                "Attempted",
                "Success");
        assertThat(SearchDestinationFailureKind.classify(status))
                .isEqualTo(SearchDestinationFailureKind.CAPACITY);
    }

    @Test
    void classify_http401WithAuthFailed_isAuth() {
        SearchConnectionStatus status = new SearchConnectionStatus(
                "OpenSearch",
                false,
                "",
                "",
                "HTTP 401 Unauthorized",
                "Failed",
                "Failed",
                "Success");
        assertThat(SearchDestinationFailureKind.classify(status))
                .isEqualTo(SearchDestinationFailureKind.AUTH);
    }

    @Test
    void classify_transportTimeoutWithAuthAttempted_isCapacity() {
        SearchConnectionStatus status = new SearchConnectionStatus(
                "Amazon OpenSearch",
                false,
                "",
                "",
                "NoHttpResponseException: host failed to respond",
                "Failed",
                "Attempted",
                "Failed");
        assertThat(SearchDestinationFailureKind.classify(status))
                .isEqualTo(SearchDestinationFailureKind.CAPACITY);
    }

    @Test
    void classify_incompleteCredentialsAuthFailed_isAuth() {
        SearchConnectionStatus status = new SearchConnectionStatus(
                "Amazon OpenSearch",
                false,
                "",
                "",
                "Username and password are required for Basic authentication.",
                "Failed",
                "Failed",
                "Not tested");
        assertThat(SearchDestinationFailureKind.classify(status))
                .isEqualTo(SearchDestinationFailureKind.AUTH);
    }

    @Test
    void isCapacityDetail_recognizesGatewayAndTransport() {
        assertThat(SearchDestinationFailureKind.isCapacityDetail("HTTP 504 Gateway Time-out")).isTrue();
        assertThat(SearchDestinationFailureKind.isCapacityDetail("failed to respond")).isTrue();
        assertThat(SearchDestinationFailureKind.isCapacityDetail("mapper_parsing_exception")).isFalse();
    }
}
