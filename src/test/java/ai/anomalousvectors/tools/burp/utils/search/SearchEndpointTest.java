package ai.anomalousvectors.tools.burp.utils.search;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class SearchEndpointTest {

    @ParameterizedTest
    @MethodSource("supportedEndpoints")
    void parse_acceptsSupportedRootForms(String configured, String canonical, String host, int effectivePort) {
        SearchEndpoint endpoint = SearchEndpoint.parse(configured);

        assertThat(endpoint.baseUrl()).isEqualTo(canonical);
        assertThat(endpoint.displayValue()).isEqualTo(canonical);
        assertThat(endpoint.host()).isEqualTo(host);
        assertThat(endpoint.effectivePort()).isEqualTo(effectivePort);
    }

    private static Stream<Arguments> supportedEndpoints() {
        return Stream.of(
                Arguments.of(
                        " https://opensearch.url:9200/ ",
                        "https://opensearch.url:9200",
                        "opensearch.url",
                        9200),
                Arguments.of(
                        "HTTPS://SEARCH-EXAMPLE.US-EAST-1.ES.AMAZONAWS.COM:443/",
                        "https://search-example.us-east-1.es.amazonaws.com",
                        "search-example.us-east-1.es.amazonaws.com",
                        443),
                Arguments.of("http://127.0.0.1:80", "http://127.0.0.1", "127.0.0.1", 80),
                Arguments.of("http://[2001:db8::1]:9200/", "http://[2001:db8::1]:9200", "[2001:db8::1]", 9200));
    }

    @Test
    void parse_canonicalizesEquivalentRootsToEqualValues() {
        SearchEndpoint first = SearchEndpoint.parse("HTTPS://Example.COM:443/");
        SearchEndpoint second = SearchEndpoint.parse("https://example.com");

        assertThat(first).isEqualTo(second);
        assertThat(first.hashCode()).isEqualTo(second.hashCode());
        assertThat(first.baseUrl()).isEqualTo("https://example.com");
    }

    @Test
    void resolve_buildsRequestsFromTheCanonicalRoot() {
        SearchEndpoint endpoint = SearchEndpoint.parse("https://example.com:9443/");

        assertThat(endpoint.resolve("/tool-burp-traffic/_bulk?refresh=false"))
                .hasToString("https://example.com:9443/tool-burp-traffic/_bulk?refresh=false");
    }

    @ParameterizedTest
    @MethodSource("unsupportedEndpoints")
    void parse_rejectsUnsupportedEndpointComponents(String configured, String expectedMessage) {
        assertThatThrownBy(() -> SearchEndpoint.parse(configured))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage(expectedMessage);
    }

    private static Stream<Arguments> unsupportedEndpoints() {
        return Stream.of(
                Arguments.of("", "Base URL is required."),
                Arguments.of("opensearch.example:9200", "Base URL must use http:// or https://."),
                Arguments.of("ftp://example.com", "Base URL must use http:// or https://."),
                Arguments.of("https://user:secret@example.com", "Base URL must not include embedded credentials."),
                Arguments.of("https://example.com/proxy", "Base URL must identify the database root without a path."),
                Arguments.of("https://example.com?pretty", "Base URL must not include a query string."),
                Arguments.of("https://example.com#cluster", "Base URL must not include a fragment."),
                Arguments.of("https://example.com:0", "Base URL port must be between 1 and 65535."),
                Arguments.of("https://example.com:65536", "Base URL port must be between 1 and 65535."));
    }

    @Test
    void parse_doesNotRepeatCredentialBearingInputInFailureMessage() {
        assertThatThrownBy(() -> SearchEndpoint.parse("https://operator:highly-sensitive@example.com/path"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Base URL must not include embedded credentials.")
                .hasMessageNotContaining("operator")
                .hasMessageNotContaining("highly-sensitive");
    }

    @ParameterizedTest
    @MethodSource("invalidRequestTargets")
    void resolve_rejectsTargetsThatCouldReplaceTheEndpoint(String requestTarget) {
        SearchEndpoint endpoint = SearchEndpoint.parse("https://example.com");

        assertThatThrownBy(() -> endpoint.resolve(requestTarget))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static Stream<String> invalidRequestTargets() {
        return Stream.of("relative", "//other.example/_bulk", "https://other.example/_bulk", "/_bulk#fragment");
    }
}
