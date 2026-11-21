package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.sinks.SearchSink.IndexResult;

/**
 * Negative path validation: an unreachable OpenSearch endpoint should yield FAILED status.
 */
@Tag("integration")
class SearchSinkErrorIT {

    // Deliberately unreachable endpoint (local address on a non-listening port) for negative path testing.
    private static final String BAD_URL = "http://127.0.0.1:9";

    @Test
    void createIndexFromResource_returnsFailed_whenEndpointUnreachable() {
        IndexResult res = SearchSink.createIndexFromResource(BAD_URL, "traffic");
        assertThat(res.shortName()).isEqualTo("traffic");
        assertThat(res.fullName()).endsWith("-traffic"); // exact prefix validated elsewhere
        assertThat(res.status()).isEqualTo(IndexResult.Status.FAILED);
    }
}
