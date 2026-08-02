package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.sinks.OpenSearchSink.IndexResult;
import ai.anomalousvectors.tools.burp.testutils.OpenSearchTestConfig;

/**
 * Negative-path validation: missing mapping resource should yield FAILED status.
 */
@Tag("integration")
class OpenSearchSinkMissingResourceIT {

    @Test
    void createIndexFromResource_returnsFailed_whenMappingResourceMissing() {
        // "nonexistent" does not correspond to any bundled search mapping file.
        IndexResult res = OpenSearchSink.createIndexFromResource(OpenSearchTestConfig.get().baseUrl(), "nonexistent");

        assertThat(res.shortName()).isEqualTo("nonexistent");
        assertThat(res.fullName()).endsWith("-nonexistent");
        assertThat(res.status()).isEqualTo(IndexResult.Status.FAILED);
    }
}
