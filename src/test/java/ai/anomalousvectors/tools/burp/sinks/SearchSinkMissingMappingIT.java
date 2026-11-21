package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;

import ai.anomalousvectors.tools.burp.sinks.SearchSink.IndexResult;
import ai.anomalousvectors.tools.burp.testutils.OpenSearchReachable;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.Logger;

/**
 * Negative-path validation: creating an index for which no mapping resource exists
 * should return FAILED and not create the index.
 */
@Tag("integration")
class SearchSinkMissingMappingIT {

    @Test
    void createIndexFromResource_returnsFailed_whenMappingIsMissing() throws Exception {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        // Choose a short name with no corresponding mapping file.
        String shortName = "nonexistent";
        String expectedFull = IndexNaming.indexNameForShortName(shortName);

        OpenSearchClient client = OpenSearchReachable.getClient();

        // Ensure the index is absent before the test (best-effort cleanup).
        try {
            client.indices().delete(new DeleteIndexRequest.Builder().index(expectedFull).build());
        } catch (java.io.IOException | RuntimeException e) {
            // Best-effort cleanup: index may already be missing or the dev cluster may have been reset.
            Logger.logError("[SearchSinkMissingMappingIT] Failed to delete index during pre-test cleanup: " + expectedFull, e);
        }

        // Attempt creation; sink should fail due to missing resource.
        IndexResult result = OpenSearchReachable.createIndexFromResource(shortName);
        assertThat(result.shortName()).isEqualTo(shortName);
        assertThat(result.fullName()).isEqualTo(expectedFull);
        assertThat(result.status()).isEqualTo(IndexResult.Status.FAILED);

        // Verify the index was not created.
        boolean existsAfter = client.indices().exists(b -> b.index(expectedFull)).value();
        assertThat(existsAfter).isFalse();
    }
}
