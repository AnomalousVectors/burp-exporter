package ai.anomalousvectors.tools.burp.sinks;

import java.io.IOException;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;

import static org.assertj.core.api.Assertions.assertThat;

import ai.anomalousvectors.tools.burp.sinks.SearchSink.IndexResult;
import ai.anomalousvectors.tools.burp.testutils.OpenSearchReachable;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.Logger;

/**
 * Verifies sink behavior when an unknown source name is supplied.
 * Ensures no result is labeled with the unknown short name and any produced indices conform to naming rules.
 */
@Tag("integration")
class SearchSinkUnsupportedSourceIT {

    private static final Set<String> ALLOWED_SHORT_NAMES = Set.of(
            "exporter", "settings", "sitemap", "findings", "traffic"
    );

    @Test
    void unknownSource_producesNoUnknownShortNames_andCleansUp() {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        List<IndexResult> results = OpenSearchReachable.createSelectedIndexes(List.of("bogus"));

        // No result should carry the unknown short name.
        assertThat(results.stream().anyMatch(r -> r.shortName().equals("bogus"))).isFalse();

        // Any produced results must be from the allowed set and use correct full-name derivation.
        for (IndexResult r : results) {
            assertThat(r.shortName()).isIn(ALLOWED_SHORT_NAMES);
            String expectedFull = IndexNaming.indexNameForShortName(r.shortName());
            assertThat(r.fullName()).isEqualTo(expectedFull);
        }

        // Cleanup of any indices that were produced (best-effort).
        if (!results.isEmpty()) {
            OpenSearchClient client = OpenSearchReachable.getClient();
            for (IndexResult r : results) {
                try {
                    client.indices().delete(new DeleteIndexRequest.Builder().index(r.fullName()).build());
                } catch (IOException | RuntimeException e) {
                    Logger.logError("[SearchSinkUnsupportedSourceIT] Failed to delete index during unsupported-source test cleanup: " + r.fullName(), e);
                }
            }
        }
    }
}
