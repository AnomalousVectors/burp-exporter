package ai.anomalousvectors.tools.burp.sinks;

import java.io.IOException;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;

import static org.assertj.core.api.Assertions.assertThat;

import ai.anomalousvectors.tools.burp.sinks.OpenSearchSink.IndexResult;
import ai.anomalousvectors.tools.burp.testutils.OpenSearchReachable;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.Logger;

/**
 * Exercises index lifecycle operations against a live OpenSearch test cluster.
 *
 * <p>These tests verify index creation, existence reporting, deletion, and re-creation through
 * {@link OpenSearchSink}. Root-owned cleanup runs after all selected Jupiter tests finish.</p>
 */
@Tag("integration")
@ExtendWith(OpenSearchCleanupExtension.class)
class OpenSearchSinkIT {

    /**
     * Verifies the full lifecycle for the standard index set.
     *
     * <p>The test creates or discovers the expected indices, deletes them with best-effort
     * cleanup, recreates them, and then validates their full names.</p>
     */
    @Test
    void create_delete_recreate_standardIndices_viaSink() throws IOException {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        List<String> sources = List.of("settings", "sitemap", "findings", "traffic", "exporter");

        // Pass 1: create or report existing
        List<IndexResult> first = OpenSearchReachable.createSelectedIndexes(sources);

        EnumSet<IndexResult.Status> allowed = EnumSet.of(IndexResult.Status.CREATED, IndexResult.Status.EXISTS);
        assertThat(first)
                .isNotEmpty()
                .allSatisfy(r -> assertThat(r.status()).isIn(allowed));

        // Validate full index naming
        for (IndexResult r : first) {
            String expectedFull = IndexNaming.indexNameForShortName(r.shortName());
            assertThat(r.fullName()).isEqualTo(expectedFull);
        }

        // Delete reported indices (best-effort cleanup of dev cluster)
        List<String> fullNames = first.stream().map(result -> result.fullName()).toList();
        OpenSearchClient client = OpenSearchReachable.getClient();
        for (String index : fullNames) {
            deleteIndexQuietly(client, index, "test cleanup");
        }

        // Verify deletion
        for (String index : fullNames) {
            boolean exists = client.indices().exists(b -> b.index(index)).value();
            assertThat(exists).isFalse();
        }

        // Pass 2: re-create and verify CREATED status
        List<IndexResult> second = OpenSearchReachable.createSelectedIndexes(sources);
        assertThat(second)
                .isNotEmpty()
                .allSatisfy(r -> assertThat(r.status()).isEqualTo(IndexResult.Status.CREATED));

        // Short names check
        Set<String> seenShort = second.stream().map(result -> result.shortName()).collect(Collectors.toSet());
        assertThat(seenShort).contains("exporter", "settings", "sitemap", "findings", "traffic");
    }

    /**
     * Verifies the lifecycle for the traffic and exporter source combination.
     *
     * <p>The exporter source is included because traffic-only selection now omits the Exporter index.
     * This test ensures both reported indices can be deleted and recreated cleanly.</p>
     */
    @Test
    void create_delete_recreate_singleSource_traffic_viaSink() {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        List<IndexResult> first = OpenSearchReachable.createSelectedIndexes(List.of("traffic", "exporter"));
        assertThat(first).isNotEmpty();

        // Validate expected short names and full names
        for (IndexResult r : first) {
            String expectedFull = IndexNaming.indexNameForShortName(r.shortName());
            assertThat(r.fullName()).isEqualTo(expectedFull);
        }

        // Delete both indices reported (best-effort cleanup of dev cluster)
        OpenSearchClient client2 = OpenSearchReachable.getClient();
        for (IndexResult r : first) {
            deleteIndexQuietly(client2, r.fullName(), "single-source test cleanup");
        }

        // Re-create and verify CREATED status
        List<IndexResult> second = OpenSearchReachable.createSelectedIndexes(List.of("traffic", "exporter"));
        assertThat(second)
                .isNotEmpty()
                .allSatisfy(r -> assertThat(r.status()).isEqualTo(IndexResult.Status.CREATED));
    }

    private static void deleteIndexQuietly(OpenSearchClient client, String index, String context) {
        try {
            client.indices().delete(new DeleteIndexRequest.Builder().index(index).build());
        } catch (IOException | RuntimeException e) {
            Logger.logError("[OpenSearchSinkIT] Failed to delete index during " + context + ": " + index, e);
        }
    }
}
