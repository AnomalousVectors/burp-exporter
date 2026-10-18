package ai.anomalousvectors.tools.burp.sinks;

import java.io.IOException;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.TimeUnit;

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
 * Integration test: create/delete/recreate subset of indices.
 * Root-owned cleanup runs after all selected Jupiter tests finish.
 */
@Tag("integration")
@ExtendWith(OpenSearchCleanupExtension.class)
class OpenSearchSinkSubsetIT {

    private static final int WAIT_AFTER_DELETE_MS = 500;
    private static final int POLL_EXISTS_MAX_MS = 5_000;
    private static final int POLL_INTERVAL_MS = 100;

    @Test
    void create_delete_recreate_subset_settings_and_traffic() throws InterruptedException, IOException {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        List<String> sources = List.of("settings", "traffic", "exporter");

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
        OpenSearchClient client = OpenSearchReachable.getClient();
        for (IndexResult r : first) {
            try {
                client.indices().delete(new DeleteIndexRequest.Builder().index(r.fullName()).build());
            } catch (IOException | RuntimeException e) {
                Logger.logError("[OpenSearchSinkSubsetIT] Failed to delete index during subset test cleanup: " + r.fullName(), e);
            }
        }

        // Wait for deletes to be visible before re-create
        TimeUnit.MILLISECONDS.sleep(WAIT_AFTER_DELETE_MS);
        for (IndexResult r : first) {
            waitForIndexAbsent(client, r.fullName());
        }

        // Pass 2: re-create and verify CREATED status
        List<IndexResult> second = OpenSearchReachable.createSelectedIndexes(sources);
        assertThat(second)
                .isNotEmpty()
                .allSatisfy(r -> assertThat(r.status()).isEqualTo(IndexResult.Status.CREATED));
    }

    /**
     * Polls the dev cluster until the supplied index is absent or the deadline elapses.
     * Encapsulates the retry loop so the sleep-in-loop pattern is confined to this helper.
     */
    private static void waitForIndexAbsent(OpenSearchClient client, String fullName)
            throws IOException, InterruptedException {
        long deadline = System.currentTimeMillis() + POLL_EXISTS_MAX_MS;
        while (client.indices().exists(b -> b.index(fullName)).value()
                && System.currentTimeMillis() < deadline) {
            TimeUnit.MILLISECONDS.sleep(POLL_INTERVAL_MS);
        }
    }
}
