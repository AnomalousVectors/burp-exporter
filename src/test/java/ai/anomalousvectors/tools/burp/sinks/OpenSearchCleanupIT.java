package ai.anomalousvectors.tools.burp.sinks;

import java.io.IOException;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;

import ai.anomalousvectors.tools.burp.testutils.OpenSearchReachable;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;

/**
 * Verifies the broad test-cluster cleanup helper independently of test-class ordering.
 *
 * <p>Cleanup is broad only within the fixed exporter test-index prefix on the shared cluster.
 * It quiesces recurring reporters before deletion and leaves other project/platform indexes
 * untouched. {@link OpenSearchCleanupExtension} owns final root cleanup.</p>
 */
@Tag("integration")
@ExtendWith(OpenSearchCleanupExtension.class)
public class OpenSearchCleanupIT {

    @Test
    void cleanupHelper_deletesExporterIndexesFromDedicatedCluster() throws IOException {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        deleteExporterIndexesNow();

        OpenSearchReachable.createSelectedIndexes(java.util.List.of("exporter", "settings", "traffic"));

        OpenSearchClient client = OpenSearchReachable.getClient();
        assertIndexExists(client, IndexNaming.indexNameForShortName("exporter"));
        assertIndexExists(client, IndexNaming.indexNameForShortName("settings"));
        assertIndexExists(client, IndexNaming.indexNameForShortName("traffic"));

        deleteExporterIndexesNow();

        assertIndexMissing(client, IndexNaming.indexNameForShortName("exporter"));
        assertIndexMissing(client, IndexNaming.indexNameForShortName("settings"));
        assertIndexMissing(client, IndexNaming.indexNameForShortName("traffic"));
    }

    /**
     * Deletes the fixed exporter test-index prefix from the shared integration-test cluster.
     *
     * <p>This cleanup is best-effort by design. It first resets recurring exporter lifecycle state
     * and then deletes the current default prefix so later tests start from a clean cluster.</p>
     */
    public static void deleteExporterIndexesNow() {
        try {
            ExportReporterLifecycle.resetForTests();
            OpenSearchClient client = OpenSearchReachable.getClient();
            deletePrefix(client, IndexNaming.INDEX_PREFIX);
        } catch (IOException | RuntimeException ignored) {
            // Best-effort cleanup is verified by the post-build exporter-index inventory.
        }
    }

    private static void deletePrefix(OpenSearchClient client, String prefix) throws IOException {
        client.indices().delete(new DeleteIndexRequest.Builder()
                .index(prefix + "*")
                .allowNoIndices(true)
                .ignoreUnavailable(true)
                .build());
    }

    private static void assertIndexExists(OpenSearchClient client, String indexName) throws IOException {
        boolean exists = client.indices().exists(b -> b.index(indexName)).value();
        org.assertj.core.api.Assertions.assertThat(exists).isTrue();
    }

    private static void assertIndexMissing(OpenSearchClient client, String indexName) throws IOException {
        boolean exists = client.indices().exists(b -> b.index(indexName)).value();
        org.assertj.core.api.Assertions.assertThat(exists).isFalse();
    }
}
