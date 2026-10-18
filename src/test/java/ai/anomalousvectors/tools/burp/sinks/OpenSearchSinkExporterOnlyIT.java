package ai.anomalousvectors.tools.burp.sinks;

import java.io.IOException;
import java.util.EnumSet;
import java.util.List;

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
 * Exercises the Exporter-index lifecycle against a live OpenSearch test cluster.
 *
 * <p>The Exporter index is created through the {@code exporter} source selection. Root-owned
 * cleanup runs after all selected Jupiter tests finish.</p>
 */
@Tag("integration")
@ExtendWith(OpenSearchCleanupExtension.class)
class OpenSearchSinkExporterOnlyIT {

    @Test
    void create_delete_recreate_exporterOnly_viaSink() {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        List<IndexResult> first = OpenSearchReachable.createSelectedIndexes(List.of("exporter"));
        assertThat(first).isNotEmpty();

        EnumSet<IndexResult.Status> allowed = EnumSet.of(IndexResult.Status.CREATED, IndexResult.Status.EXISTS);
        assertThat(first).allSatisfy(r -> assertThat(allowed).contains(r.status()));

        // Validate full name
        for (IndexResult r : first) {
            assertThat(r.shortName()).isEqualTo("exporter");
            assertThat(r.fullName()).isEqualTo(IndexNaming.indexNameForShortName("exporter"));
        }

        // Delete reported index (best-effort cleanup of dev cluster)
        OpenSearchClient client = OpenSearchReachable.getClient();
        for (IndexResult r : first) {
            deleteIndexQuietly(client, r.fullName());
        }

        // Re-create and verify CREATED status
        List<IndexResult> second = OpenSearchReachable.createSelectedIndexes(List.of("exporter"));
        assertThat(second)
                .isNotEmpty()
                .allSatisfy(r -> assertThat(r)
                        .extracting(
                                result -> result.shortName(),
                                result -> result.fullName(),
                                result -> result.status())
                        .containsExactly("exporter", IndexNaming.indexNameForShortName("exporter"), IndexResult.Status.CREATED));
    }

    private static void deleteIndexQuietly(OpenSearchClient client, String index) {
        try {
            client.indices().delete(new DeleteIndexRequest.Builder().index(index).build());
        } catch (IOException | RuntimeException e) {
            Logger.logError("[OpenSearchSinkExporterOnlyIT] Failed to delete index during exporter-only test cleanup: " + index, e);
        }
    }
}
