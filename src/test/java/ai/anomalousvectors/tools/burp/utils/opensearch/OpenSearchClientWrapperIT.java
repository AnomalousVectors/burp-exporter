package ai.anomalousvectors.tools.burp.utils.opensearch;

import ai.anomalousvectors.tools.burp.sinks.ExportReporterLifecycle;
import ai.anomalousvectors.tools.burp.testutils.OpenSearchReachable;
import ai.anomalousvectors.tools.burp.testutils.OpenSearchTestIndex;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.api.Test;
import com.fasterxml.jackson.databind.JsonNode;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.core.GetRequest;
import org.opensearch.client.opensearch.core.GetResponse;
import org.opensearch.client.opensearch.core.IndexRequest;
import org.opensearch.client.opensearch.core.IndexResponse;
import org.opensearch.client.opensearch.indices.CreateIndexRequest;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for OpenSearch connectivity, index lifecycle, and basic document operations.
 * Uses configured test credentials and only the fixed disposable Traffic index on the shared cluster.
 */
@Tag("integration")
@ResourceLock("traffic-opensearch-index")
class OpenSearchClientWrapperIT {

    @BeforeEach
    @AfterEach
    void resetClientOwners() {
        // Retire pending async closes before another scenario acquires a shared transport.
        ExportReporterLifecycle.resetForTests();
        OpenSearchConnector.closeAll();
    }

    /**
     * Verifies connectivity, index creation, existence check, and cleanup.
     *
     * @throws Exception if an unexpected error occurs during the test
     */
    @Test
    void testConnection_createIndex_verify_delete() throws Exception {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        try (OpenSearchTestIndex testIndex = OpenSearchTestIndex.open("traffic")) {
            String indexName = testIndex.name();
            OpenSearchClient client = OpenSearchReachable.getClient();

            boolean existsBefore = client.indices().exists(b -> b.index(indexName)).value();
            assertThat(existsBefore).isFalse();

            CreateIndexRequest createReq = new CreateIndexRequest.Builder()
                    .index(indexName)
                    .build();
            client.indices().create(createReq);

            boolean existsAfter = client.indices().exists(b -> b.index(indexName)).value();
            assertThat(existsAfter).isTrue();
        }
    }

    /**
     * Verifies indexing and retrieval of a document using the official client.
     * Creates an index, indexes a document, retrieves it, validates contents, and deletes the index.
     *
     * @throws Exception if an unexpected error occurs during the test
     */
    @Test
    void indexDocument_roundTrip_thenDeleteIndex() throws Exception {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        try (OpenSearchTestIndex testIndex = OpenSearchTestIndex.open("traffic")) {
            String indexName = testIndex.name();
            OpenSearchClient client = OpenSearchReachable.getClient();

            client.indices().create(new CreateIndexRequest.Builder().index(indexName).build());

            Map<String, Object> doc = Map.of(
                    "field", "value",
                    "ts", Instant.now().toString()
            );

            IndexRequest<Map<String, Object>> indexReq = new IndexRequest.Builder<Map<String, Object>>()
                    .index(indexName)
                    .id("1")
                    .document(doc)
                    .build();

            IndexResponse indexResp = client.index(indexReq);
            String result = indexResp.result().jsonValue();
            assertThat(result.equalsIgnoreCase("created") || result.equalsIgnoreCase("updated")).isTrue();

            GetResponse<JsonNode> getResp = client.get(
                    new GetRequest.Builder().index(indexName).id("1").build(),
                    JsonNode.class
            );
            assertThat(getResp.found()).isTrue();

            JsonNode source = java.util.Objects.requireNonNull(getResp.source(), "indexed document source");
            assertThat(source.get("field").asText()).isEqualTo("value");
        }
    }
}
