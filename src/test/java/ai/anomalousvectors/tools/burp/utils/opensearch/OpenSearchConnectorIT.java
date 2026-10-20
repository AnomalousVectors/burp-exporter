package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.indices.CreateIndexRequest;

import ai.anomalousvectors.tools.burp.sinks.ExportReporterLifecycle;
import ai.anomalousvectors.tools.burp.testutils.OpenSearchReachable;
import ai.anomalousvectors.tools.burp.testutils.OpenSearchTestIndex;
import ai.anomalousvectors.tools.burp.testutils.OpenSearchTestConfig;

/**
 * Live-cluster integration coverage of {@link OpenSearchConnector#closeAll()}.
 *
 * <p>Complements {@link OpenSearchConnectorTest}, which exercises identity/cache contracts
 * against a never-connected dummy URL. This test verifies that a real Apache HC5 transport
 * survives a close-and-rebuild cycle: after {@code closeAll()} the next {@code getClient(...)}
 * call must yield a fresh, working client whose connection pool is not "shut down".</p>
 */
@Tag("integration")
@ResourceLock("traffic-opensearch-index")
class OpenSearchConnectorIT {

    @BeforeEach
    @AfterEach
    void resetClientOwners() {
        // Retire pending async closes before another scenario acquires a shared transport.
        ExportReporterLifecycle.resetForTests();
        OpenSearchConnector.closeAll();
    }

    @Test
    void closeAll_thenGetClient_rebuildsWorkingTransport() throws Exception {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        OpenSearchTestConfig config = OpenSearchTestConfig.get();
        try (OpenSearchTestIndex testIndex = OpenSearchTestIndex.open("traffic")) {
            String indexName = testIndex.name();
            // Prime the cache with a working transport, then exercise it once so the pool is warm.
            OpenSearchClient before = OpenSearchConnector.getClient(
                    config.baseUrl(), config.username(), config.password());
            before.indices().create(new CreateIndexRequest.Builder().index(indexName).build());

            // Close everything: this is the path Stop fires asynchronously and Unload fires
            // synchronously. After this call, the cache must be empty and the next getClient(...)
            // must rebuild a new transport rather than hand out a closed one.
            OpenSearchConnector.closeAll();

            OpenSearchClient after = OpenSearchConnector.getClient(
                    config.baseUrl(), config.username(), config.password());
            assertThat(after).isNotSameAs(before);

            boolean exists = after.indices().exists(b -> b.index(indexName)).value();
            assertThat(exists).isTrue();
        }
    }

    @Test
    void closeAll_isIdempotent_againstLiveCluster() {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        OpenSearchTestConfig config = OpenSearchTestConfig.get();

        // Prime the cache, close, close again. No call should throw, and a follow-up getClient(...)
        // must still yield a usable client. This guards the Stop-then-Unload path from regressing
        // into a NullPointerException, IllegalStateException, or "pool already shut down" surface.
        OpenSearchConnector.getClient(config.baseUrl(), config.username(), config.password());
        assertThatCode(OpenSearchConnector::closeAll).doesNotThrowAnyException();
        assertThatCode(OpenSearchConnector::closeAll).doesNotThrowAnyException();

        OpenSearchClient rebuilt = OpenSearchConnector.getClient(
                config.baseUrl(), config.username(), config.password());
        assertThat(rebuilt).isNotNull();
    }
}
