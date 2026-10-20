package ai.anomalousvectors.tools.burp.testutils;

import java.io.IOException;
import java.util.function.Supplier;

import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;

import ai.anomalousvectors.tools.burp.utils.IndexNaming;

/**
 * Bounds a bare-client integration scenario to one fixed disposable index on the shared cluster.
 *
 * <p>Use with try-with-resources so assertion failures still delete the exact owned index and
 * cleanup failures are reported, or suppressed onto the original failure. This scope does not
 * create mappings, close shared transports, or reset exporter state; callers must quiesce their
 * own producers before closing it. Concurrent scenarios must use the same index resource lock.</p>
 */
public final class OpenSearchTestIndex implements AutoCloseable {

    private final String name;
    private final Supplier<OpenSearchClient> clients;

    private OpenSearchTestIndex(String name, Supplier<OpenSearchClient> clients) {
        this.name = name;
        this.clients = clients;
    }

    /**
     * Removes leftovers from one of the five default test indexes and owns its final cleanup.
     *
     * @param shortName exact logical index key, such as {@code traffic}; not a physical name
     * @return scope whose {@link #name()} is independent of mutable runtime naming configuration
     * @throws IllegalArgumentException if the key is not one of the fixed test indexes
     * @throws IOException if initial cleanup fails
     */
    public static OpenSearchTestIndex open(String shortName) throws IOException {
        return open(shortName, OpenSearchReachable::getClient);
    }

    static OpenSearchTestIndex open(String shortName, Supplier<OpenSearchClient> clients) throws IOException {
        if (shortName == null || !IndexNaming.indexKeys().contains(shortName)) {
            throw new IllegalArgumentException("An exact default test index key is required.");
        }
        OpenSearchTestIndex scope = new OpenSearchTestIndex(
                IndexNaming.indexNameForShortName(shortName), clients);
        scope.deleteIndex();
        return scope;
    }

    /** Returns the exact default physical index name owned by this scope. */
    public String name() {
        return name;
    }

    /**
     * Deletes this scope's index, tolerating absence but not transport or authorization failures.
     *
     * @throws IOException if the cluster cannot complete cleanup
     */
    @Override
    public void close() throws IOException {
        deleteIndex();
    }

    private void deleteIndex() throws IOException {
        // A scenario can close the connector cache; never retain its old, closed transport.
        clients.get().indices().delete(new DeleteIndexRequest.Builder()
                .index(name)
                .ignoreUnavailable(true)
                .build());
    }
}
