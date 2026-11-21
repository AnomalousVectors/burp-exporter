package ai.anomalousvectors.tools.burp.testutils;

import ai.anomalousvectors.tools.burp.utils.search.SearchClientWrapper;

/**
 * Caches reachability for the OpenSearch instance used by integration tests.
 *
 * <p>URL and optional credentials come from {@link OpenSearchTestConfig}. The first reachability
 * check performs one connection attempt per JVM, and later callers reuse the cached result so
 * integration tests can skip quickly when the cluster is unavailable.</p>
 */
public final class OpenSearchReachable {

    /** Base URL snapshot resolved when this helper class is first loaded. */
    public static final String BASE_URL = OpenSearchTestConfig.get().baseUrl();

    private static volatile Boolean cached = null;

    private OpenSearchReachable() {}

    /** Returns the configured OpenSearch base URL. */
    public static String getBaseUrl() {
        return OpenSearchTestConfig.get().baseUrl();
    }

    /** Returns the configured basic-auth username, or {@code null} when auth is disabled. */
    public static String getUsername() {
        return OpenSearchTestConfig.get().username();
    }

    /** Returns the configured basic-auth password, or {@code null} when auth is disabled. */
    public static String getPassword() {
        return OpenSearchTestConfig.get().password();
    }

    /**
     * Returns an OpenSearch client using the configured test-cluster URL and credentials.
     *
     * @return client for the configured integration-test cluster
     */
    public static org.opensearch.client.opensearch.OpenSearchClient getClient() {
        OpenSearchTestConfig c = OpenSearchTestConfig.get();
        return ai.anomalousvectors.tools.burp.utils.search.SearchConnector.getClient(
                c.baseUrl(), c.username(), c.password());
    }

    /**
     * Creates the indices required by the selected sources using test-cluster credentials.
     *
     * @param selectedSources selected exporter source keys
     * @return index-creation results from {@link ai.anomalousvectors.tools.burp.sinks.SearchSink}
     */
    public static java.util.List<ai.anomalousvectors.tools.burp.sinks.SearchSink.IndexResult> createSelectedIndexes(
            java.util.List<String> selectedSources) {
        OpenSearchTestConfig c = OpenSearchTestConfig.get();
        return ai.anomalousvectors.tools.burp.sinks.SearchSink.createSelectedIndexes(
                c.baseUrl(), selectedSources, c.username(), c.password());
    }

    /**
     * Creates one index from the bundled mapping resource using test-cluster credentials.
     *
     * @param shortName index short name such as {@code traffic}
     * @return index-creation result
     */
    public static ai.anomalousvectors.tools.burp.sinks.SearchSink.IndexResult createIndexFromResource(String shortName) {
        OpenSearchTestConfig c = OpenSearchTestConfig.get();
        return ai.anomalousvectors.tools.burp.sinks.SearchSink.createIndexFromResource(
                c.baseUrl(), shortName, null, c.username(), c.password());
    }

    /**
     * Returns whether the OpenSearch dev cluster at {@link #BASE_URL} is reachable.
     *
     * <p>Credentials from {@link OpenSearchTestConfig} are used when configured. The first call
     * performs the actual connection test; subsequent calls return the cached result.</p>
     */
    public static synchronized boolean isReachable() {
        if (cached == null) {
            OpenSearchTestConfig config = OpenSearchTestConfig.get();
            cached = SearchClientWrapper.testConnection(
                    config.baseUrl(), config.username(), config.password()).success();
        }
        return cached;
    }
}
