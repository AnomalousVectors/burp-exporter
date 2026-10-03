package ai.anomalousvectors.tools.burp.utils.opensearch;

import org.apache.hc.core5.http.HttpHost;

import ai.anomalousvectors.tools.burp.utils.search.SearchEndpoint;

/**
 * Helpers for classic database HTTP requests that must route through a pooled client with
 * explicit host targeting so TLS client-certificate material is applied consistently.
 */
public final class OpenSearchClassicHttpSupport {

    private OpenSearchClassicHttpSupport() {
        throw new AssertionError("No instances");
    }

    /**
     * Resolves the {@link HttpHost} from a configured database base URL.
     *
     * @param baseUrl configured database base URL
     * @return host for classic {@code execute(host, request, ...)} routing
     */
    public static HttpHost hostForBaseUrl(String baseUrl) {
        SearchEndpoint endpoint = SearchEndpoint.parse(baseUrl);
        return new HttpHost(endpoint.scheme(), endpoint.host(), endpoint.port());
    }

    /**
     * Builds the relative bulk path for an index.
     *
     * @param indexName target index name
     * @return path beginning with {@code /}
     */
    public static String bulkPathForIndex(String indexName) {
        String name = indexName == null ? "" : indexName.trim();
        return "/" + name + "/_bulk";
    }
}
