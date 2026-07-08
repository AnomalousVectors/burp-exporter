package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.net.URI;

import org.apache.hc.core5.http.HttpHost;

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
        String normalized = baseUrl == null ? "" : baseUrl.trim().replaceAll("/+$", "");
        URI uri = URI.create(normalized);
        return new HttpHost(uri.getScheme(), uri.getHost(), uri.getPort());
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
