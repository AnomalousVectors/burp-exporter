package ai.anomalousvectors.tools.burp.utils.opensearch;

import ai.anomalousvectors.tools.burp.utils.Logger;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.nio.AsyncClientConnectionManager;
import org.apache.hc.core5.http.HttpHost;
import org.opensearch.client.json.JsonpMapper;
import org.opensearch.client.json.jackson.JacksonJsonpMapper;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.transport.OpenSearchTransport;
import org.opensearch.client.transport.httpclient5.ApacheHttpClient5TransportBuilder;

import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

/**
 * Factory/cache for OpenSearch clients.
 *
 * <p>Ownership:
 * Clients are cached per base URL (and optional credentials) and reused. Do not close the returned client;
 * lifecycle is managed here.</p>
 */
public final class OpenSearchConnector {

    private static final ConcurrentHashMap<String, OpenSearchClient> clientCache = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, CloseableHttpClient> classicClientCache = new ConcurrentHashMap<>();

    private OpenSearchConnector() {
        throw new AssertionError("No instances");
    }

    /**
     * Returns a cached client for the given base URL, creating it on first use (no auth).
     *
     * @param baseUrl e.g., https://opensearch.url:9200
     * @return shared client
     * @throws OpenSearchClientBuildException when the client cannot be constructed
     */
    public static OpenSearchClient getClient(String baseUrl) {
        return getClient(baseUrl, OpenSearchAuth.none());
    }

    /**
     * Returns a cached client for the given base URL and optional basic-auth credentials.
     * When both username and password are non-null and non-empty, basic auth is configured.
     *
     * @param baseUrl  e.g., https://opensearch.url:9200
     * @param username optional; null or empty to skip auth
     * @param password optional; null or empty to skip auth
     * @return shared client
     * @throws OpenSearchClientBuildException when the client cannot be constructed
     */
    public static OpenSearchClient getClient(String baseUrl, String username, String password) {
        OpenSearchAuth auth = username == null || username.isBlank() || password == null || password.isBlank()
                ? OpenSearchAuth.none()
                : OpenSearchAuth.basic(username, password);
        return getClient(baseUrl, auth);
    }

    /** Returns a cached client for the given base URL and selected auth mode. */
    public static OpenSearchClient getClient(String baseUrl, OpenSearchAuth auth) {
        ConfigState.SearchDestination destination = RuntimeConfig.searchDestinationKind();
        boolean insecure = isInsecureEnabled(destination);
        OpenSearchAuth resolvedAuth = auth == null ? OpenSearchAuth.none() : auth;
        String key = cacheKey(baseUrl, resolvedAuth, insecure,
                OpenSearchTlsSupport.currentTlsMode(destination),
                OpenSearchTlsSupport.pinnedCertificateFingerprint(destination));
        return clientCache.computeIfAbsent(key, k -> buildClient(baseUrl, resolvedAuth, insecure, destination));
    }

    /**
     * Returns a cached classic HTTP client with the same TLS/auth behavior as {@link #getClient}.
     *
     * <p>Used by raw/chunked HTTP paths that call OpenSearch APIs directly, so they stay
     * behaviorally aligned with connector/test-connection.</p>
     */
    static CloseableHttpClient getClassicHttpClient(String baseUrl, String username, String password) {
        OpenSearchAuth auth = username == null || username.isBlank() || password == null || password.isBlank()
                ? OpenSearchAuth.none()
                : OpenSearchAuth.basic(username, password);
        return getClassicHttpClient(baseUrl, auth);
    }

    /**
     * Returns a cached classic HTTP client for the selected database destination.
     *
     * @param baseUrl configured database base URL
     * @param auth resolved authentication descriptor
     * @return pooled classic HTTP client owned by this connector
     */
    public static CloseableHttpClient getClassicHttpClient(String baseUrl, OpenSearchAuth auth) {
        ConfigState.SearchDestination destination = RuntimeConfig.searchDestinationKind();
        boolean insecure = isInsecureEnabled(destination);
        OpenSearchAuth resolvedAuth = auth == null ? OpenSearchAuth.none() : auth;
        String key = cacheKey(baseUrl, resolvedAuth, insecure,
                OpenSearchTlsSupport.currentTlsMode(destination),
                OpenSearchTlsSupport.pinnedCertificateFingerprint(destination));
        return classicClientCache.computeIfAbsent(
                key, k -> buildClassicClient(baseUrl, resolvedAuth, insecure, destination));
    }

    private static final String INSECURE_PROP = "OPENSEARCH_INSECURE";

    static boolean isInsecureEnabled() {
        return isInsecureEnabled(ConfigState.SearchDestination.OPEN_SEARCH);
    }

    static boolean isInsecureEnabled(ConfigState.SearchDestination destination) {
        return "true".equalsIgnoreCase(System.getProperty(INSECURE_PROP, "").trim())
                || OpenSearchTlsSupport.isInsecureMode(destination);
    }

    private static String cacheKey(String baseUrl, OpenSearchAuth auth,
                                   boolean insecure, String tlsMode, String pinnedFingerprint) {
        String authKey = auth == null ? OpenSearchAuth.none().cacheKey() : auth.cacheKey();
        return baseUrl + "|" + authKey + "|insecure=" + insecure + "|tls=" + tlsMode + "|pin=" + pinnedFingerprint;
    }

    private static OpenSearchClient buildClient(
            String baseUrl,
            OpenSearchAuth auth,
            boolean insecure,
            ConfigState.SearchDestination destination) {
        try {
            URI uri = URI.create(baseUrl);
            HttpHost host = new HttpHost(uri.getScheme(), uri.getHost(), uri.getPort());
            JsonpMapper mapper = new JacksonJsonpMapper();

            ApacheHttpClient5TransportBuilder builder = ApacheHttpClient5TransportBuilder
                    .builder(host)
                    .setMapper(mapper);
            builder.setDefaultHeaders(auth.defaultHeaders());

            boolean useHttps = "https".equalsIgnoreCase(uri.getScheme());

            builder.setHttpClientConfigCallback(httpBuilder -> {
                PoolingAsyncClientConnectionManagerBuilder connManagerBuilder =
                        PoolingAsyncClientConnectionManagerBuilder.create();
                if (useHttps) {
                    try {
                        OpenSearchHttpTlsSupport.configureAsyncTls(connManagerBuilder, auth, insecure, destination);
                    } catch (IOException | GeneralSecurityException e) {
                        throw new OpenSearchClientBuildException("Failed to build OpenSearch TLS context", e);
                    }
                } else {
                    connManagerBuilder.setDefaultTlsConfig(org.apache.hc.client5.http.config.TlsConfig.custom()
                            .setVersionPolicy(org.apache.hc.core5.http2.HttpVersionPolicy.NEGOTIATE)
                            .build());
                }
                AsyncClientConnectionManager connManager = connManagerBuilder.build();
                httpBuilder.setConnectionManager(connManager);
                return httpBuilder;
            });

            OpenSearchTransport transport = builder.build();
            return new OpenSearchClient(transport);
        } catch (RuntimeException e) {
            throw new OpenSearchClientBuildException("Failed to build OpenSearch client for " + baseUrl, e);
        }
    }

    private static CloseableHttpClient buildClassicClient(
            String baseUrl, OpenSearchAuth auth, boolean insecure, ConfigState.SearchDestination destination) {
        try {
            URI uri = URI.create(baseUrl);
            boolean useHttps = "https".equalsIgnoreCase(uri.getScheme());

            PoolingHttpClientConnectionManagerBuilder connManagerBuilder =
                    PoolingHttpClientConnectionManagerBuilder.create();
            if (useHttps) {
                OpenSearchHttpTlsSupport.configureClassicTls(connManagerBuilder, auth, insecure, destination);
            } else {
                connManagerBuilder.setDefaultTlsConfig(org.apache.hc.client5.http.config.TlsConfig.custom()
                        .setVersionPolicy(org.apache.hc.core5.http2.HttpVersionPolicy.NEGOTIATE)
                        .build());
            }

            var httpBuilder = HttpClients.custom()
                    .setConnectionManager(connManagerBuilder.build());
            org.apache.hc.core5.http.Header[] defaultHeaders = auth.defaultHeaders();
            if (defaultHeaders.length > 0) {
                httpBuilder.setDefaultHeaders(Arrays.asList(defaultHeaders));
            }
            return httpBuilder.build();
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            throw new OpenSearchClientBuildException(
                    "Failed to build classic OpenSearch HTTP client for " + baseUrl, e);
        }
    }

    /**
     * Closes every cached OpenSearch client and classic HTTP client, then clears both caches.
     *
     * <p>Each client owns a pooled connection manager, TLS session cache, and reactor/scheduler
     * threads that hold substantial off-heap state (direct {@code ByteBuffer}s, SSL session state).
     * Because the caches are {@code static}, those resources outlive any Stop/Start cycle unless
     * this method runs; otherwise they are released only on extension unload via classloader GC.</p>
     *
     * <p>Close exceptions are logged at debug and swallowed so a single misbehaving client cannot
     * prevent the other entries from being released. The method is idempotent: subsequent calls
     * on an already-empty cache are no-ops, and a later {@link #getClient(String)} rebuilds a
     * fresh client rather than returning a closed one.</p>
     */
    public static void closeAll() {
        AtomicInteger failures = new AtomicInteger();

        // Drain entries out of each cache *before* closing them. If we instead closed-then-cleared,
        // a concurrent getClient(...) call (e.g., the async stop-reclaim thread racing with a later
        // request) could observe an entry whose transport was already closed and return that
        // instance to the caller, surfacing as "Connection pool shut down" on the next request.
        List<Map.Entry<String, OpenSearchClient>> drainedClients = new ArrayList<>(clientCache.entrySet());
        clientCache.clear();
        for (Map.Entry<String, OpenSearchClient> entry : drainedClients) {
            try {
                entry.getValue()._transport().close();
            } catch (IOException | RuntimeException e) {
                failures.incrementAndGet();
                Logger.logDebug("[OpenSearch] OpenSearchConnector failed to close transport for "
                        + redactKey(entry.getKey()) + ": "
                        + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            }
        }

        List<Map.Entry<String, CloseableHttpClient>> drainedClassic = new ArrayList<>(classicClientCache.entrySet());
        classicClientCache.clear();
        for (Map.Entry<String, CloseableHttpClient> entry : drainedClassic) {
            try {
                entry.getValue().close();
            } catch (IOException | RuntimeException e) {
                failures.incrementAndGet();
                Logger.logDebug("[OpenSearch] OpenSearchConnector failed to close classic client for "
                        + redactKey(entry.getKey()) + ": "
                        + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            }
        }

        // Per-client failures land in the debug log (high-frequency tabs only). Promote a single
        // aggregate WARN to the panel so an operator who unloads the extension still sees that
        // not every cached client closed cleanly, without having to enable debug logging.
        int total = failures.get();
        if (total > 0) {
            Logger.logWarnPanelOnly("[OpenSearch] closeAll: " + total
                    + " cached client(s) failed to close cleanly; see debug log for details.");
        }
    }

    /**
     * Strips the credential segment from a cache key so it is safe to log. Package-private so
     * the redaction contract can be exercised directly without forcing real connection failures.
     */
    static String redactKey(String key) {
        if (key == null) {
            return "null";
        }
        int firstPipe = key.indexOf('|');
        if (firstPipe < 0) {
            return key;
        }
        int insecureMarker = key.indexOf("|insecure=");
        if (insecureMarker < 0 || insecureMarker <= firstPipe) {
            return key.substring(0, firstPipe);
        }
        return key.substring(0, firstPipe) + key.substring(insecureMarker);
    }
}
