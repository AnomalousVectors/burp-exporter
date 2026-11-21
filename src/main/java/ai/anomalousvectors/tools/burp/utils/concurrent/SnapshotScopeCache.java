package ai.anomalousvectors.tools.burp.utils.concurrent;

import java.util.concurrent.ConcurrentHashMap;

import burp.api.montoya.MontoyaApi;

/**
 * Per-snapshot URL to Burp scope cache safe for parallel document builders.
 */
public final class SnapshotScopeCache {

    private final MontoyaApi api;
    private final ConcurrentHashMap<String, Boolean> inScopeByUrl = new ConcurrentHashMap<>();

    /**
     * Creates an empty cache owned by one snapshot export.
     *
     * @param api Burp API used for cache misses; {@code null} treats every URL as out of scope
     */
    public SnapshotScopeCache(MontoyaApi api) {
        this.api = api;
    }

    /**
     * Returns whether {@code url} is in Burp scope, caching positive and negative answers.
     *
     * <p>Safe for parallel snapshot builders. Cache misses call Burp synchronously; missing scope
     * access or runtime accessor failures are cached as out of scope for this cache's lifetime.</p>
     *
     * @param url URL to check; null or blank is out of scope
     * @return cached or freshly observed Burp scope result
     */
    public boolean isInScope(String url) {
        if (url == null || url.isBlank() || api == null) {
            return false;
        }
        return inScopeByUrl.computeIfAbsent(url, this::lookupScope);
    }

    private boolean lookupScope(String url) {
        try {
            var scope = api.scope();
            return scope != null && scope.isInScope(url);
        } catch (RuntimeException ignored) {
            return false;
        }
    }
}
