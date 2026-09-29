package ai.anomalousvectors.tools.burp.utils;

import burp.api.montoya.MontoyaApi;

/**
 * Caches stable Burp metadata used by async exporters.
 *
 * <p>Background reporters should prefer this helper over probing Burp sub-APIs on every
 * export cycle. That avoids repeated lifecycle-sensitive calls during extension startup,
 * shutdown, or project transitions, while still allowing the cache to be primed from a known
 * good {@link MontoyaApi} instance.</p>
 */
public final class BurpRuntimeMetadata {
    /** Stable fallback project identifier used when Burp does not expose a project id. */
    public static final String UNKNOWN_PROJECT_ID = "unknown-project";

    private static volatile String burpVersion;
    private static volatile String projectId;

    private BurpRuntimeMetadata() {}

    /**
     * Primes cached metadata from the provided API when values are not already known.
     *
     * <p>Safe to call multiple times. Runtime failures are ignored because callers use this
     * helper to avoid turning lifecycle races into user-visible errors. Fatal JVM errors remain
     * visible to the host.</p>
     *
     * @param api current Montoya API handle; ignored when {@code null}
     */
    public static void prime(MontoyaApi api) {
        if (api == null) {
            return;
        }
        if (burpVersion == null) {
            String resolvedVersion = resolveBurpVersion(api);
            if (resolvedVersion != null) {
                burpVersion = resolvedVersion;
            }
        }
        if (projectId == null) {
            String resolvedProjectId = resolveProjectId(api);
            if (resolvedProjectId != null) {
                projectId = resolvedProjectId;
            }
        }
    }

    /**
     * Returns the cached Burp version, resolving it lazily when needed.
     *
     * <p>When the value cannot be resolved safely, returns {@code null}.</p>
     *
     * @return Burp version string, or {@code null} when unavailable
     */
    public static String burpVersion() {
        String cached = burpVersion;
        if (cached != null) {
            return cached;
        }
        MontoyaApi api = MontoyaApiProvider.get();
        if (api == null) {
            return null;
        }
        String resolved = resolveBurpVersion(api);
        if (resolved != null) {
            burpVersion = resolved;
        }
        return resolved;
    }

    /**
     * Returns the cached Burp project id, resolving it lazily when needed.
     *
     * <p>When the value cannot be resolved safely, returns {@code null}.</p>
     *
     * @return Burp project id, or {@code null} when unavailable
     */
    public static String projectId() {
        String cached = projectId;
        if (cached != null) {
            return cached;
        }
        MontoyaApi api = MontoyaApiProvider.get();
        if (api == null) {
            return null;
        }
        String resolved = resolveProjectId(api);
        if (resolved != null) {
            projectId = resolved;
        }
        return resolved;
    }

    /** Returns the cached project id, or a stable fallback label when unavailable. */
    public static String projectIdOrUnknown() {
        String resolved = projectId();
        return resolved == null || resolved.isBlank() ? UNKNOWN_PROJECT_ID : resolved;
    }

    /** Clears all cached metadata. */
    public static void clear() {
        burpVersion = null;
        projectId = null;
    }

    private static String resolveBurpVersion(MontoyaApi api) {
        try {
            var burpSuite = api.burpSuite();
            if (burpSuite == null) {
                return null;
            }
            var version = burpSuite.version();
            return version != null ? String.valueOf(version) : null;
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static String resolveProjectId(MontoyaApi api) {
        try {
            var project = api.project();
            if (project == null) {
                return null;
            }
            return project.id();
        } catch (RuntimeException ignored) {
            return null;
        }
    }
}
