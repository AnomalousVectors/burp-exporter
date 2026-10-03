package ai.anomalousvectors.tools.burp.utils.search;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Objects;

/**
 * Validated root endpoint for an OpenSearch, Amazon OpenSearch, or Elasticsearch destination.
 *
 * <p>Only absolute HTTP(S) origins are supported. Paths other than the root slash, embedded
 * credentials, queries, and fragments are rejected so every transport constructs requests from
 * the same origin. Instances are immutable and safe for concurrent use.</p>
 */
public final class SearchEndpoint {

    private final URI uri;
    private final String baseUrl;
    private final String authority;

    private SearchEndpoint(URI uri, String baseUrl, String authority) {
        this.uri = uri;
        this.baseUrl = baseUrl;
        this.authority = authority;
    }

    /**
     * Parses and canonicalizes a configured database root URL.
     *
     * <p>Leading and trailing whitespace and one root trailing slash are accepted. Scheme and host
     * casing are normalized, and explicit default ports are omitted. Validation failures never
     * include the supplied value so URL-embedded credentials are not repeated in diagnostics.</p>
     *
     * @param configuredValue configured root URL
     * @return validated canonical endpoint
     * @throws IllegalArgumentException when the value is not a supported database root URL
     */
    public static SearchEndpoint parse(String configuredValue) {
        String value = configuredValue == null ? "" : configuredValue.trim();
        if (value.isEmpty()) {
            throw new IllegalArgumentException("Base URL is required.");
        }

        URI parsed;
        try {
            parsed = new URI(value).parseServerAuthority();
        } catch (URISyntaxException | IllegalArgumentException e) {
            throw new IllegalArgumentException("Base URL is not a valid absolute HTTP(S) URL.", e);
        }

        String scheme = parsed.getScheme();
        if (scheme == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
            throw new IllegalArgumentException("Base URL must use http:// or https://.");
        }
        if (parsed.getRawUserInfo() != null) {
            throw new IllegalArgumentException("Base URL must not include embedded credentials.");
        }
        String host = parsed.getHost();
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("Base URL must include a valid host.");
        }
        if (parsed.getRawQuery() != null) {
            throw new IllegalArgumentException("Base URL must not include a query string.");
        }
        if (parsed.getRawFragment() != null) {
            throw new IllegalArgumentException("Base URL must not include a fragment.");
        }
        String path = parsed.getRawPath();
        if (path != null && !path.isEmpty() && !"/".equals(path)) {
            throw new IllegalArgumentException("Base URL must identify the database root without a path.");
        }

        int port = parsed.getPort();
        String rawAuthority = parsed.getRawAuthority();
        if (port == 0 || port > 65_535 || rawAuthority == null || rawAuthority.endsWith(":")) {
            throw new IllegalArgumentException("Base URL port must be between 1 and 65535.");
        }

        String normalizedScheme = scheme.toLowerCase(Locale.ROOT);
        String normalizedHost = host.toLowerCase(Locale.ROOT);
        int normalizedPort = isDefaultPort(normalizedScheme, port) ? -1 : port;
        String authorityHost = normalizedHost.indexOf(':') >= 0 && !normalizedHost.startsWith("[")
                ? "[" + normalizedHost + "]"
                : normalizedHost;
        String canonicalAuthority = normalizedPort < 0
                ? authorityHost
                : authorityHost + ":" + normalizedPort;
        String canonicalBaseUrl = normalizedScheme + "://" + canonicalAuthority;
        return new SearchEndpoint(URI.create(canonicalBaseUrl), canonicalBaseUrl, canonicalAuthority);
    }

    private static boolean isDefaultPort(String scheme, int port) {
        return ("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443);
    }

    /** Returns the canonical endpoint URI without a trailing slash. */
    public URI uri() {
        return uri;
    }

    /** Returns the canonical root URL used for transport construction and cache identity. */
    public String baseUrl() {
        return baseUrl;
    }

    /** Returns the canonical value safe for endpoint-bearing diagnostic messages. */
    public String displayValue() {
        return baseUrl;
    }

    /** Returns the normalized lowercase URI scheme. */
    public String scheme() {
        return uri.getScheme();
    }

    /** Returns the normalized lowercase host. */
    public String host() {
        return uri.getHost();
    }

    /** Returns the explicit non-default port, or {@code -1} when the scheme default applies. */
    public int port() {
        return uri.getPort();
    }

    /** Returns the effective port, including the HTTP(S) default when no explicit port remains. */
    public int effectivePort() {
        return port() >= 0 ? port() : "https".equals(scheme()) ? 443 : 80;
    }

    /** Returns the canonical host header authority, including a non-default port when configured. */
    public String authority() {
        return authority;
    }

    /**
     * Resolves an absolute request target against this endpoint.
     *
     * @param requestTarget root-relative path with an optional query string
     * @return absolute request URI on this endpoint
     * @throws IllegalArgumentException when the target is not root-relative or contains a fragment
     */
    public URI resolve(String requestTarget) {
        String target = requestTarget == null || requestTarget.isBlank() ? "/" : requestTarget;
        URI relative;
        try {
            relative = new URI(target);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Search request target is not a valid URI path.", e);
        }
        if (!target.startsWith("/") || target.startsWith("//") || relative.isAbsolute()
                || relative.getRawAuthority() != null) {
            throw new IllegalArgumentException("Search request target must be a root-relative path.");
        }
        if (relative.getRawFragment() != null) {
            throw new IllegalArgumentException("Search request target must not include a fragment.");
        }
        return uri.resolve(relative);
    }

    @Override
    public boolean equals(Object other) {
        return this == other || other instanceof SearchEndpoint endpoint && uri.equals(endpoint.uri);
    }

    @Override
    public int hashCode() {
        return Objects.hash(uri);
    }

    @Override
    public String toString() {
        return baseUrl;
    }
}
