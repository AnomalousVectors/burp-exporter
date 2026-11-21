package ai.anomalousvectors.tools.burp.utils;

import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;

/**
 * Decides whether a URL is in scope for export based on the extension's scope configuration.
 *
 * <p>Stateless and safe for concurrent callers using immutable {@link ConfigState.State}
 * snapshots, such as those returned by
 * {@link ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig#getState()}.</p>
 *
 * <p>Scope type is normalized to lowercase and trimmed so that {@code "Custom"} and
 * {@code "custom"} are treated identically.</p>
 */
public final class ScopeFilter {

    private ScopeFilter() { }

    /**
     * Returns whether the given request should be exported according to the current scope.
     *
     * <p>Scope type "all" exports everything; "burp" uses Burp's in-scope flag; "custom"
     * matches the host, or the full URL when no host can be parsed, against custom regex/string
     * entries (any match includes the URL).
     * Scope type is normalized to lowercase before comparison.</p>
     *
     * @param state       current config state; {@code null} is treated as no export
     * @param url         request URL for custom matching; {@code null} cannot match custom scope
     * @param burpInScope Burp's {@code request.isInScope()} result; used only when
     *                    {@code state.scopeType()} is {@link ConfigKeys#SCOPE_BURP}
     * @return {@code true} if the request is in scope and should be exported
     */
    public static boolean shouldExport(ConfigState.State state, String url, boolean burpInScope) {
        if (state == null) {
            return false;
        }
        String raw = state.scopeType();
        String scopeType = (raw == null || raw.isBlank())
                ? ConfigKeys.SCOPE_ALL
                : raw.trim().toLowerCase(Locale.ROOT);

        return switch (scopeType) {
            case ConfigKeys.SCOPE_BURP -> burpInScope;
            case ConfigKeys.SCOPE_CUSTOM -> url != null && matchesCustom(url, state.customEntries());
            default -> true;
        };
    }

    /**
     * Returns whether the URL matches any custom scope entry.
     *
     * <p>Both STRING and REGEX entries are matched against the URL's <em>host</em> (authority host).
     * STRING uses substring containment; REGEX uses {@link Pattern#compile(String)} and
     * {@link java.util.regex.Matcher#find()}. So {@code acme.com} STRING and {@code ^.*acme\.com$}
     * REGEX both match {@code https://acme.com/foo?param=value}. If the URL has no parseable host,
     * the full URL is used. Invalid regex entries are skipped.</p>
     *
     * @param url     non-null URL string
     * @param entries custom scope entries; {@code null} or empty yields {@code false}
     * @return {@code true} if at least one entry matches
     */
    private static boolean matchesCustom(String url, List<ConfigState.ScopeEntry> entries) {
        if (entries == null || entries.isEmpty()) {
            return false;
        }
        String target = hostFromUrl(url);
        if (target == null) target = url;

        for (ConfigState.ScopeEntry e : entries) {
            String value = e.value();
            if (value == null || value.isBlank()) {
                continue;
            }
            if (e.kind() == ConfigState.Kind.STRING) {
                if (target.contains(value)) return true;
            } else {
                try {
                    if (Pattern.compile(value).matcher(target).find()) return true;
                } catch (Exception ignored) {
                    // invalid regex, skip entry
                }
            }
        }
        return false;
    }

    /**
     * Extracts the host (authority host) from a URL for custom scope matching (STRING and REGEX).
     *
     * @param url full URL; may be {@code null} or blank
     * @return host string, or {@code null} if unparseable or no host
     */
    private static String hostFromUrl(String url) {
        if (url == null || url.isBlank()) return null;
        try {
            URI uri = URI.create(url);
            return uri.getHost();
        } catch (Exception ignored) {
            return null;
        }
    }
}
