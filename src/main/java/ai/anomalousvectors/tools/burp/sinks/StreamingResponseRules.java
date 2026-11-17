package ai.anomalousvectors.tools.burp.sinks;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ai.anomalousvectors.tools.burp.utils.Logger;
import burp.api.montoya.MontoyaApi;

/** Reads, but never changes, Burp's project-level streaming URL selection. */
final class StreamingResponseRules {
    private final List<Rule> rules;

    private StreamingResponseRules(List<Rule> rules) {
        this.rules = List.copyOf(rules);
    }

    static StreamingResponseRules empty() {
        return new StreamingResponseRules(List.of());
    }

    static StreamingResponseRules read(MontoyaApi api) {
        try {
            if (api.burpSuite() == null) return empty();
            String json = api.burpSuite().exportProjectOptionsAsJson(
                    "project_options.http.streaming_responses");
            if (json == null) return empty();
            return parse(json);
        } catch (RuntimeException e) {
            Logger.logWarnPanelOnly("[StreamingRecovery] Streaming URL settings could not be read; "
                    + "automatic recovery is limited to recognized SSE responses.");
            return empty();
        }
    }

    static StreamingResponseRules parse(String json) {
        try {
            JsonNode root = new ObjectMapper().readTree(json);
            JsonNode settings = root.path("project_options").path("http").path("streaming_responses");
            if (settings.isMissingNode()) throw new IllegalArgumentException("Streaming settings unavailable");
            List<Rule> rules = new ArrayList<>();
            for (JsonNode entry : settings.path("urls")) {
                if (!entry.path("enabled").asBoolean(true)) continue;
                if (entry.isTextual()) {
                    rules.add(new Rule(Pattern.compile(entry.asText()), null, null, null, null));
                } else if (entry.has("prefix")) {
                    rules.add(new Rule(prefixPattern(entry.path("prefix").asText(),
                            entry.path("include_subdomains").asBoolean(false)),
                            null, null, null, null));
                } else if (entry.has("url")) {
                    rules.add(new Rule(Pattern.compile(entry.path("url").asText()), null, null, null, null));
                } else if (entry.has("host") || entry.has("protocol")
                        || entry.has("port") || entry.has("file")) {
                    String host = entry.path("host").asText();
                    if (host.matches("[0-9.:/-]+") && (host.contains("/") || host.contains("-"))) {
                        throw new IllegalArgumentException("IP-range streaming rules are unsupported");
                    }
                    rules.add(new Rule(null, Pattern.compile(entry.path("host").asText(".*")),
                            Pattern.compile(entry.path("file").asText(".*")),
                            Pattern.compile(entry.path("port").asText(".*")),
                            entry.path("protocol").asText("any")));
                } else {
                    throw new IllegalArgumentException("Unsupported streaming URL rule");
                }
                if (rules.size() > 1024) throw new IllegalArgumentException("Streaming rule capacity");
            }
            if (!settings.path("store").asBoolean(true)) {
                Logger.logWarnPanelOnly("[StreamingRecovery] Burp is not storing streaming responses; "
                        + "History-backed response recovery may be unavailable.");
            }
            return new StreamingResponseRules(rules);
        } catch (java.io.IOException e) {
            throw new IllegalArgumentException("Invalid streaming settings", e);
        }
    }

    boolean matches(String url) {
        if (url == null) return false;
        try {
            URI uri = URI.create(url);
            // Burp's advanced File matcher excludes query strings.
            String file = uri.getRawPath();
            int port = uri.getPort() >= 0 ? uri.getPort() : "https".equals(uri.getScheme()) ? 443 : 80;
            for (Rule rule : rules) {
                if (rule.url != null && rule.url.matcher(url).find()) return true;
                if (rule.host != null && uri.getHost() != null && rule.host.matcher(uri.getHost()).find()
                        && rule.file.matcher(file).find() && rule.port.matcher(Integer.toString(port)).find()
                        && ("any".equals(rule.protocol) || rule.protocol.equalsIgnoreCase(uri.getScheme()))) return true;
            }
        } catch (IllegalArgumentException e) {
            return false;
        }
        return false;
    }

    private static Pattern prefixPattern(String prefix, boolean subdomains) {
        boolean explicitScheme = prefix.contains("://");
        URI uri = URI.create(explicitScheme ? prefix : "https://" + prefix);
        String host = uri.getHost();
        if (host == null || uri.getRawUserInfo() != null) {
            throw new IllegalArgumentException("Unsupported streaming URL prefix");
        }
        String scheme = explicitScheme ? Pattern.quote(uri.getScheme()) : "https?";
        String domain = subdomains && !host.contains(":") ? "(?:[^./:]+\\.)*" : "";
        String authority = domain + Pattern.quote(host)
                + (uri.getPort() >= 0 ? ":" + uri.getPort() : "");
        String path = uri.getRawPath() == null ? "" : uri.getRawPath();
        String query = uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery();
        return Pattern.compile("^(?i:" + scheme + "://" + authority + ")"
                + Pattern.quote(path + query));
    }

    private record Rule(Pattern url, Pattern host, Pattern file, Pattern port, String protocol) { }
}
