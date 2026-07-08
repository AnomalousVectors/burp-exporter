package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.net.URI;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Shared formatting for OpenSearch HTTP request/response logging (Test Connection only).
 * Produces one log entry per request and per response, with indented raw content from the wire.
 * Protocol reflects actual HTTP version when known; otherwise "HTTP (version unknown)" (e.g. SSL failure before any response).
 */
public final class OpenSearchLogFormat {

    private static final String PROTOCOL_UNKNOWN = "HTTP (version unknown)";

    private OpenSearchLogFormat() {}

    /**
     * Builds the actual request as sent for logging: request line, Host, and redacted Authorization when auth was used.
     * Use for Test Connection so the log reflects what was on the wire (with credentials redacted).
     */
    public static String formatRequestForLog(String method, String path, String baseUrl, String protocol, boolean authUsed) {
        return formatRequestForLog(method, path, baseUrl, protocol, authUsed ? "Basic ***" : "");
    }

    /** Builds the actual request as sent for logging with the supplied redacted Authorization value. */
    public static String formatRequestForLog(
            String method, String path, String baseUrl, String protocol, String redactedAuthorization) {
        String proto = protocol != null && !protocol.isBlank() ? protocol : PROTOCOL_UNKNOWN;
        try {
            URI uri = URI.create(baseUrl.replaceFirst("^\\s+", "").trim());
            String host = uri.getHost() != null ? uri.getHost() : "";
            if (uri.getPort() > 0 && uri.getPort() != (uri.getScheme() != null && "https".equals(uri.getScheme()) ? 443 : 80)) {
                host = host + ":" + uri.getPort();
            }
            StringBuilder sb = new StringBuilder();
            sb.append(method).append(" ").append(path).append(" ").append(proto).append("\nHost: ").append(host);
            if (redactedAuthorization != null && !redactedAuthorization.isBlank()) {
                sb.append("\nAuthorization: ").append(redactedAuthorization);
            }
            return sb.toString();
        } catch (Exception e) {
            StringBuilder sb = new StringBuilder();
            sb.append(method).append(" ").append(path).append(" ").append(proto);
            if (redactedAuthorization != null && !redactedAuthorization.isBlank()) {
                sb.append("\nAuthorization: ").append(redactedAuthorization);
            }
            return sb.toString();
        }
    }

    /**
     * Builds a response string from real status and headers (redacted). Use for Test Connection.
     * If headerLines is null or empty, omits header block and uses only status line + body.
     */
    public static String buildRawResponseWithHeaders(String body, String protocol, int statusCode, String reasonPhrase, List<String> headerLines) {
        String proto = protocol != null && !protocol.isBlank() ? protocol : PROTOCOL_UNKNOWN;
        String b = (body != null ? body : "").stripTrailing();
        StringBuilder sb = new StringBuilder();
        sb.append(proto).append(" ").append(statusCode).append(" ").append(reasonPhrase != null ? reasonPhrase : "");
        if (headerLines != null && !headerLines.isEmpty()) {
            for (String line : headerLines) {
                sb.append("\n").append(line);
            }
        } else {
            sb.append("\nContent-Type: application/json");
        }
        sb.append("\n\n").append(b);
        return sb.toString();
    }

    /** Returns true for header names that should have their value redacted in logs (e.g. Authorization, Set-Cookie). */
    public static boolean shouldRedactHeader(String name) {
        if (name == null) return false;
        String n = name.trim().toLowerCase(java.util.Locale.ROOT);
        return n.equals("authorization") || n.equals("proxy-authorization") || n.equals("set-cookie") || n.equals("cookie");
    }

    /**
     * Extracts the HTTP protocol from an OpenSearch/HttpClient exception message when present.
     * e.g. "status line [HTTP/2.0 401 Unauthorized]" -> "HTTP/2.0"; "status line [HTTP/1.1 200 OK]" -> "HTTP/1.1".
     * @return protocol string or null if not found
     */
    public static String parseProtocolFromException(Throwable t) {
        if (t == null) return null;
        String msg = t.getMessage();
        if (msg == null) return parseProtocolFromException(t.getCause());
        Matcher m = Pattern.compile("(?i)status\\s+line\\s+\\[(HTTP/1\\.1|HTTP/2\\.0)\\s+").matcher(msg);
        if (m.find()) return m.group(1);
        return parseProtocolFromException(t.getCause());
    }

    private static final Pattern STATUS_LINE = Pattern.compile("(?i)status\\s+line\\s+\\[(?:HTTP/[^\\s]+)\\s+(\\d+)\\s+([^\\]]*)\\]");

    /** Extracts status code from exception; returns 500 if not parseable. */
    public static int parseStatusCodeFromException(Throwable t) {
        if (t == null) return 500;
        String msg = t.getMessage();
        if (msg == null) return parseStatusCodeFromException(t.getCause());
        Matcher m = STATUS_LINE.matcher(msg);
        if (m.find()) return Integer.parseInt(m.group(1));
        return parseStatusCodeFromException(t.getCause());
    }

    /** Extracts reason phrase from exception (e.g. "Unauthorized" from "status line [HTTP/2.0 401 Unauthorized]"). */
    public static String parseReasonFromException(Throwable t) {
        if (t == null) return "Error";
        String msg = t.getMessage();
        if (msg == null) return parseReasonFromException(t.getCause());
        Matcher m = STATUS_LINE.matcher(msg);
        if (m.find()) {
            String r = m.group(2);
            return r != null && !r.isBlank() ? r.trim() : "Error";
        }
        return parseReasonFromException(t.getCause());
    }

    /** Prefixes each line so raw request/response aligns with wrapped-line indent in the log. */
    public static String indentRaw(String raw) {
        if (raw == null || raw.isEmpty()) return raw;
        return "  " + raw.replace("\n", "\n  ");
    }
}
