package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.net.URI;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Shared formatting for search-database HTTP request/response logging.
 *
 * <p>Used by Test Connection probes and bulk failure DEBUG lines so multi-line bodies (HTML gateway
 * pages, JSON errors) stay indented and readable in the Log panel.</p>
 *
 * <p>Protocol reflects actual HTTP version when known; otherwise {@code HTTP (version unknown)}
 * (for example SSL failure before any response).</p>
 *
 * <p>Stateless and thread-safe. Header helpers redact known credential-bearing headers, but
 * arbitrary bodies and exception messages are not secret-scanned.</p>
 */
public final class OpenSearchLogFormat {

    private static final String PROTOCOL_UNKNOWN = "HTTP (version unknown)";

    private OpenSearchLogFormat() {}

    /**
     * Builds a request-line summary with a redacted Basic Authorization label.
     *
     * @param method HTTP method
     * @param path request path
     * @param baseUrl base URL used to derive the Host header
     * @param protocol negotiated protocol, or blank when unknown
     * @param authUsed whether Basic authentication was attached
     * @return request summary containing no raw Basic credentials
     */
    public static String formatRequestForLog(String method, String path, String baseUrl, String protocol, boolean authUsed) {
        return formatRequestForLog(method, path, baseUrl, protocol, authUsed ? "Basic ***" : "");
    }

    /**
     * Builds a request-line summary with a caller-supplied redacted Authorization label.
     *
     * <p>{@code redactedAuthorization} is appended verbatim. Callers must pass only a scheme and
     * redaction marker, never a raw credential or signature.</p>
     *
     * @param method HTTP method
     * @param path request path
     * @param baseUrl base URL used to derive the Host header
     * @param protocol negotiated protocol, or blank when unknown
     * @param redactedAuthorization pre-redacted label, or blank to omit the header
     * @return formatted request summary
     */
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
     * Builds a response string from status, pre-redacted headers, and body.
     *
     * <p>Header lines and body are appended verbatim. Callers must redact sensitive header values
     * with {@link #shouldRedactHeader(String)} before passing them and must decide whether the
     * response body is appropriate to log.</p>
     *
     * @param body response body; {@code null} becomes blank
     * @param protocol negotiated protocol, or blank when unknown
     * @param statusCode HTTP status code
     * @param reasonPhrase HTTP reason phrase; {@code null} becomes blank
     * @param headerLines pre-redacted header lines; empty adds a JSON content-type placeholder
     * @return formatted multi-line response
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

    /**
     * Returns whether a header's value must be redacted in logs.
     *
     * @param name header name; {@code null} is not classified as sensitive
     * @return {@code true} for known credential-, cookie-, or SigV4-bearing headers
     */
    public static boolean shouldRedactHeader(String name) {
        if (name == null) return false;
        String n = name.trim().toLowerCase(java.util.Locale.ROOT);
        return n.equals("authorization")
                || n.equals("proxy-authorization")
                || n.equals("set-cookie")
                || n.equals("cookie")
                || n.equals("x-amz-security-token")
                || n.equals("x-amz-signature");
    }

    /**
     * Extracts an HTTP protocol from a search-client exception chain.
     *
     * <p>Recognizes status-line messages for HTTP/1.1 and HTTP/2.0.</p>
     *
     * @param t exception chain root; may be {@code null}
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

    /**
     * Extracts an HTTP status code from an exception chain.
     *
     * @param t exception chain root; may be {@code null}
     * @return parsed status code, or {@code 500} when unavailable
     */
    public static int parseStatusCodeFromException(Throwable t) {
        if (t == null) return 500;
        String msg = t.getMessage();
        if (msg == null) return parseStatusCodeFromException(t.getCause());
        Matcher m = STATUS_LINE.matcher(msg);
        if (m.find()) return Integer.parseInt(m.group(1));
        return parseStatusCodeFromException(t.getCause());
    }

    /**
     * Extracts an HTTP reason phrase from an exception chain.
     *
     * @param t exception chain root; may be {@code null}
     * @return parsed reason phrase, or {@code Error} when unavailable
     */
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

    /**
     * Prefixes each line for alignment in the log.
     *
     * @param raw request or response text; {@code null} is returned unchanged
     * @return indented text, or the original null/empty value
     */
    public static String indentRaw(String raw) {
        if (raw == null || raw.isEmpty()) return raw;
        return "  " + raw.replace("\n", "\n  ");
    }

    /**
     * Formats an HTTP failure status and response body for DEBUG logs.
     *
     * <p>Puts the status on the first line, then indents the body with {@link #indentRaw(String)}
     * so multi-line HTML gateway pages and JSON errors match Test Connection {@code Response:}
     * formatting instead of flush-left lines that look like new log entries.</p>
     *
     * @param status HTTP status code
     * @param responseBody response entity text; {@code null}/blank yields status only
     * @return status, or status plus indented body
     */
    public static String formatStatusAndIndentedBody(int status, String responseBody) {
        String body = responseBody == null ? "" : responseBody.stripTrailing();
        if (body.isEmpty()) {
            return Integer.toString(status);
        }
        return status + "\n" + indentRaw(body);
    }

    /**
     * Formats a bounded exception chain for transport diagnostics without stack-trace noise.
     *
     * <p>Exception messages are normalized and length-bounded but not secret-redacted. Callers must
     * ensure the exception chain does not contain credentials or request bodies before logging the
     * result.</p>
     *
     * @param failure exception chain root; may be {@code null}
     * @return bounded single-line description
     */
    static String describeExceptionChain(Throwable failure) {
        if (failure == null) {
            return "unknown";
        }
        StringBuilder detail = new StringBuilder(256);
        Throwable current = failure;
        int depth = 0;
        while (current != null && depth < 5) {
            if (detail.length() > 0) {
                detail.append(" <- ");
            }
            detail.append(current.getClass().getSimpleName());
            String message = current.getMessage();
            if (message != null && !message.isBlank()) {
                detail.append(": ").append(message.trim().replace('\n', ' ').replace('\r', ' '));
            }
            Throwable cause = current.getCause();
            if (cause == current) {
                break;
            }
            current = cause;
            depth++;
        }
        if (current != null) {
            detail.append(" <- ...");
        }
        return detail.length() <= 600 ? detail.toString() : detail.substring(0, 597) + "...";
    }
}
