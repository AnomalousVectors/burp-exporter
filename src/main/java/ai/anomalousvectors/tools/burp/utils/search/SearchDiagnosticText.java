package ai.anomalousvectors.tools.burp.utils.search;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.SecureCredentialStore;

/**
 * Normalizes untrusted search-destination text before it reaches operator diagnostics.
 *
 * <p>Search databases and intermediary gateways can return captured field values, credentials,
 * multi-line text, or very large bodies in normal error responses. This boundary applies known
 * credential redaction and UTF-8 byte limits before a message reaches the shared logging listener
 * bus. It does not claim to discover arbitrary secrets.</p>
 *
 * <p>Stateless and thread-safe. Credential values are read from the in-memory session store only
 * while constructing a diagnostic string and are never retained by this class.</p>
 */
public final class SearchDiagnosticText {

    /** Maximum UTF-8 bytes retained from a response body. */
    public static final int RESPONSE_BODY_PREVIEW_BYTES = 4 * 1024;

    /** Maximum UTF-8 bytes emitted for one complete response diagnostic. */
    public static final int RESPONSE_DIAGNOSTIC_BYTES = 8 * 1024;

    private static final int MAX_SOURCE_CHARS = 16 * 1024;
    private static final String REDACTED = "***";
    private static final String TRUNCATED = "... [truncated]";
    private static final String TOKEN_CHARACTER = "[\\p{L}\\p{N}._~+/@=\\-]";

    private static final Pattern AUTHORIZATION_SCHEME = Pattern.compile(
            "(?i)(\\b(?:basic|bearer|apikey)\\s+)([^\\s,;]+)");
    private static final Pattern SENSITIVE_HEADER = Pattern.compile(
            "(?im)^((?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|"
                    + "x-amz-security-token|x-amz-signature)\\s*:)\\s*.*$");
    private static final Pattern SENSITIVE_INLINE_HEADER = Pattern.compile(
            "(?i)(\\b(?:x-api-key|x-auth-token|x-amz-security-token|x-amz-signature)\\s*:\\s*)"
                    + "([^\\s,;]+)");
    private static final Pattern SENSITIVE_JSON_FIELD = Pattern.compile(
            "(?i)([\\\"](?:password|passwd|passphrase|api[_-]?key|apikey|client[_-]?secret|"
                    + "bearer[_-]?token|token|session[_-]?token|secret[_-]?access[_-]?key|"
                    + "access[_-]?key[_-]?id|authorization)"
                    + "[\\\"]\\s*:\\s*[\\\"])([^\\\"]*)([\\\"])");
    private static final Pattern SENSITIVE_PARAMETER = Pattern.compile(
            "(?i)((?:^|[?&;\\s])(?:password|passwd|passphrase|api[_-]?key|apikey|client[_-]?secret|"
                    + "bearer[_-]?token|token|session[_-]?token|secret[_-]?access[_-]?key|"
                    + "access[_-]?key[_-]?id|authorization|x-amz-credential|x-amz-signature|"
                    + "x-amz-security-token)"
                    + "\\s*=\\s*)([^&;\\s]+)");
    private static final Pattern FIELD_VALUE_PREVIEW = Pattern.compile(
            "(?i)(preview of field(?:'s)? value\\s*:\\s*)(?:\\[[^\\]]*]|\\\"[^\\\"]*\\\"|'[^']*'|\\S+)");

    private SearchDiagnosticText() {
        throw new AssertionError("No instances");
    }

    /**
     * Returns one bounded line suitable for a structured diagnostic field.
     *
     * @param value destination-provided value; {@code null} becomes empty
     * @param maxUtf8Bytes inclusive UTF-8 byte limit; non-positive returns empty
     * @return redacted, line-normalized, byte-bounded text
     */
    public static String singleLine(String value, int maxUtf8Bytes) {
        if (value == null || maxUtf8Bytes <= 0) {
            return "";
        }
        String lineStructured = boundedSource(value)
                .replace("\r\n", "\n")
                .replace('\r', '\n')
                .replaceAll("[\\p{Cc}&&[^\\n\\t]]", " ");
        String normalized = redact(lineStructured)
                .replaceAll("[\\n\\t\\f]+", " ")
                .replaceAll(" +", " ")
                .strip();
        return truncateUtf8(normalized, maxUtf8Bytes, TRUNCATED, false);
    }

    /**
     * Returns a bounded, redacted response-body preview.
     *
     * <p>Line structure is retained for JSON and gateway HTML readability. Callers must indent or
     * otherwise label the returned text so continuation lines cannot resemble independent log
     * events.</p>
     *
     * @param body raw response body; {@code null} becomes empty
     * @return bounded preview with a truncation marker when applicable
     */
    public static String responseBodyPreview(String body) {
        if (body == null || body.isBlank()) {
            return "";
        }
        boolean sourceTruncated = body.length() > MAX_SOURCE_CHARS;
        String normalized = boundedSource(body)
                .replace("\r\n", "\n")
                .replace('\r', '\n')
                .replaceAll("[\\p{Cc}&&[^\\n\\t]]", " ")
                .stripTrailing();
        String redacted = redact(normalized);
        String bounded = truncateUtf8(redacted, RESPONSE_BODY_PREVIEW_BYTES, "", false);
        boolean byteTruncated = !bounded.equals(redacted);
        if (!sourceTruncated && !byteTruncated) {
            return bounded;
        }
        return truncateUtf8(redacted, RESPONSE_BODY_PREVIEW_BYTES, "\n" + TRUNCATED, true);
    }

    /**
     * Returns a bounded, redacted multi-line diagnostic.
     *
     * <p>Line structure is retained, carriage returns are normalized, and control characters other
     * than newlines and tabs are replaced. This is the final envelope boundary for a response
     * diagnostic after its status, headers, and body preview have been assembled.</p>
     *
     * @param value assembled diagnostic text; {@code null} becomes empty
     * @param maxUtf8Bytes inclusive UTF-8 byte limit; non-positive returns empty
     * @return redacted, normalized, byte-bounded text
     */
    public static String multiLine(String value, int maxUtf8Bytes) {
        if (value == null || maxUtf8Bytes <= 0) {
            return "";
        }
        boolean sourceTruncated = value.length() > MAX_SOURCE_CHARS;
        String normalized = boundedSource(value)
                .replace("\r\n", "\n")
                .replace('\r', '\n')
                .replaceAll("[\\p{Cc}&&[^\\n\\t]]", " ")
                .stripTrailing();
        String redacted = redact(normalized);
        String bounded = truncateUtf8(redacted, maxUtf8Bytes, "", false);
        if (!sourceTruncated && bounded.equals(redacted)) {
            return bounded;
        }
        return truncateUtf8(redacted, maxUtf8Bytes, "\n" + TRUNCATED, true);
    }

    /**
     * Returns a bounded line for a response header already classified by its caller.
     *
     * @param line header name/value line
     * @return safe header line
     */
    public static String headerLine(String line) {
        return singleLine(line, 1_024);
    }

    /**
     * Returns a bounded description of an exception chain.
     *
     * @param failure exception chain root; may be {@code null}
     * @return non-empty single-line diagnostic
     */
    public static String exceptionChain(Throwable failure) {
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
            String message = singleLine(current.getMessage(), 256);
            if (!message.isBlank()) {
                detail.append(": ").append(message);
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
        return truncateUtf8(detail.toString(), 600, TRUNCATED, false);
    }

    private static String boundedSource(String value) {
        return value.length() <= MAX_SOURCE_CHARS ? value : value.substring(0, MAX_SOURCE_CHARS);
    }

    private static String redact(String value) {
        String redacted = value;
        for (String secret : knownCredentialValues()) {
            redacted = redactKnownCredentialValue(redacted, secret);
        }
        redacted = replaceGroup(AUTHORIZATION_SCHEME, redacted, 1);
        redacted = replaceGroup(SENSITIVE_HEADER, redacted, 1);
        redacted = replaceGroup(SENSITIVE_INLINE_HEADER, redacted, 1);
        redacted = replaceOuterGroups(SENSITIVE_JSON_FIELD, redacted);
        redacted = replaceGroup(SENSITIVE_PARAMETER, redacted, 1);
        return replaceGroup(FIELD_VALUE_PREVIEW, redacted, 1);
    }

    private static String redactKnownCredentialValue(String input, String secret) {
        Pattern boundedSecret = Pattern.compile(
                "(?<!" + TOKEN_CHARACTER + ")"
                        + Pattern.quote(secret)
                        + "(?!" + TOKEN_CHARACTER + ")");
        return boundedSecret.matcher(input).replaceAll(Matcher.quoteReplacement(REDACTED));
    }

    private static String replaceGroup(Pattern pattern, String input, int preservedGroup) {
        Matcher matcher = pattern.matcher(input);
        StringBuffer output = new StringBuffer(input.length());
        while (matcher.find()) {
            matcher.appendReplacement(
                    output,
                    Matcher.quoteReplacement(matcher.group(preservedGroup) + REDACTED));
        }
        matcher.appendTail(output);
        return output.toString();
    }

    private static String replaceOuterGroups(Pattern pattern, String input) {
        Matcher matcher = pattern.matcher(input);
        StringBuffer output = new StringBuffer(input.length());
        while (matcher.find()) {
            matcher.appendReplacement(
                    output,
                    Matcher.quoteReplacement(matcher.group(1) + REDACTED + matcher.group(3)));
        }
        matcher.appendTail(output);
        return output.toString();
    }

    private static List<String> knownCredentialValues() {
        List<String> values = new ArrayList<>();
        for (ConfigState.SearchDestination destination : ConfigState.SearchDestination.values()) {
            String key = destination.configKey();
            SecureCredentialStore.BasicCredentials basic =
                    SecureCredentialStore.loadBasicCredentials(key);
            SecureCredentialStore.ApiKeyCredentials apiKey =
                    SecureCredentialStore.loadApiKeyCredentials(key);
            SecureCredentialStore.JwtCredentials bearer =
                    SecureCredentialStore.loadJwtCredentials(key);
            SecureCredentialStore.CertificateCredentials certificate =
                    SecureCredentialStore.loadCertificateCredentials(key);
            SecureCredentialStore.AwsStaticCredentials aws =
                    SecureCredentialStore.loadAwsStaticCredentials(key);
            addIfPresent(values, basic.username());
            addIfPresent(values, basic.password());
            addIfPresent(values, apiKey.token());
            addIfPresent(values, bearer.token());
            addIfPresent(values, certificate.passphrase());
            addIfPresent(values, aws.accessKeyId());
            addIfPresent(values, aws.secretAccessKey());
            addIfPresent(values, aws.sessionToken());
        }
        values.sort(Comparator.comparingInt((String value) -> value.length()).reversed());
        return values;
    }

    private static void addIfPresent(List<String> values, String value) {
        if (value != null && !value.isEmpty() && !values.contains(value)) {
            values.add(value);
        }
    }

    private static String truncateUtf8(
            String value,
            int maxBytes,
            String marker,
            boolean forceMarker) {
        if (value == null || value.isEmpty() || maxBytes <= 0) {
            return "";
        }
        if (!forceMarker && value.getBytes(StandardCharsets.UTF_8).length <= maxBytes) {
            return value;
        }
        String suffix = marker == null ? "" : marker;
        byte[] markerBytes = suffix.getBytes(StandardCharsets.UTF_8);
        if (markerBytes.length > maxBytes) {
            suffix = "";
            markerBytes = new byte[0];
        }
        int contentBudget = Math.max(0, maxBytes - markerBytes.length);
        StringBuilder output = new StringBuilder(Math.min(value.length(), contentBudget));
        int used = 0;
        for (int offset = 0; offset < value.length();) {
            int codePoint = value.codePointAt(offset);
            String next = new String(Character.toChars(codePoint));
            int nextBytes = next.getBytes(StandardCharsets.UTF_8).length;
            if (used + nextBytes > contentBudget) {
                break;
            }
            output.append(next);
            used += nextBytes;
            offset += Character.charCount(codePoint);
        }
        return output + suffix;
    }
}
