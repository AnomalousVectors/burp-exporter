package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ai.anomalousvectors.tools.burp.utils.search.SearchConnectionStatus;

/**
 * Classifies search-destination probe or push failures for outage vs auto-disable policy.
 *
 * <p>{@link #AUTH} failures may disable the database destination. {@link #CAPACITY} failures
 * (gateway timeouts, rate limits, transport pressure) keep export enabled and rely on queueing plus
 * shared backoff. {@link #HARD} covers blank/unusable configuration that cannot recover without
 * operator changes.</p>
 *
 * <p>Stateless and safe for concurrent callers.</p>
 */
enum SearchDestinationFailureKind {

    /** Credential rejection or incomplete auth configuration. */
    AUTH,

    /** Transient gateway, rate-limit, or transport pressure. */
    CAPACITY,

    /** Unrecoverable without config changes (blank URL / missing required settings). */
    HARD;

    private static final Pattern HTTP_STATUS = Pattern.compile("\\bHTTP\\s+(\\d{3})\\b", Pattern.CASE_INSENSITIVE);

    /**
     * Classifies a connection-test / health-probe result.
     *
     * <p>Callers normally pass a failed result. A successful result is classified as
     * {@link #CAPACITY} as the conservative non-disabling fallback; success handling occurs before
     * failure policy consumes this value.</p>
     *
     * @param status probe result; {@code null} treated as {@link #CAPACITY}
     * @return failure kind for outage policy
     */
    static SearchDestinationFailureKind classify(SearchConnectionStatus status) {
        if (status == null) {
            return CAPACITY;
        }
        if (status.success()) {
            return CAPACITY;
        }
        String message = status.message() == null ? "" : status.message();
        String lower = message.toLowerCase(Locale.ROOT);
        if (isHardConfigMessage(lower)) {
            return HARD;
        }
        if ("Failed".equals(status.authenticationStatus())) {
            return AUTH;
        }
        int httpStatus = httpStatusFromMessage(message);
        if (httpStatus > 0 && BulkRateLimitBackoff.isRateLimited(httpStatus)) {
            return CAPACITY;
        }
        if (httpStatus == 401 || httpStatus == 403) {
            return AUTH;
        }
        if (BulkRateLimitBackoff.isTransientTransportDetail(message)) {
            return CAPACITY;
        }
        // Prefer soft outage for other connectivity failures so export keeps backing off.
        return CAPACITY;
    }

    /**
     * Returns whether a bulk/transport detail string is capacity pressure (not auth/mapping).
     *
     * @param detail exception or status message; may be blank
     * @return {@code true} when the detail looks like rate-limit / gateway / transport pressure
     */
    static boolean isCapacityDetail(String detail) {
        if (detail == null || detail.isBlank()) {
            return false;
        }
        int httpStatus = httpStatusFromMessage(detail);
        if (httpStatus > 0 && BulkRateLimitBackoff.isRateLimited(httpStatus)) {
            return true;
        }
        return BulkRateLimitBackoff.isTransientTransportDetail(detail);
    }

    private static boolean isHardConfigMessage(String lowerMessage) {
        return lowerMessage.contains("not configured")
                || lowerMessage.contains("url is blank")
                || lowerMessage.contains("endpoint is blank");
    }

    private static int httpStatusFromMessage(String message) {
        if (message == null || message.isBlank()) {
            return -1;
        }
        Matcher matcher = HTTP_STATUS.matcher(message);
        if (matcher.find()) {
            try {
                return Integer.parseInt(matcher.group(1));
            } catch (NumberFormatException ignored) {
                return -1;
            }
        }
        // Bare "HTTP 504 ..." already matched; also accept leading status phrases.
        String trimmed = message.trim();
        if (trimmed.length() >= 3 && Character.isDigit(trimmed.charAt(0))) {
            try {
                return Integer.parseInt(trimmed.substring(0, 3));
            } catch (NumberFormatException ignored) {
                return -1;
            }
        }
        return -1;
    }
}
