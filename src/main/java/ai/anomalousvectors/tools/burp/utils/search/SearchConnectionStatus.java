package ai.anomalousvectors.tools.burp.utils.search;

/**
 * Destination-neutral connection-test result for the Config panel.
 *
 * @param productName operator-facing destination name
 * @param success whether the test completed successfully
 * @param distribution optional distribution/vendor string from the backend
 * @param version optional backend version
 * @param clusterUuid optional stable cluster identity from the root response
 * @param message detail message
 * @param connectionStatus connection status label
 * @param authenticationStatus authentication status label
 * @param trustStatus TLS trust status label
 */
public record SearchConnectionStatus(
        String productName,
        boolean success,
        String distribution,
        String version,
        String clusterUuid,
        String message,
        String connectionStatus,
        String authenticationStatus,
        String trustStatus) {

    /**
     * Creates a status when the destination does not expose a cluster identity.
     *
     * @param productName operator-facing destination name
     * @param success whether the test completed successfully
     * @param distribution optional distribution/vendor string from the backend
     * @param version optional backend version
     * @param message detail message
     * @param connectionStatus connection status label
     * @param authenticationStatus authentication status label
     * @param trustStatus TLS trust status label
     */
    public SearchConnectionStatus(
            String productName,
            boolean success,
            String distribution,
            String version,
            String message,
            String connectionStatus,
            String authenticationStatus,
            String trustStatus) {
        this(
                productName,
                success,
                distribution,
                version,
                "",
                message,
                connectionStatus,
                authenticationStatus,
                trustStatus);
    }

    /**
     * Returns a multi-line status summary suitable for the Config destination status panel.
     *
     * <p>Missing product and version values use operator-facing fallback labels. Authentication
     * rejection details append a credential-refresh hint.</p>
     *
     * @return non-null multi-line status text
     */
    public String formattedStatus() {
        String product = productName == null || productName.isBlank() ? "Database" : productName;
        String resolvedVersion = (distribution == null || distribution.isBlank() ? "" : distribution + " ")
                + (version == null || version.isBlank() ? "unknown" : version);
        String details = message == null || message.isBlank() ? "" : "\nDetails: " + message;
        String authHint = authenticationFailureHint();
        return "Connection: " + connectionStatus
                + "\nAuthentication: " + authenticationStatus
                + "\nTrust: " + trustStatus
                + "\n" + product + " version: " + resolvedVersion.trim()
                + details
                + authHint;
    }

    /**
     * Returns an operator hint when authentication failed with an HTTP 401/403-style detail.
     *
     * @return hint line including a leading newline, or empty when not applicable
     */
    private String authenticationFailureHint() {
        if (!"Failed".equals(authenticationStatus)) {
            return "";
        }
        String detail = message == null ? "" : message.toLowerCase(java.util.Locale.ROOT);
        boolean authRejected = detail.contains("401")
                || detail.contains("403")
                || detail.contains("unauthorized")
                || detail.contains("forbidden");
        if (!authRejected) {
            return "";
        }
        return """

                Hint: Check credentials (bearer/API key/session token may have expired). Update Config, then re-test or Stop and Start.""";
    }
}
