package ai.anomalousvectors.tools.burp.utils.search;

/**
 * Destination-neutral connection-test result for the Config panel.
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
public record SearchConnectionStatus(
        String productName,
        boolean success,
        String distribution,
        String version,
        String message,
        String connectionStatus,
        String authenticationStatus,
        String trustStatus) {

    /** Returns a multi-line status summary suitable for the Config destination status panel. */
    public String formattedStatus() {
        String product = productName == null || productName.isBlank() ? "Database" : productName;
        String resolvedVersion = (distribution == null || distribution.isBlank() ? "" : distribution + " ")
                + (version == null || version.isBlank() ? "unknown" : version);
        String details = message == null || message.isBlank() ? "" : "\nDetails: " + message;
        return "Connection: " + connectionStatus
                + "\nAuthentication: " + authenticationStatus
                + "\nTrust: " + trustStatus
                + "\n" + product + " version: " + resolvedVersion.trim()
                + details;
    }
}
