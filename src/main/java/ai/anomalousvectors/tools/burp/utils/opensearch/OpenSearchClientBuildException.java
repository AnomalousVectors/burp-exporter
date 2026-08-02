package ai.anomalousvectors.tools.burp.utils.opensearch;

/** Thrown when an OpenSearch client cannot be constructed. */
public final class OpenSearchClientBuildException extends RuntimeException {
    /**
     * Creates a client-construction failure with its underlying cause.
     *
     * @param message operator-safe description of the failed construction step
     * @param cause underlying TLS, URI, credential, or transport setup failure
     */
    public OpenSearchClientBuildException(String message, Throwable cause) {
        super(message, cause);
    }
}
