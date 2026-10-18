package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.io.Serial;

/** Thrown when an OpenSearch client cannot be constructed. */
public final class OpenSearchClientBuildException extends RuntimeException {
    @Serial private static final long serialVersionUID = 1L;

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
