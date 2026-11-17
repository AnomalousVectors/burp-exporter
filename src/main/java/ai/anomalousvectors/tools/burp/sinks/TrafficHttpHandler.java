package ai.anomalousvectors.tools.burp.sinks;

/**
 * General Burp HTTP traffic handler for non-Proxy live request/response export.
 *
 * <p>This sink-neutral type is the canonical public entry point for the extension's shared HTTP
 * traffic capture path for other tools; native Proxy capture belongs to
 * {@link TrafficProxyHttpHandler}. It keeps callers and user-facing docs on the neutral {@code Traffic}
 * vocabulary while the larger implementation remains isolated in
 * {@link TrafficHttpHandlerSupport}.</p>
 */
public class TrafficHttpHandler extends TrafficHttpHandlerSupport {

    /**
     * Public accessor for the current pending-orphans size. Delegates to
     * {@link TrafficHttpHandlerSupport#getPendingOrphansSize()} so packages outside
     * {@code sinks} (UI surfaces) can read the value.
     */
    public static int pendingOrphansSize() {
        return getPendingOrphansSize();
    }
}
