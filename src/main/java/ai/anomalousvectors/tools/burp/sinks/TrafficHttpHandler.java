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

    /**
     * Returns a thread-safe snapshot of shared native Proxy/general HTTP receipt accounting.
     *
     * <p>Stop clears retained entries but preserves peak/pressure totals. A new run starts with
     * zero totals. Reclamation counts lost late-response eligibility, not proven response loss.</p>
     *
     * @return current or last-run bounded receipt accounting; contains no message data
     */
    public static RequestReceiptStats requestReceiptStats() {
        LiveRequestReceipts.Snapshot snapshot = receiptSnapshot();
        return new RequestReceiptStats(snapshot.retained(), snapshot.capacity(), snapshot.peak(),
                snapshot.reclaimed(), snapshot.rejected());
    }

    /**
     * Payload-free receipt occupancy and pressure totals for one export run.
     *
     * @param retained current receipts, including requests awaiting request-only handling
     * @param capacity shared maximum across native Proxy and general HTTP tools
     * @param peak maximum simultaneous receipt count
     * @param reclaimed old receipts removed under capacity pressure
     * @param rejected request admissions refused because no receipt could be reclaimed
     */
    public record RequestReceiptStats(int retained, int capacity, int peak, long reclaimed, long rejected) { }
}
