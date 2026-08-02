package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.search.SearchDeployment;

/**
 * Operator-facing Amazon OpenSearch capacity-pressure diagnostics.
 *
 * <p>Emits throttled WARN lines that name the observed HTTP/transport symptom and point at the
 * CloudWatch metrics an operator should verify before concluding write-threadpool throttling.
 * Absence of those CloudWatch rejections means the client-side symptom alone is not proof of
 * Amazon write rejection.</p>
 *
 * <p>Thread-safe. A process-wide monotonic throttle bounds panel output across concurrent
 * senders.</p>
 */
final class AmazonOpenSearchPressureLog {

    private static final long LOG_INTERVAL_NANOS = TimeUnit.SECONDS.toNanos(60L);
    private static final AtomicLong LAST_LOG_NANOS = new AtomicLong(0L);

    private AmazonOpenSearchPressureLog() {
        throw new AssertionError("No instances");
    }

    /**
     * Logs a throttled WARN when Amazon bulk HTTP status suggests capacity or gateway pressure.
     *
     * @param status HTTP status (for example {@code 429}, {@code 502}, {@code 503}, {@code 504})
     * @param indexName target index; blank becomes {@code unknown}
     * @param pathLabel prepared/chunked path label
     */
    static void maybeNoteHttpPressure(int status, String indexName, String pathLabel) {
        if (!BulkByteBudget.isAmazonDestination()) {
            return;
        }
        if (status != 429 && status != 502 && status != 503 && status != 504) {
            return;
        }
        maybeLog("HTTP " + status, indexName, pathLabel);
    }

    /**
     * Logs a throttled WARN when Amazon bulk transport fails without an HTTP status
     * (timeouts, failed-to-respond, connection resets).
     *
     * <p>The detail is emitted after length clamping but is not secret-redacted. Callers must pass
     * a single-line transport summary that contains no credentials or request body.</p>
     *
     * @param detail exception message or short cause; may be blank
     * @param indexName target index; blank becomes {@code unknown}
     * @param pathLabel prepared/chunked path label
     */
    static void maybeNoteTransportPressure(String detail, String indexName, String pathLabel) {
        if (!BulkByteBudget.isAmazonDestination()) {
            return;
        }
        String lower = detail == null ? "" : detail.toLowerCase(Locale.ROOT);
        if (!(lower.contains("failed to respond")
                || lower.contains("timeout")
                || lower.contains("timed out")
                || lower.contains("connection reset")
                || lower.contains("connection refused")
                || lower.contains("broken pipe"))) {
            return;
        }
        String symptom = detail == null || detail.isBlank() ? "transport failure" : detail.trim();
        if (symptom.length() > 160) {
            symptom = symptom.substring(0, 157) + "...";
        }
        maybeLog(symptom, indexName, pathLabel);
    }

    /** Clears the throttle clock (export stop/clear and focused unit tests). */
    static void clear() {
        LAST_LOG_NANOS.set(0L);
    }

    private static void maybeLog(String symptom, String indexName, String pathLabel) {
        long now = System.nanoTime();
        long previous = LAST_LOG_NANOS.get();
        if (previous != 0L && now - previous < LOG_INTERVAL_NANOS) {
            return;
        }
        if (!LAST_LOG_NANOS.compareAndSet(previous, now) && previous != 0L) {
            return;
        }
        String index = indexName == null || indexName.isBlank() ? "unknown" : indexName;
        String path = pathLabel == null || pathLabel.isBlank() ? "Bulk" : pathLabel;
        Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                + " Amazon capacity symptom (client-observed): " + symptom
                + " path=" + path
                + " index=" + index
                + ". This is not proof of Amazon write rejection — verify CloudWatch"
                + " AWS/ES (hosted) or AOSS (serverless) metrics:"
                + " CoordinatingWriteRejected, PrimaryWriteRejected, ThreadpoolWriteRejected,"
                + " CPUUtilization, JVMMemoryPressure."
                + cloudWatchHintSuffix());
    }

    private static String cloudWatchHintSuffix() {
        String baseUrl = RuntimeConfig.searchBaseUrl();
        String region = SearchDeployment.detectAmazonOpenSearchRegion(baseUrl);
        String domain = SearchDeployment.detectAmazonOpenSearchDomainName(baseUrl);
        if (region.isBlank()) {
            return " Open the CloudWatch metrics console for this domain's region.";
        }
        if (domain.isBlank()) {
            return " CloudWatch console: https://" + region
                    + ".console.aws.amazon.com/cloudwatch/home?region=" + region
                    + "#metricsV2:graph=~()";
        }
        // Deep link omits ClientId; operators with multiple accounts still land on the metric names.
        return " CloudWatch verify: https://" + region
                + ".console.aws.amazon.com/cloudwatch/home?region=" + region
                + "#metricsV2:graph=~(metrics~(~(~'AWS*2fES~'CoordinatingWriteRejected~'DomainName~'"
                + domain
                + ")~(~'AWS*2fES~'PrimaryWriteRejected~'DomainName~'"
                + domain
                + ")~(~'AWS*2fES~'ThreadpoolWriteRejected~'DomainName~'"
                + domain
                + ")~(~'AWS*2fES~'CPUUtilization~'DomainName~'"
                + domain
                + ")~(~'AWS*2fES~'JVMMemoryPressure~'DomainName~'"
                + domain
                + "))~view~'timeSeries~stacked~false~region~'"
                + region
                + "~stat~'Maximum~period~60)";
    }
}
