package ai.anomalousvectors.tools.burp.sinks;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.concurrent.LazyScheduler;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Rolls up high-confidence BODY-enumeration skips into deduplicated DEBUG summaries.
 *
 * <p>Targets the mis-gate case where declared form/multipart traffic was skipped because the body
 * sniff inferred binary. Burp-correction paths (declared grpc/protobuf, synthetic BODY filter)
 * stay silent. Startup, live, and Stop emit concise DEBUG summaries. Live rollups fire every
 * {@link #PERIODIC_INTERVAL_SECONDS}.</p>
 */
public final class BodyEnumerationSkippedLog {

    /** Live periodic summary interval while export is running. */
    static final int PERIODIC_INTERVAL_SECONDS = 60;

    private static final Object LOCK = new Object();
    private static final LazyScheduler SCHEDULER =
            new LazyScheduler("burp-exporter-body-enum-skipped-log");

    private static final Map<String, Integer> STARTUP_SUSPECT_URLS = new LinkedHashMap<>();
    private static int startupSuspectDocCount;
    private static final Map<String, Integer> LIVE_PENDING_URLS = new LinkedHashMap<>();
    private static int livePendingDocCount;
    private static int gateBugDocCount;

    private static boolean startupSummaryEmitted;
    private static boolean startupAccumulationActive;

    private BodyEnumerationSkippedLog() {}

    /** Clears per-run aggregation state without logging. */
    public static void startForCurrentRun() {
        synchronized (LOCK) {
            STARTUP_SUSPECT_URLS.clear();
            startupSuspectDocCount = 0;
            LIVE_PENDING_URLS.clear();
            livePendingDocCount = 0;
            gateBugDocCount = 0;
            startupSummaryEmitted = false;
            startupAccumulationActive = true;
        }
    }

    /**
     * Starts the 60-second periodic live summary scheduler.
     *
     * <p>Safe to call from any thread. No-op when already started.</p>
     */
    public static void startPeriodicFlusher() {
        if (SCHEDULER.isStarted()) {
            return;
        }
        synchronized (BodyEnumerationSkippedLog.class) {
            if (SCHEDULER.isStarted()) {
                return;
            }
            SCHEDULER.getOrStart().scheduleAtFixedRate(
                    BodyEnumerationSkippedLog::flushPeriodicSummary,
                    PERIODIC_INTERVAL_SECONDS,
                    PERIODIC_INTERVAL_SECONDS,
                    TimeUnit.SECONDS);
        }
    }

    /**
     * Flushes any pending live summary, stops the periodic scheduler, and clears state.
     *
     * <p>Call from export Stop before clearing run state.</p>
     */
    public static void stopPeriodicFlusher() {
        flushStopSummary();
        SCHEDULER.stop();
    }

    /** Clears state without emitting; used during test and lifecycle resets. */
    public static void clearRunState() {
        SCHEDULER.stop();
        startForCurrentRun();
    }

    /**
     * Evaluates one document and records mis-gate suspicion when criteria match.
     *
     * @param request source request
     * @param service optional HTTP service for URL reconstruction
     * @param requestDoc built request sub-document
     * @param contentType Burp declared content type
     * @param headers request headers
     * @param inferredContentType sniffed {@code request.content_type.inferred} value
     * @param bodyBytes raw request body bytes
     * @param bodyEnumerationSkipped whether BODY enumeration was skipped on the fast path
     */
    public static void evaluateAndRecord(
            HttpRequest request,
            HttpService service,
            Map<String, Object> requestDoc,
            ContentType contentType,
            List<HttpHeader> headers,
            String inferredContentType,
            byte[] bodyBytes,
            boolean bodyEnumerationSkipped) {
        if (!isMisgateSuspect(
                contentType, headers, inferredContentType, bodyBytes, bodyEnumerationSkipped)) {
            if (isGateBugSuspect(
                    contentType, headers, inferredContentType, bodyBytes, bodyEnumerationSkipped)) {
                recordGateBug();
            }
            return;
        }
        String dedupeUrl = dedupeUrl(request, service, requestDoc);
        recordMisgateSuspect(dedupeUrl);
    }

    /**
     * Returns whether a document matches the mis-gate suspect criteria (declared form/multipart,
     * inferred binary, BODY enumeration skipped, non-empty body).
     *
     * @param contentType Burp declared content type
     * @param headers request headers
     * @param inferredContentType sniffed {@code request.content_type.inferred} value
     * @param bodyBytes raw request body bytes
     * @param bodyEnumerationSkipped whether BODY enumeration was skipped on the fast path
     * @return {@code true} when the document is a mis-gate suspect
     */
    public static boolean isMisgateSuspect(
            ContentType contentType,
            List<HttpHeader> headers,
            String inferredContentType,
            byte[] bodyBytes,
            boolean bodyEnumerationSkipped) {
        if (!bodyEnumerationSkipped || bodyBytes == null || bodyBytes.length == 0) {
            return false;
        }
        String primary = RequestResponseParametersSupport.resolvePrimaryMediaType(contentType, headers);
        if (HttpMessageDocSupport.isExplicitlyBinaryMediaType(primary)) {
            return false;
        }
        if (!RequestResponseParametersSupport.isDeclaredFormOrMultipart(contentType, headers, primary)) {
            return false;
        }
        if (HttpMessageDocSupport.INFERRED_CT_TEXT.equals(inferredContentType)
                || HttpMessageDocSupport.INFERRED_CT_EMPTY.equals(inferredContentType)) {
            return false;
        }
        return HttpMessageDocSupport.INFERRED_CT_BINARY.equals(inferredContentType);
    }

    /**
     * Returns whether a document matches the unexpected gate-bug criteria (declared form/multipart,
     * inferred text or empty, BODY enumeration skipped).
     *
     * @param contentType Burp declared content type
     * @param headers request headers
     * @param inferredContentType sniffed {@code request.content_type.inferred} value
     * @param bodyBytes raw request body bytes
     * @param bodyEnumerationSkipped whether BODY enumeration was skipped on the fast path
     * @return {@code true} when the gate outcome is unexpected
     */
    public static boolean isGateBugSuspect(
            ContentType contentType,
            List<HttpHeader> headers,
            String inferredContentType,
            byte[] bodyBytes,
            boolean bodyEnumerationSkipped) {
        if (!bodyEnumerationSkipped || bodyBytes == null || bodyBytes.length == 0) {
            return false;
        }
        String primary = RequestResponseParametersSupport.resolvePrimaryMediaType(contentType, headers);
        if (HttpMessageDocSupport.isExplicitlyBinaryMediaType(primary)) {
            return false;
        }
        if (!RequestResponseParametersSupport.isDeclaredFormOrMultipart(contentType, headers, primary)) {
            return false;
        }
        return HttpMessageDocSupport.INFERRED_CT_TEXT.equals(inferredContentType)
                || HttpMessageDocSupport.INFERRED_CT_EMPTY.equals(inferredContentType);
    }

    /**
     * Emits deduplicated startup/backlog DEBUG summaries when any startup suspects were recorded.
     *
     * <p>Safe to call multiple times; only the first emission logs.</p>
     */
    public static void flushStartupSummary() {
        String misgateLine;
        String gateBugLine;
        int misgateCount;
        Map<String, Integer> misgateUrlSnapshot;
        synchronized (LOCK) {
            startupAccumulationActive = false;
            misgateLine = null;
            gateBugLine = null;
            misgateCount = 0;
            misgateUrlSnapshot = Map.of();
            if (!startupSummaryEmitted && !STARTUP_SUSPECT_URLS.isEmpty()) {
                startupSummaryEmitted = true;
                misgateCount = startupSuspectDocCount;
                misgateUrlSnapshot = new LinkedHashMap<>(STARTUP_SUSPECT_URLS);
                misgateLine = formatMisgateSummaryLocked("startup/backlog", misgateCount, misgateUrlSnapshot);
                STARTUP_SUSPECT_URLS.clear();
                startupSuspectDocCount = 0;
            }
            if (gateBugDocCount > 0) {
                int count = gateBugDocCount;
                gateBugDocCount = 0;
                gateBugLine = formatGateBugWarning("startup/backlog", count);
            }
        }
        if (misgateLine != null) {
            ParameterIntegrityDetailReporter.report(
                    "startup_backlog",
                    "misgate_binary",
                    misgateCount,
                    misgateUrlSnapshot,
                    Map.of(),
                    "request.parameters may omit BODY rows; request.body remains complete",
                    ParameterIntegrityDetailReporter.UrlListPolicy.FULL);
            Logger.logDebug(misgateLine);
        }
        if (gateBugLine != null) {
            Logger.logWarnPanelOnly(gateBugLine);
        }
    }

    /**
     * Emits DEBUG summaries for live suspects accumulated since the last periodic flush.
     *
     * <p>No-op when export is stopped or the pending bucket is empty. Log text uses phase
     * {@code periodic/live} so operators can distinguish scheduled rollups from startup/stop.</p>
     */
    public static void flushPeriodicSummary() {
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        String line;
        int docCount;
        Map<String, Integer> urlSnapshot;
        synchronized (LOCK) {
            if (livePendingDocCount <= 0) {
                return;
            }
            docCount = livePendingDocCount;
            urlSnapshot = new LinkedHashMap<>(LIVE_PENDING_URLS);
            line = formatMisgateSummaryLocked("periodic/live", docCount, urlSnapshot);
            LIVE_PENDING_URLS.clear();
            livePendingDocCount = 0;
        }
        if (line != null) {
            ParameterIntegrityDetailReporter.report(
                    "live",
                    "misgate_binary",
                    docCount,
                    urlSnapshot,
                    Map.of(),
                    "request.parameters may omit BODY rows; request.body remains complete",
                    ParameterIntegrityDetailReporter.UrlListPolicy.FULL);
            Logger.logDebug(line);
        }
    }

    /**
     * Emits a final DEBUG summary for any live suspects not yet flushed by the periodic scheduler.
     *
     * <p>Session totals are INFO from {@link ParameterIntegritySessionLog}; this path keeps
     * pending summaries and gate-bug warnings only.</p>
     */
    public static void flushStopSummary() {
        flushStopDebugSamples();
    }

    /**
     * Emits DEBUG mis-gate summaries for live suspects not yet flushed by the scheduler.
     */
    public static void flushStopDebugSamples() {
        String misgateLine;
        String gateBugLine;
        int misgateCount;
        Map<String, Integer> misgateUrlSnapshot;
        synchronized (LOCK) {
            misgateLine = null;
            gateBugLine = null;
            misgateCount = 0;
            misgateUrlSnapshot = Map.of();
            if (livePendingDocCount > 0) {
                misgateCount = livePendingDocCount;
                misgateUrlSnapshot = new LinkedHashMap<>(LIVE_PENDING_URLS);
                misgateLine = formatMisgateSummaryLocked("stop", misgateCount, misgateUrlSnapshot);
                LIVE_PENDING_URLS.clear();
                livePendingDocCount = 0;
            }
            if (gateBugDocCount > 0) {
                int count = gateBugDocCount;
                gateBugDocCount = 0;
                gateBugLine = formatGateBugWarning("stop", count);
            }
        }
        if (misgateLine != null) {
            ParameterIntegrityDetailReporter.report(
                    "stop",
                    "misgate_binary",
                    misgateCount,
                    misgateUrlSnapshot,
                    Map.of(),
                    "request.parameters may omit BODY rows; request.body remains complete",
                    ParameterIntegrityDetailReporter.UrlListPolicy.FULL);
            Logger.logDebug(misgateLine);
        }
        if (gateBugLine != null) {
            Logger.logWarnPanelOnly(gateBugLine);
        }
    }

    static String formatMisgateSummaryForTests(int docCount, Map<String, Integer> urlCounts, String phase) {
        synchronized (LOCK) {
            return formatMisgateSummaryLocked(phase, docCount, urlCounts);
        }
    }

    private static void recordMisgateSuspect(String url) {
        synchronized (LOCK) {
            if (startupAccumulationActive) {
                STARTUP_SUSPECT_URLS.compute(url, (k, v) -> v == null ? 1 : v + 1);
                startupSuspectDocCount++;
            } else {
                LIVE_PENDING_URLS.compute(url, (k, v) -> v == null ? 1 : v + 1);
                livePendingDocCount++;
            }
        }
    }

    private static void recordGateBug() {
        synchronized (LOCK) {
            gateBugDocCount++;
        }
    }

    private static String formatMisgateSummaryLocked(String phase, int docCount, Map<String, Integer> urlCounts) {
        if (docCount <= 0) {
            return null;
        }
        StringBuilder sb = new StringBuilder(320);
        sb.append("[ParameterIntegrity] misgate_binary during ")
                .append(phase)
                .append(": ")
                .append(docCount)
                .append(" request(s); unique_request_urls=")
                .append(urlCounts == null ? 0 : urlCounts.size())
                .append(". Form fields may be missing from request.parameters. See Stats → Mis-gate Suspects. ")
                .append(ParameterIntegrityDetailReporter.detailPointer("misgate_binary"))
                .append(".");
        return sb.toString();
    }

    private static String formatGateBugWarning(String phase, int count) {
        return "[ParameterIntegrity] BODY enumeration skipped during "
                + phase
                + " for "
                + count
                + " request(s) with declared form/multipart but inferred text/empty body"
                + " (unexpected gate outcome; report if seen). "
                + ParameterIntegrityDetailReporter.detailPointer("misgate_binary")
                + ".";
    }

    private static String dedupeUrl(HttpRequest request, HttpService service, Map<String, Object> requestDoc) {
        String direct = RequestResponseDocBuilder.safeRequestUrl(request, "BodyEnumSkipped");
        if (direct != null) {
            return direct;
        }
        String rebuilt = RequestResponseDocBuilder.buildBestEffortUrl(request, service, requestDoc, "BodyEnumSkipped");
        if (rebuilt != null) {
            return rebuilt;
        }
        String path = RequestResponseDocBuilder.requestPathWithQuery(requestDoc);
        return path == null ? "unknown" : path;
    }

}
