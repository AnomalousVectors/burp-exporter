package ai.anomalousvectors.tools.burp.sinks;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Records URL-parameter truncation for operator logs with startup backlog deduplication and live
 * first-seen DEBUG notices.
 *
 * <p>Startup/backlog truncations accumulate by original {@code request.url} until
 * {@link #flushStartupSummary()} runs. Live truncations emit a DEBUG notice the first time each
 * URL is seen during the active export run; additional unique URLs beyond
 * {@link #LIVE_UNIQUE_URL_LOG_CAP} roll into a throttled overflow summary.</p>
 */
public final class UrlParameterTruncationLog {

    /** Maximum distinct live URLs logged individually before switching to overflow summary lines. */
    static final int LIVE_UNIQUE_URL_LOG_CAP = 50;

    private static final Object LOCK = new Object();
    private static final Set<String> LIVE_LOGGED_URLS = ConcurrentHashMap.newKeySet();
    private static final Map<String, Integer> STARTUP_URL_DROPPED_TOTALS = new LinkedHashMap<>();

    private static int liveUniqueUrlLogsEmitted;
    private static long liveOverflowUniqueUrls;
    private static long liveOverflowUniqueUrlsLastLogged;
    private static int startupTruncatedDocCount;
    private static boolean startupSummaryEmitted;
    /** When {@code true}, truncations accumulate for the startup/backlog summary line. */
    private static boolean startupAccumulationActive;

    private UrlParameterTruncationLog() {}

    /** Clears per-run aggregation state without logging. */
    public static void startForCurrentRun() {
        synchronized (LOCK) {
            STARTUP_URL_DROPPED_TOTALS.clear();
            LIVE_LOGGED_URLS.clear();
            liveUniqueUrlLogsEmitted = 0;
            liveOverflowUniqueUrls = 0;
            liveOverflowUniqueUrlsLastLogged = 0;
            startupTruncatedDocCount = 0;
            startupSummaryEmitted = false;
            startupAccumulationActive = true;
        }
    }

    /** Clears state without emitting; used during test and lifecycle resets. */
    public static void clearRunState() {
        startForCurrentRun();
    }

    /**
     * Records one document whose URL parameters were truncated.
     *
     * @param request source request
     * @param service optional HTTP service for URL reconstruction when {@code request.url()} is unavailable
     * @param requestDoc built request sub-document (may already contain narrowed path/query fields)
     * @param droppedUrlParams number of URL parameter entries dropped by the cap
     */
    public static void record(
            HttpRequest request,
            HttpService service,
            Map<String, Object> requestDoc,
            int droppedUrlParams) {
        if (droppedUrlParams <= 0) {
            return;
        }
        ExportStats.recordUrlParamsTruncated(droppedUrlParams);
        String dedupeUrl = dedupeUrl(request, service, requestDoc);
        synchronized (LOCK) {
            if (startupAccumulationActive) {
                recordStartupLocked(dedupeUrl, droppedUrlParams);
                return;
            }
        }
        recordLive(dedupeUrl, droppedUrlParams);
    }

    /**
     * Emits a deduplicated startup/backlog summary when any startup truncations were recorded.
     *
     * <p>Safe to call multiple times; only the first emission logs.</p>
     */
    public static void flushStartupSummary() {
        String line;
        int docCount;
        Map<String, Integer> urlDroppedTotals;
        synchronized (LOCK) {
            startupAccumulationActive = false;
            if (startupSummaryEmitted || STARTUP_URL_DROPPED_TOTALS.isEmpty()) {
                return;
            }
            startupSummaryEmitted = true;
            line = formatStartupSummaryLocked();
            docCount = startupTruncatedDocCount;
            urlDroppedTotals = new LinkedHashMap<>(STARTUP_URL_DROPPED_TOTALS);
        }
        ParameterIntegrityDetailReporter.report(
                "startup_backlog",
                "url_params_truncated",
                docCount,
                urlDroppedTotals,
                Map.of("dropped_url_params", droppedTotal(urlDroppedTotals)),
                "request.parameters and derived query fields may omit URL rows beyond the cap; request.url remains complete",
                ParameterIntegrityDetailReporter.UrlListPolicy.FULL);
        Logger.logDebug(line);
    }

    /**
     * Emits any final live overflow summary not reached by the periodic threshold.
     *
     * <p>This method is thread-safe. It updates the live overflow watermark before logging so a
     * repeated Stop flush does not duplicate the same summary.</p>
     */
    public static void flushStopSummary() {
        long additional;
        synchronized (LOCK) {
            additional = liveOverflowUniqueUrls - liveOverflowUniqueUrlsLastLogged;
            if (additional <= 0) {
                return;
            }
            liveOverflowUniqueUrlsLastLogged = liveOverflowUniqueUrls;
        }
        Logger.logDebug(formatOverflowSummary(additional));
    }

    static String formatStartupSummaryForTests(Map<String, Integer> urlDroppedTotals) {
        synchronized (LOCK) {
            Map<String, Integer> previous = new LinkedHashMap<>(STARTUP_URL_DROPPED_TOTALS);
            try {
                STARTUP_URL_DROPPED_TOTALS.clear();
                STARTUP_URL_DROPPED_TOTALS.putAll(urlDroppedTotals);
                return formatStartupSummaryLocked();
            } finally {
                STARTUP_URL_DROPPED_TOTALS.clear();
                STARTUP_URL_DROPPED_TOTALS.putAll(previous);
            }
        }
    }

    /** Records startup state while the caller holds {@link #LOCK}. */
    private static void recordStartupLocked(String url, int droppedUrlParams) {
        STARTUP_URL_DROPPED_TOTALS.compute(url, (k, v) -> v == null ? droppedUrlParams : v + droppedUrlParams);
        startupTruncatedDocCount++;
    }

    private static void recordLive(String url, int droppedUrlParams) {
        boolean firstForUrl;
        String logLine = null;
        synchronized (LOCK) {
            firstForUrl = LIVE_LOGGED_URLS.add(url);
            if (!firstForUrl) {
                return;
            }
            if (liveUniqueUrlLogsEmitted < LIVE_UNIQUE_URL_LOG_CAP) {
                liveUniqueUrlLogsEmitted++;
                logLine = formatLiveLine(droppedUrlParams);
            } else {
                liveOverflowUniqueUrls++;
                logLine = overflowSummaryIfDueLocked();
            }
        }
        ParameterIntegrityDetailReporter.report(
                "live",
                "url_params_truncated",
                1,
                Map.of(url, 1),
                Map.of("dropped_url_params", droppedUrlParams),
                "request.parameters and derived query fields may omit URL rows beyond the cap; request.url remains complete",
                ParameterIntegrityDetailReporter.UrlListPolicy.FULL);
        if (logLine != null) {
            Logger.logDebug(logLine);
        }
    }

    /** Returns a periodic overflow summary while the caller holds {@link #LOCK}. */
    private static String overflowSummaryIfDueLocked() {
        if (liveOverflowUniqueUrls <= 0 || liveOverflowUniqueUrls % 25 != 0) {
            return null;
        }
        long additional = liveOverflowUniqueUrls - liveOverflowUniqueUrlsLastLogged;
        if (additional <= 0) {
            return null;
        }
        liveOverflowUniqueUrlsLastLogged = liveOverflowUniqueUrls;
        return formatOverflowSummary(additional);
    }

    private static String formatOverflowSummary(long additionalUniqueUrls) {
        return "[ParameterCardinality] URL parameters truncated for "
                + additionalUniqueUrls
                + " additional unique request.url value(s) this run (cap="
                + RequestResponseParametersSupport.URL_PARAMETERS_CAP
                + "); see Stats for session totals. "
                + ParameterIntegrityDetailReporter.detailPointer("url_params_truncated")
                + ".";
    }

    private static String formatLiveLine(int droppedUrlParams) {
        return "[ParameterCardinality] URL parameters truncated to "
                + RequestResponseParametersSupport.URL_PARAMETERS_CAP
                + "; dropped_url_params="
                + droppedUrlParams
                + " (index query/path/parameters may be incomplete). "
                + ParameterIntegrityDetailReporter.detailPointer("url_params_truncated")
                + ".";
    }

    private static String formatStartupSummaryLocked() {
        long totalDropped = 0L;
        for (int dropped : STARTUP_URL_DROPPED_TOTALS.values()) {
            totalDropped += dropped;
        }
        StringBuilder sb = new StringBuilder(220);
        sb.append("[StartupExport] URL parameters truncated for ")
                .append(STARTUP_URL_DROPPED_TOTALS.size())
                .append(" unique request.url(s); cap=")
                .append(RequestResponseParametersSupport.URL_PARAMETERS_CAP)
                .append("; dropped_url_params=")
                .append(totalDropped);
        sb.append("; ")
                .append(ParameterIntegrityDetailReporter.detailPointer("url_params_truncated"));
        sb.append('.');
        return sb.toString();
    }

    private static long droppedTotal(Map<String, Integer> urlDroppedTotals) {
        long totalDropped = 0L;
        for (int dropped : urlDroppedTotals.values()) {
            totalDropped += dropped;
        }
        return totalDropped;
    }

    private static String dedupeUrl(HttpRequest request, HttpService service, Map<String, Object> requestDoc) {
        String direct = RequestResponseDocBuilder.safeRequestUrl(request, "UrlParameterCap");
        if (direct != null) {
            return direct;
        }
        String rebuilt = RequestResponseDocBuilder.buildBestEffortUrl(request, service, requestDoc, "UrlParameterCap");
        if (rebuilt != null) {
            return rebuilt;
        }
        String path = RequestResponseDocBuilder.requestPathWithQuery(requestDoc);
        return path == null ? "unknown" : path;
    }

}
