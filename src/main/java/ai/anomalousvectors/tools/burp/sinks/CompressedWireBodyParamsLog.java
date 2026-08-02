package ai.anomalousvectors.tools.burp.sinks;

import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.concurrent.LazyScheduler;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Rolls up compressed-wire BODY parameter corrections for operator analysis.
 *
 * <p>Emits one DEBUG rollup at startup backlog complete, Stop, and each periodic live flush.
 * First live replace or skip-path rescue notices are also DEBUG so the family stays at one
 * LogPanel level.</p>
 */
public final class CompressedWireBodyParamsLog {

    /** Live periodic summary interval while export is running. */
    static final int PERIODIC_INTERVAL_SECONDS = 60;

    /** Categories recorded for compressed-wire BODY parameter analysis. */
    enum Category {
        /** Burp wire BODY rows replaced by supplemental logical parse. */
        REPLACED,
        /** Wire transformed; supplemental empty; Burp BODY rows dropped. */
        WIRE_DROPPED,
        /** Supplemental BODY added when Burp enumerated none (uncompressed wire path). */
        SUPPLEMENTAL_ADDED,
        /** Supplemental logical parse rejected because the body was not form-like. */
        SUPPLEMENTAL_REJECTED_NON_FORM,
        /** BODY enumeration was skipped, but urlencoded logical bytes still produced supplemental BODY rows. */
        SKIP_RESCUED
    }

    private static final Object LOCK = new Object();
    private static final LazyScheduler SCHEDULER =
            new LazyScheduler("burp-exporter-compressed-wire-body-params-log");

    private static final Map<Category, Integer> STARTUP_DOC_COUNTS = new EnumMap<>(Category.class);
    private static final Map<Category, Map<String, Integer>> STARTUP_URLS = new EnumMap<>(Category.class);
    private static final Map<Category, Integer> LIVE_PENDING_DOC_COUNTS = new EnumMap<>(Category.class);
    private static final Map<Category, Map<String, Integer>> LIVE_PENDING_URLS = new EnumMap<>(Category.class);
    private static final Set<String> LIVE_NOTICED_URLS = ConcurrentHashMap.newKeySet();

    private static boolean startupSummaryEmitted;
    private static boolean startupAccumulationActive;

    private CompressedWireBodyParamsLog() {}

    /** Clears per-run aggregation state without logging. */
    public static void startForCurrentRun() {
        synchronized (LOCK) {
            clearCategoryMaps(STARTUP_DOC_COUNTS, STARTUP_URLS);
            clearCategoryMaps(LIVE_PENDING_DOC_COUNTS, LIVE_PENDING_URLS);
            LIVE_NOTICED_URLS.clear();
            startupSummaryEmitted = false;
            startupAccumulationActive = true;
        }
    }

    /**
     * Starts the periodic live summary scheduler.
     *
     * <p>Safe to call from any thread. No-op when already started.</p>
     */
    public static void startPeriodicFlusher() {
        if (SCHEDULER.isStarted()) {
            return;
        }
        synchronized (CompressedWireBodyParamsLog.class) {
            if (SCHEDULER.isStarted()) {
                return;
            }
            SCHEDULER.getOrStart().scheduleAtFixedRate(
                    CompressedWireBodyParamsLog::flushPeriodicSummary,
                    PERIODIC_INTERVAL_SECONDS,
                    PERIODIC_INTERVAL_SECONDS,
                    TimeUnit.SECONDS);
        }
    }

    /**
     * Flushes pending live summary, stops the periodic scheduler, and clears live state.
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
     * Records one compressed-wire BODY parameter correction event.
     *
     * @param request source request
     * @param service optional HTTP service for URL reconstruction
     * @param requestDoc built request sub-document
     * @param category correction category
     */
    static void record(
            HttpRequest request,
            HttpService service,
            Map<String, Object> requestDoc,
            Category category) {
        if (category == null) {
            return;
        }
        String dedupeUrl = dedupeUrl(request, service, requestDoc);
        boolean liveNotice;
        synchronized (LOCK) {
            if (startupAccumulationActive) {
                STARTUP_DOC_COUNTS.compute(category, (k, v) -> v == null ? 1 : v + 1);
                urlBucketFor(STARTUP_URLS, category).compute(dedupeUrl, (k, v) -> v == null ? 1 : v + 1);
                liveNotice = false;
            } else {
                LIVE_PENDING_DOC_COUNTS.compute(category, (k, v) -> v == null ? 1 : v + 1);
                urlBucketFor(LIVE_PENDING_URLS, category).compute(dedupeUrl, (k, v) -> v == null ? 1 : v + 1);
                liveNotice = category == Category.REPLACED || category == Category.SKIP_RESCUED;
            }
        }
        if (liveNotice) {
            maybeLogLiveNotice(dedupeUrl, category);
        }
    }

    /**
     * Emits startup/backlog DEBUG summaries when any events were recorded.
     *
     * <p>Safe to call multiple times; only the first emission logs.</p>
     */
    public static void flushStartupSummary() {
        String summaryLine;
        Map<Category, Integer> docCounts;
        Map<Category, Map<String, Integer>> urlCounts;
        synchronized (LOCK) {
            startupAccumulationActive = false;
            summaryLine = null;
            docCounts = Map.of();
            urlCounts = Map.of();
            if (!startupSummaryEmitted && hasAnyDocs(STARTUP_DOC_COUNTS)) {
                startupSummaryEmitted = true;
                docCounts = copyDocCounts(STARTUP_DOC_COUNTS);
                urlCounts = copyUrlCounts(STARTUP_URLS);
                summaryLine = formatSummaryLocked("startup/backlog", docCounts, urlCounts);
                clearCategoryMaps(STARTUP_DOC_COUNTS, STARTUP_URLS);
            }
        }
        if (summaryLine != null) {
            reportDetails("startup_backlog", docCounts, urlCounts);
            Logger.logDebug(summaryLine);
        }
    }

    /**
     * Emits DEBUG summaries for live events accumulated since the last periodic flush.
     *
     * <p>Log text uses phase {@code periodic/live} so operators can tell scheduled rollups from
     * startup/stop summaries.</p>
     */
    public static void flushPeriodicSummary() {
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        String summaryLine;
        Map<Category, Integer> docCounts;
        Map<Category, Map<String, Integer>> urlCounts;
        synchronized (LOCK) {
            if (!hasAnyDocs(LIVE_PENDING_DOC_COUNTS)) {
                return;
            }
            docCounts = copyDocCounts(LIVE_PENDING_DOC_COUNTS);
            urlCounts = copyUrlCounts(LIVE_PENDING_URLS);
            summaryLine = formatSummaryLocked("periodic/live", docCounts, urlCounts);
            clearCategoryMaps(LIVE_PENDING_DOC_COUNTS, LIVE_PENDING_URLS);
        }
        if (summaryLine != null) {
            reportDetails("periodic/live", docCounts, urlCounts);
            Logger.logDebug(summaryLine);
        }
    }

    /** Emits final DEBUG summaries for live events not yet flushed. */
    public static void flushStopSummary() {
        flushStopDebugSamples();
    }

    /**
     * Emits a DEBUG summary for live compressed-wire events not yet flushed.
     *
     * <p>Session totals are INFO from {@link ParameterIntegritySessionLog}.</p>
     */
    public static void flushStopDebugSamples() {
        String line;
        Map<Category, Integer> docCounts;
        Map<Category, Map<String, Integer>> urlCounts;
        synchronized (LOCK) {
            line = null;
            docCounts = Map.of();
            urlCounts = Map.of();
            if (hasAnyDocs(LIVE_PENDING_DOC_COUNTS)) {
                docCounts = copyDocCounts(LIVE_PENDING_DOC_COUNTS);
                urlCounts = copyUrlCounts(LIVE_PENDING_URLS);
                line = formatSummaryLocked("stop", docCounts, urlCounts);
                clearCategoryMaps(LIVE_PENDING_DOC_COUNTS, LIVE_PENDING_URLS);
            }
        }
        reportDetails("stop", docCounts, urlCounts);
        if (line != null) {
            Logger.logDebug(line);
        }
    }

    static String formatSummaryForTests(String phase, Map<Category, Integer> docCounts) {
        synchronized (LOCK) {
            return formatSummaryLocked(phase, docCounts, Map.of());
        }
    }

    private static void maybeLogLiveNotice(String url, Category category) {
        String key = category.name() + "|" + url;
        if (!LIVE_NOTICED_URLS.add(key)) {
            return;
        }
        String label = category == Category.SKIP_RESCUED
                ? "skip-path BODY params rescued"
                : "compressed-wire BODY params replaced";
        Logger.logDebug("[ParameterIntegrity] " + label + "; "
                + ParameterIntegrityDetailReporter.detailPointer(categoryKey(category)) + ".");
    }

    private static String formatSummaryLocked(
            String phase,
            Map<Category, Integer> docCounts,
            Map<Category, Map<String, Integer>> urlCounts) {
        int replaced = docCounts.getOrDefault(Category.REPLACED, 0);
        int dropped = docCounts.getOrDefault(Category.WIRE_DROPPED, 0);
        int supplemental = docCounts.getOrDefault(Category.SUPPLEMENTAL_ADDED, 0);
        int rejected = docCounts.getOrDefault(Category.SUPPLEMENTAL_REJECTED_NON_FORM, 0);
        int rescued = docCounts.getOrDefault(Category.SKIP_RESCUED, 0);
        if (replaced + dropped + supplemental + rejected + rescued <= 0) {
            return null;
        }
        return "[ParameterIntegrity] compressed_wire_body_params during " + phase + ": wire_replaced="
                + countAndUrls(Category.REPLACED, replaced, urlCounts)
                + ", wire_dropped=" + countAndUrls(Category.WIRE_DROPPED, dropped, urlCounts)
                + ", supplemental_added=" + countAndUrls(Category.SUPPLEMENTAL_ADDED, supplemental, urlCounts)
                + ", supplemental_rejected_non_form="
                + countAndUrls(Category.SUPPLEMENTAL_REJECTED_NON_FORM, rejected, urlCounts)
                + ", skip_path_rescued=" + countAndUrls(Category.SKIP_RESCUED, rescued, urlCounts)
                + ". "
                + ParameterIntegrityDetailReporter.compressedWireSummaryPointer()
                + ". See Stats → Parameter Integrity session totals.";
    }

    private static String countAndUrls(
            Category category,
            int docCount,
            Map<Category, Map<String, Integer>> urlCounts) {
        Map<String, Integer> urls = urlCounts == null ? null : urlCounts.get(category);
        return docCount + "/" + (urls == null ? 0 : urls.size()) + " url(s)";
    }

    private static boolean hasAnyDocs(Map<Category, Integer> docCounts) {
        for (Integer count : docCounts.values()) {
            if (count != null && count > 0) {
                return true;
            }
        }
        return false;
    }

    private static Map<String, Integer> urlBucketFor(Map<Category, Map<String, Integer>> urls, Category category) {
        return urls.computeIfAbsent(category, ignored -> new LinkedHashMap<>());
    }

    private static void reportDetails(
            String phase,
            Map<Category, Integer> docCounts,
            Map<Category, Map<String, Integer>> urlCounts) {
        for (Category category : Category.values()) {
            int count = docCounts.getOrDefault(category, 0);
            if (count <= 0) {
                continue;
            }
            ParameterIntegrityDetailReporter.report(
                    phase,
                    categoryKey(category),
                    count,
                    urlCounts.getOrDefault(category, Map.of()),
                    Map.of(),
                    impact(category),
                    urlListPolicy(category));
        }
    }

    private static ParameterIntegrityDetailReporter.UrlListPolicy urlListPolicy(Category category) {
        return category == Category.SUPPLEMENTAL_ADDED
                ? ParameterIntegrityDetailReporter.UrlListPolicy.SAMPLE_ONLY
                : ParameterIntegrityDetailReporter.UrlListPolicy.FULL;
    }

    private static String categoryKey(Category category) {
        return switch (category) {
            case REPLACED -> "wire_replaced";
            case WIRE_DROPPED -> "wire_dropped";
            case SUPPLEMENTAL_ADDED -> "supplemental_added";
            case SUPPLEMENTAL_REJECTED_NON_FORM -> "supplemental_rejected_non_form";
            case SKIP_RESCUED -> "skip_path_rescued";
        };
    }

    private static String impact(Category category) {
        return switch (category) {
            case REPLACED -> "Burp wire BODY rows were replaced with logical BODY rows; raw body remains complete";
            case WIRE_DROPPED -> "Burp wire BODY rows were dropped because transformed wire bytes did not match logical form data";
            case SUPPLEMENTAL_ADDED -> "supplemental logical BODY rows were added; raw body remains complete";
            case SUPPLEMENTAL_REJECTED_NON_FORM -> "supplemental logical parse was rejected because the body was not form-like";
            case SKIP_RESCUED -> "BODY rows were recovered from logical bytes after the primary enumeration path skipped them";
        };
    }

    private static Map<Category, Integer> copyDocCounts(Map<Category, Integer> docCounts) {
        Map<Category, Integer> copy = new EnumMap<>(Category.class);
        copy.putAll(docCounts);
        return copy;
    }

    private static Map<Category, Map<String, Integer>> copyUrlCounts(Map<Category, Map<String, Integer>> urlCounts) {
        Map<Category, Map<String, Integer>> copy = new EnumMap<>(Category.class);
        for (Map.Entry<Category, Map<String, Integer>> entry : urlCounts.entrySet()) {
            copy.put(entry.getKey(), new LinkedHashMap<>(entry.getValue()));
        }
        return copy;
    }

    private static void clearCategoryMaps(
            Map<Category, Integer> docCounts,
            Map<Category, Map<String, Integer>> urlCounts) {
        docCounts.clear();
        urlCounts.clear();
    }

    private static String dedupeUrl(HttpRequest request, HttpService service, Map<String, Object> requestDoc) {
        String direct = RequestResponseDocBuilder.safeRequestUrl(request, "CompressedWireBodyParams");
        if (direct != null) {
            return direct;
        }
        String rebuilt = RequestResponseDocBuilder.buildBestEffortUrl(
                request, service, requestDoc, "CompressedWireBodyParams");
        if (rebuilt != null) {
            return rebuilt;
        }
        String path = RequestResponseDocBuilder.requestPathWithQuery(requestDoc);
        return path == null ? "unknown" : path;
    }

}
