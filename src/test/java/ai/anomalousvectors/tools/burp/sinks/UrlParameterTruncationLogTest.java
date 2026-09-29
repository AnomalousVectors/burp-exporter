package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import burp.api.montoya.http.message.requests.HttpRequest;

/** Unit tests for {@link UrlParameterTruncationLog}. */
class UrlParameterTruncationLogTest {

    private final List<String> infoMessages = new CopyOnWriteArrayList<>();
    private final List<String> debugMessages = new CopyOnWriteArrayList<>();
    private final List<String> warnMessages = new CopyOnWriteArrayList<>();
    private final Logger.LogListener listener = (level, message) -> {
        switch (level) {
            case "INFO" -> infoMessages.add(message);
            case "DEBUG" -> debugMessages.add(message);
            case "WARN" -> warnMessages.add(message);
            default -> {
            }
        }
    };

    @BeforeEach
    public void setUp() {
        ExportStats.resetForTests();
        Logger.resetState();
        Logger.registerListener(listener);
        UrlParameterTruncationLog.startForCurrentRun();
    }

    @AfterEach
    public void tearDown() {
        Logger.unregisterListener(listener);
        Logger.resetState();
        ExportStats.resetForTests();
        UrlParameterTruncationLog.clearRunState();
    }

    @Test
    void flushStartupSummary_dedupesByRequestUrl() throws Exception {
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://example.test/fuzz?many=1");
        Map<String, Object> requestDoc = Map.of("path", Map.of("query", "a=1"));

        UrlParameterTruncationLog.record(request, null, requestDoc, 5);
        UrlParameterTruncationLog.record(request, null, requestDoc, 7);
        UrlParameterTruncationLog.flushStartupSummary();
        flushLogListeners();

        assertThat(infoMessages).isEmpty();
        assertThat(debugMessages).hasSize(1);
        assertThat(debugMessages.get(0))
                .contains("1 unique request.url")
                .contains("dropped_url_params=12")
                .contains("No request body data was lost")
                .contains("Reference#url_params_truncated")
                .doesNotContain("Wiki -> Data Integrity -> Logging")
                .doesNotContain("Drill-down if affected endpoints matter")
                .doesNotContain("event.type=parameter_integrity_detail")
                .doesNotContain("category=url_params_truncated")
                .doesNotContain("urls=");
        assertThat(warnMessages).isEmpty();
        assertThat(ExportStats.getDocsUrlParamsTruncated()).isEqualTo(2);
        assertThat(ExportStats.getUrlParamsDroppedTotal()).isEqualTo(12);
    }

    @Test
    void flushStartupSummary_onlyEmitsOnce() throws Exception {
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://example.test/one");
        Map<String, Object> requestDoc = Map.of();

        UrlParameterTruncationLog.record(request, null, requestDoc, 1);
        UrlParameterTruncationLog.flushStartupSummary();
        UrlParameterTruncationLog.flushStartupSummary();
        flushLogListeners();

        assertThat(infoMessages).isEmpty();
        assertThat(debugMessages).hasSize(1);
    }

    @Test
    void afterStartupFlush_liveTruncationsDebugImmediately() throws Exception {
        HttpRequest first = mock(HttpRequest.class);
        when(first.url()).thenReturn("https://example.test/live-a");
        HttpRequest second = mock(HttpRequest.class);
        when(second.url()).thenReturn("https://example.test/live-b");
        Map<String, Object> requestDoc = Map.of();

        UrlParameterTruncationLog.flushStartupSummary();
        UrlParameterTruncationLog.record(first, null, requestDoc, 2);
        UrlParameterTruncationLog.record(second, null, requestDoc, 3);
        flushLogListeners();

        assertThat(infoMessages).isEmpty();
        assertThat(warnMessages).isEmpty();
        assertThat(debugMessages).hasSize(2);
        assertThat(debugMessages.get(0))
                .contains("No request body data was lost")
                .contains("Reference#url_params_truncated")
                .doesNotContain("category=url_params_truncated")
                .doesNotContain("live-a")
                .doesNotContain("...");
        assertThat(debugMessages.get(1))
                .contains("URL parameters truncated")
                .doesNotContain("category=url_params_truncated")
                .doesNotContain("live-b")
                .doesNotContain("...");
    }

    @Test
    void flushStopSummary_emitsPendingLiveOverflowRemainder() throws Exception {
        Map<String, Object> requestDoc = Map.of();

        UrlParameterTruncationLog.flushStartupSummary();
        for (int i = 0; i <= UrlParameterTruncationLog.LIVE_UNIQUE_URL_LOG_CAP; i++) {
            HttpRequest request = mock(HttpRequest.class);
            when(request.url()).thenReturn("https://example.test/live-" + i);
            UrlParameterTruncationLog.record(request, null, requestDoc, 1);
        }
        UrlParameterTruncationLog.flushStopSummary();
        flushLogListeners();

        assertThat(debugMessages).hasSize(UrlParameterTruncationLog.LIVE_UNIQUE_URL_LOG_CAP + 1);
        assertThat(debugMessages.get(debugMessages.size() - 1))
                .contains("URL parameters truncated for 1 additional unique request.url")
                .contains("Reference#url_params_truncated");
        assertThat(warnMessages).isEmpty();
    }

    @Test
    void liveOverflowSummary_reportsAdditionalUrlsSincePreviousSummary() throws Exception {
        Map<String, Object> requestDoc = Map.of();

        UrlParameterTruncationLog.flushStartupSummary();
        for (int i = 0; i < UrlParameterTruncationLog.LIVE_UNIQUE_URL_LOG_CAP + 50; i++) {
            HttpRequest request = mock(HttpRequest.class);
            when(request.url()).thenReturn("https://example.test/live-" + i);
            UrlParameterTruncationLog.record(request, null, requestDoc, 1);
        }
        flushLogListeners();

        assertThat(debugMessages)
                .filteredOn(message -> message.contains("additional unique request.url"))
                .hasSize(2)
                .allSatisfy(message -> assertThat(message)
                        .contains("URL parameters truncated for 25 additional unique request.url")
                        .doesNotContain("for 50 additional"));
    }

    @Test
    void formatStartupSummaryForTests_listsSampleUrls() {
        Map<String, Integer> totals = new LinkedHashMap<>();
        totals.put("https://example.test/a", 4);
        totals.put("https://example.test/b", 6);

        String line = UrlParameterTruncationLog.formatStartupSummaryForTests(totals);

        assertThat(line)
                .contains("2 unique request.url")
                .contains("dropped_url_params=10")
                .contains("Reference#url_params_truncated")
                .doesNotContain("event.type=parameter_integrity_detail")
                .doesNotContain("category=url_params_truncated")
                .doesNotContain("https://example.test/a")
                .doesNotContain("https://example.test/b");
    }

    private static void flushLogListeners() throws Exception {
        SwingUtilities.invokeAndWait(() -> {});
    }
}
