package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.http.message.requests.HttpRequest;

/** Unit tests for {@link CompressedWireBodyParamsLog}. */
class CompressedWireBodyParamsLogTest {

    private final ConfigState.State previousState = RuntimeConfig.getState();
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
        RuntimeConfig.updateState(null);
        Logger.resetState();
        Logger.registerListener(listener);
        CompressedWireBodyParamsLog.startForCurrentRun();
    }

    @AfterEach
    public void tearDown() {
        CompressedWireBodyParamsLog.clearRunState();
        Logger.unregisterListener(listener);
        Logger.resetState();
        ExportStats.resetForTests();
        RuntimeConfig.updateState(previousState);
        RuntimeConfig.setExportRunning(false);
    }

    @Test
    void record_replaced_flushesStartupDebugSummaries() throws Exception {
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://example.test/form");
        Map<String, Object> requestDoc = Map.of("url", "https://example.test/form");

        CompressedWireBodyParamsLog.record(
                request, null, requestDoc, CompressedWireBodyParamsLog.Category.REPLACED);
        CompressedWireBodyParamsLog.flushStartupSummary();
        flushLogListeners();

        assertThat(infoMessages).isEmpty();
        assertThat(debugMessages).hasSize(1);
        assertThat(debugMessages.get(0))
                .contains("[ParameterIntegrity]")
                .contains("compressed_wire_body_params")
                .contains("wire_replaced=1/1 url(s)")
                .contains("startup/backlog")
                .contains("No raw body data was lost")
                .contains("Reference#compressed_wire_body_params")
                .doesNotContain("Reference#wire_replaced")
                .doesNotContain("Wiki -> Data Integrity -> Logging")
                .doesNotContain("event.type=parameter_integrity_detail")
                .doesNotContain("category=wire_replaced")
                .doesNotContain("https://example.test/form")
                .doesNotContain("...");
    }

    @Test
    void record_supplementalRejected_flushesDistinctCategory() throws Exception {
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://example.test/rejected");
        Map<String, Object> requestDoc = Map.of("url", "https://example.test/rejected");

        CompressedWireBodyParamsLog.record(
                request,
                null,
                requestDoc,
                CompressedWireBodyParamsLog.Category.SUPPLEMENTAL_REJECTED_NON_FORM);
        CompressedWireBodyParamsLog.flushStartupSummary();
        flushLogListeners();

        assertThat(infoMessages).isEmpty();
        assertThat(debugMessages).hasSize(1);
        assertThat(debugMessages.get(0))
                .contains("supplemental_rejected_non_form=1/1 url(s)")
                .contains("Reference#compressed_wire_body_params")
                .doesNotContain("Reference#supplemental_rejected_non_form")
                .doesNotContain("event.type=parameter_integrity_detail")
                .doesNotContain("category=supplemental_rejected_non_form")
                .doesNotContain("https://example.test/rejected")
                .doesNotContain("...");
    }

    @Test
    void record_liveReplaced_emitsDebugOncePerUrl() throws Exception {
        RuntimeConfig.setExportRunning(true);
        CompressedWireBodyParamsLog.flushStartupSummary();
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://example.test/live");
        Map<String, Object> requestDoc = Map.of("url", "https://example.test/live");

        CompressedWireBodyParamsLog.record(
                request, null, requestDoc, CompressedWireBodyParamsLog.Category.REPLACED);
        CompressedWireBodyParamsLog.record(
                request, null, requestDoc, CompressedWireBodyParamsLog.Category.REPLACED);
        flushLogListeners();

        assertThat(warnMessages).isEmpty();
        assertThat(debugMessages).hasSize(1);
        assertThat(debugMessages.get(0))
                .contains("compressed-wire BODY params replaced")
                .contains("Reference#wire_replaced");
    }

    @Test
    void flushStopSummary_emitsPendingLiveCounts() throws Exception {
        RuntimeConfig.setExportRunning(true);
        CompressedWireBodyParamsLog.flushStartupSummary();
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://example.test/stop");
        Map<String, Object> requestDoc = Map.of("url", "https://example.test/stop");

        CompressedWireBodyParamsLog.record(
                request, null, requestDoc, CompressedWireBodyParamsLog.Category.SKIP_RESCUED);
        CompressedWireBodyParamsLog.flushStopSummary();
        flushLogListeners();

        assertThat(debugMessages).hasSize(2);
        assertThat(infoMessages).isEmpty();
        assertThat(debugMessages.get(0))
                .contains("skip-path BODY params rescued")
                .contains("Reference#skip_path_rescued");
        assertThat(debugMessages.get(1))
                .contains("compressed_wire_body_params during stop")
                .contains("skip_path_rescued=1/1 url(s)")
                .contains("Reference#compressed_wire_body_params")
                .doesNotContain("Reference#skip_path_rescued")
                .doesNotContain("event.type=parameter_integrity_detail")
                .doesNotContain("category=skip_path_rescued")
                .doesNotContain("https://example.test/stop")
                .doesNotContain("...");
    }

    @Test
    void clearRunState_dropsPendingLiveCountsWithoutLogging() throws Exception {
        RuntimeConfig.setExportRunning(true);
        CompressedWireBodyParamsLog.flushStartupSummary();
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://example.test/reset");
        Map<String, Object> requestDoc = Map.of("url", "https://example.test/reset");

        CompressedWireBodyParamsLog.record(
                request, null, requestDoc, CompressedWireBodyParamsLog.Category.WIRE_DROPPED);
        CompressedWireBodyParamsLog.clearRunState();
        flushLogListeners();

        assertThat(debugMessages).isEmpty();
        assertThat(infoMessages).isEmpty();
        assertThat(warnMessages).isEmpty();
    }

    @Test
    void formatSummaryForTests_listsAllCategories() {
        Map<CompressedWireBodyParamsLog.Category, Integer> counts = new EnumMap<>(CompressedWireBodyParamsLog.Category.class);
        counts.put(CompressedWireBodyParamsLog.Category.REPLACED, 2);
        counts.put(CompressedWireBodyParamsLog.Category.WIRE_DROPPED, 1);
        counts.put(CompressedWireBodyParamsLog.Category.SUPPLEMENTAL_ADDED, 3);
        counts.put(CompressedWireBodyParamsLog.Category.SKIP_RESCUED, 4);

        String line = CompressedWireBodyParamsLog.formatSummaryForTests("test", counts);

        assertThat(line)
                .contains("wire_replaced=2/0 url(s)")
                .contains("wire_dropped=1/0 url(s)")
                .contains("supplemental_added=3/0 url(s)")
                .contains("supplemental_rejected_non_form=0/0 url(s)")
                .contains("skip_path_rescued=4/0 url(s)")
                .contains("during test")
                .contains("Reference#compressed_wire_body_params")
                .doesNotContain("Reference#wire_replaced")
                .doesNotContain("Wiki -> Data Integrity -> Logging")
                .doesNotContain("event.type=parameter_integrity_detail");
    }

    private static void flushLogListeners() throws Exception {
        SwingUtilities.invokeAndWait(() -> {});
    }
}
