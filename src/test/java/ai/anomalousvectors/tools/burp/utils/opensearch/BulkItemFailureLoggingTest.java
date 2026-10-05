package ai.anomalousvectors.tools.burp.utils.opensearch;

import ai.anomalousvectors.tools.burp.utils.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the per-item bulk-failure observability contract: per-item bulk failures emit a single structured
 * DEBUG log line with {@code index=}, {@code op=}, {@code type=}, and {@code reason=} tokens.
 * Covers both the chunked traffic path ({@link ChunkedBulkSender#parseBulkResponse}) and the
 * shared formatter used by {@link OpenSearchClientWrapper}.
 */
class BulkItemFailureLoggingTest {

    private final List<LoggedEvent> events = new CopyOnWriteArrayList<>();
    private final Logger.LogListener listener = (level, message) -> events.add(new LoggedEvent(level, message));

    @BeforeEach
    public void registerLogListener() {
        Logger.resetState();
        Logger.registerListener(listener);
    }

    @AfterEach
    public void unregisterLogListener() {
        Logger.unregisterListener(listener);
        Logger.resetState();
        events.clear();
    }

    @Test
    void chunkedParse_failedItem_emitsStructuredErrorWithIndexAndType() throws Exception {
        String body = "{\"took\":1,\"errors\":true,\"items\":["
                + "{\"index\":{\"_index\":\"t\",\"status\":201}},"
                + "{\"index\":{\"_index\":\"t\",\"status\":400,\"error\":{"
                + "\"type\":\"mapper_parsing_exception\","
                + "\"reason\":\"Document contains at least one immense term\"}}}]}";

        SwingUtilities.invokeAndWait(() ->
                ChunkedBulkSender.parseBulkResponse(body, 2, List.of(), "tool-burp-traffic"));

        assertThat(events).anySatisfy(e -> {
            assertThat(e.level()).isEqualToIgnoringCase("debug");
            assertThat(e.message())
                    .contains("[OpenSearch] Bulk item failure:")
                    .contains("index=tool-burp-traffic")
                    .contains("op=1")
                    .contains("type=mapper_parsing_exception")
                    .contains("reason=Document contains at least one immense term");
        });
    }

    @Test
    void chunkedParse_manyFailures_logsCappedItemsPlusSummary() throws Exception {
        StringBuilder body = new StringBuilder("{\"took\":1,\"errors\":true,\"items\":[");
        int total = 5;
        for (int i = 0; i < total; i++) {
            if (i > 0) body.append(',');
            body.append("{\"index\":{\"_index\":\"t\",\"status\":400,\"error\":{"
                    + "\"type\":\"mapper_parsing_exception\",\"reason\":\"bad-")
                    .append(i).append("\"}}}");
        }
        body.append("]}");

        SwingUtilities.invokeAndWait(() ->
                ChunkedBulkSender.parseBulkResponse(body.toString(), total, List.of(), "sitemap-idx"));

        long perItemLines = events.stream()
                .map(event -> event.message())
                .filter(m -> m.contains("Bulk item failure:"))
                .count();
        assertThat(perItemLines).isEqualTo(3);
        assertThat(events).anySatisfy(e -> assertThat(e.message())
                .contains("Bulk item failure summary")
                .contains("index=sitemap-idx")
                .contains("additional=" + (total - 3))
                .contains("totalFailed=" + total));
    }

    @Test
    void formatBulkItemFailure_clampsLongReasons() {
        String longReason = "x".repeat(1000);
        String formatted = OpenSearchClientWrapper.formatBulkItemFailure("idx", 42, "mapper_parsing_exception", longReason);
        assertThat(formatted)
                .contains("index=idx")
                .contains("op=42")
                .contains("type=mapper_parsing_exception")
                .contains("...");
        // Envelope + clamped reason stays under ~700 chars regardless of input length.
        assertThat(formatted.length()).isLessThan(700);
    }

    @Test
    void formatBulkItemFailure_nullTypeAndReason_fallsBackToUnknown() {
        String formatted = OpenSearchClientWrapper.formatBulkItemFailure("idx", 0, null, null);
        assertThat(formatted)
                .contains("type=unknown")
                .contains("reason=unknown");
    }

    @Test
    void formatBulkItemFailure_normalizesLinesAndRemovesFieldValuePreview() {
        String formatted = OpenSearchClientWrapper.formatBulkItemFailure(
                "idx\r\nforged-index",
                0,
                "mapper\nforged-type",
                "failed\r\n[ERROR] forged; Preview of field's value: 'captured-secret'");

        assertThat(formatted)
                .doesNotContain("\r", "\n", "captured-secret")
                .contains("index=idx forged-index")
                .contains("type=mapper forged-type")
                .contains("Preview of field's value: ***");
    }

    private record LoggedEvent(String level, String message) {
        LoggedEvent {
            level = level == null ? "" : level;
            message = message == null ? "" : message;
        }
    }
}
