package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.Logger;

class BulkNdjsonResponseParserTest {

    @Test
    void parse_classifiesCreatedUpdatedAndNoop() {
        String body = """
                {"items":[
                  {"index":{"_index":"traffic","_id":"1","status":201,"result":"created"}},
                  {"index":{"_index":"traffic","_id":"2","status":200,"result":"updated"}},
                  {"index":{"_index":"traffic","_id":"3","status":200,"result":"noop"}}
                ]}
                """;

        BulkNdjsonResponseParser.ParsedBulk parsed = BulkNdjsonResponseParser.parse(body, "traffic");

        assertThat(parsed.breakdown().created()).isEqualTo(1);
        assertThat(parsed.breakdown().updated()).isEqualTo(1);
        assertThat(parsed.breakdown().noop()).isEqualTo(1);
        assertThat(parsed.successCount()).isEqualTo(3);
        assertThat(parsed.breakdown().exportedCount()).isEqualTo(2);
    }

    @Test
    void warnIfOutcomeFlagMismatch_includesRequestCorrelationWithoutResponseBody() throws Exception {
        String body = """
                {"errors":true,"items":[
                  {"index":{"_index":"traffic","_id":"sensitive-id","status":201,"result":"created"}}
                ]}
                """;
        List<String> warnings = new CopyOnWriteArrayList<>();
        Logger.LogListener listener = (level, message) -> {
            if ("WARN".equals(level)) {
                warnings.add(message);
            }
        };
        Logger.registerListener(listener);
        try {
            BulkNdjsonResponseParser.ParsedBulk parsed =
                    BulkNdjsonResponseParser.parse(body, "tool-burp-traffic");

            assertThat(parsed.hasOutcomeFlagMismatch()).isTrue();
            BulkNdjsonResponseParser.warnIfOutcomeFlagMismatch(
                    parsed, "tool-burp-traffic", 42L);
            SwingUtilities.invokeAndWait(() -> {});

            assertThat(warnings).singleElement().satisfies(message -> {
                assertThat(message)
                        .contains(
                                "Bulk response outcome mismatch:",
                                "requestId=42",
                                "index=tool-burp-traffic",
                                "responseErrors=true",
                                "parsedFailures=0",
                                "responseItems=1")
                        .doesNotContain("sensitive-id");
            });
        } finally {
            Logger.unregisterListener(listener);
            Logger.resetState();
        }
    }

    @Test
    void warnIfOutcomeFlagMismatch_detectsErrorsFalseWithFailedItem() throws Exception {
        String body = """
                {"errors":false,"items":[
                  {"index":{"_index":"traffic","_id":"sensitive-id","status":400,
                    "error":{"type":"mapper_parsing_exception","reason":"sensitive-reason"}}}
                ]}
                """;
        List<String> warnings = new CopyOnWriteArrayList<>();
        Logger.LogListener listener = (level, message) -> {
            if ("WARN".equals(level)) {
                warnings.add(message);
            }
        };
        Logger.registerListener(listener);
        try {
            BulkNdjsonResponseParser.ParsedBulk parsed =
                    BulkNdjsonResponseParser.parse(body, "tool-burp-traffic");

            assertThat(parsed.hasOutcomeFlagMismatch()).isTrue();
            BulkNdjsonResponseParser.warnIfOutcomeFlagMismatch(
                    parsed, "tool-burp-traffic", 84L);
            SwingUtilities.invokeAndWait(() -> {});

            assertThat(warnings).singleElement().satisfies(message -> {
                assertThat(message)
                        .contains(
                                "requestId=84",
                                "responseErrors=false",
                                "parsedFailures=1",
                                "responseItems=1")
                        .doesNotContain("sensitive-id", "sensitive-reason");
            });
        } finally {
            Logger.unregisterListener(listener);
            Logger.resetState();
        }
    }

    @Test
    void parse_missingOrNonBooleanErrorsFlag_doesNotClaimMismatch() {
        String missing = """
                {"items":[{"index":{"status":201,"result":"created"}}]}
                """;
        String nonBoolean = """
                {"errors":"false","items":[{"index":{"status":400}}]}
                """;

        assertThat(BulkNdjsonResponseParser.parse(missing, "traffic").hasOutcomeFlagMismatch())
                .isFalse();
        assertThat(BulkNdjsonResponseParser.parse(nonBoolean, "traffic").hasOutcomeFlagMismatch())
                .isFalse();
    }
}
