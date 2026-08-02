package ai.anomalousvectors.tools.burp.utils.export;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.opensearch.BulkByteBudget;

/**
 * Unit tests for {@link SearchBodyPrefixFitter}.
 */
class SearchBodyPrefixFitterTest {

    private ConfigState.State previous;

    @AfterEach
    void tearDown() {
        ExportStats.resetForTests();
        BulkByteBudget.clear();
        if (previous != null) {
            RuntimeConfig.updateState(previous);
            previous = null;
        }
    }

    @Test
    void fitToLiveBudget_deepCopiesNestedSetIntoMutableOrderedCollection() {
        previous = RuntimeConfig.getState();
        configureAmazonBudget();
        BulkByteBudget.resetForStart();
        String originalValue = "x".repeat(2_000_000);
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("name", "X-Large");
        header.put("value", originalValue);
        Set<Map<String, Object>> headers =
                Collections.unmodifiableSet(new LinkedHashSet<>(List.of(header)));
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("request", Map.of("headers", headers));
        PreparedExportDocument original =
                ExportDocumentIdentity.prepare("tool-burp-traffic", "traffic", document);

        PreparedExportDocument fitted = SearchBodyPrefixFitter.fitToLiveBudget(original);

        assertThat(fitted).isNotSameAs(original);
        assertThat(headers).hasSize(1);
        assertThat(header.get("value")).isSameAs(originalValue);
        Map<?, ?> fittedRequest = (Map<?, ?>) fitted.document().get("request");
        assertThat(fittedRequest.get("headers")).isInstanceOf(List.class);
        assertThat(fitted.resolvedBulkBytes()).isLessThanOrEqualTo(BulkByteBudget.currentMaxBytes());
    }

    @Test
    void fitToLiveBudget_alreadyFits_returnsSameInstance() {
        previous = RuntimeConfig.getState();
        configureAmazonBudget();
        BulkByteBudget.resetForStart();

        Map<String, Object> doc = trafficDocWithBody(32);
        PreparedExportDocument prepared = ExportDocumentIdentity.prepare("tool-burp-traffic", "traffic", doc);

        PreparedExportDocument fitted = SearchBodyPrefixFitter.fitToLiveBudget(prepared);

        assertThat(fitted).isSameAs(prepared);
        assertThat(SearchBodyPrefixFitter.didTruncate(prepared, fitted)).isFalse();
    }

    @Test
    void fitToLiveBudget_oversizedBody_prefixesAndSetsTruncated() {
        previous = RuntimeConfig.getState();
        configureAmazonBudget();
        BulkByteBudget.resetForStart();
        BulkByteBudget.applyRateLimitPressure(429, "tool-burp-traffic", "Prepared bulk", 5_000L);
        long ceiling = BulkByteBudget.currentMaxBytes();
        assertThat(ceiling).isEqualTo(BulkByteBudget.AMAZON_MIN_BYTES);

        int wireBytes = (int) Math.min(Integer.MAX_VALUE, ceiling + (512 * 1024));
        Map<String, Object> doc = trafficDocWithBody(wireBytes);
        PreparedExportDocument prepared = ExportDocumentIdentity.prepare("tool-burp-traffic", "traffic", doc);
        assertThat(prepared.resolvedBulkBytes()).isGreaterThan(ceiling);

        Object originalLength = ((Map<?, ?>) ((Map<?, ?>) prepared.document().get("response")).get("body"))
                .get("length");

        PreparedExportDocument fitted = SearchBodyPrefixFitter.fitToLiveBudget(prepared);
        assertThat(SearchBodyPrefixFitter.didTruncate(prepared, fitted)).isTrue();
        assertThat(fitted.resolvedBulkBytes()).isLessThanOrEqualTo(ceiling);
        assertThat(fitted.operationId()).isEqualTo(prepared.operationId());
        Map<?, ?> fittedMeta = (Map<?, ?>) fitted.document().get("meta");
        assertThat(fittedMeta.get("search_truncated")).isEqualTo(Boolean.TRUE);

        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) ((Map<String, Object>) fitted.document().get("response"))
                .get("body");
        assertThat(body.get("truncated")).isEqualTo(Boolean.TRUE);
        assertThat(body.get("length")).isEqualTo(originalLength);
        String b64 = (String) body.get("b64");
        assertThat(b64).isNotNull();
        assertThat(b64.length()).isLessThan(Base64.getEncoder().encodeToString(new byte[wireBytes]).length());
        @SuppressWarnings("unchecked")
        Map<String, Object> originalBody =
                (Map<String, Object>) ((Map<String, Object>) prepared.document().get("response")).get("body");
        assertThat(originalBody.get("truncated")).isNull();
    }

    @Test
    void fitToLiveBudget_largeStringWithoutBody_truncatesUntilFits() {
        previous = RuntimeConfig.getState();
        configureAmazonBudget();
        BulkByteBudget.resetForStart();
        BulkByteBudget.applyRateLimitPressure(429, "tool-burp-findings", "Prepared bulk", 5_000L);
        long ceiling = BulkByteBudget.currentMaxBytes();

        Map<String, Object> issue = new LinkedHashMap<>();
        issue.put("description", "x".repeat((int) ceiling + 64));
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("issue", issue);
        PreparedExportDocument prepared = ExportDocumentIdentity.prepare("tool-burp-findings", "findings", doc);
        assertThat(prepared.resolvedBulkBytes()).isGreaterThan(ceiling);

        PreparedExportDocument fitted = SearchBodyPrefixFitter.fitToLiveBudget(prepared);
        assertThat(SearchBodyPrefixFitter.didTruncate(prepared, fitted)).isTrue();
        assertThat(fitted.resolvedBulkBytes()).isLessThanOrEqualTo(ceiling);
        @SuppressWarnings("unchecked")
        Map<String, Object> fittedIssue = (Map<String, Object>) fitted.document().get("issue");
        assertThat(((String) fittedIssue.get("description")).length()).isLessThan((int) ceiling + 64);
    }

    @Test
    void fitToLiveBudget_largeHeaderValue_truncates() {
        previous = RuntimeConfig.getState();
        configureAmazonBudget();
        BulkByteBudget.resetForStart();
        BulkByteBudget.applyRateLimitPressure(429, "tool-burp-traffic", "Prepared bulk", 5_000L);
        long ceiling = BulkByteBudget.currentMaxBytes();

        Map<String, Object> header = new LinkedHashMap<>();
        header.put("name", "Cookie");
        header.put("value", "y".repeat((int) ceiling));
        header.put("raw", "Cookie: " + "y".repeat((int) ceiling));
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("headers", List.of(header));
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("request", request);

        PreparedExportDocument prepared = ExportDocumentIdentity.prepare("tool-burp-traffic", "traffic", doc);
        assertThat(prepared.resolvedBulkBytes()).isGreaterThan(ceiling);

        PreparedExportDocument fitted = SearchBodyPrefixFitter.fitToLiveBudget(prepared);
        assertThat(fitted.resolvedBulkBytes()).isLessThanOrEqualTo(ceiling);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> headers =
                (List<Map<String, Object>>) ((Map<String, Object>) fitted.document().get("request")).get("headers");
        assertThat(headers.get(0).get("truncated")).isEqualTo(Boolean.TRUE);
        assertThat(((String) headers.get(0).get("value")).length()).isLessThan((int) ceiling);
    }

    @Test
    void fitToLiveBudget_findingsNestedBodies_truncates() {
        previous = RuntimeConfig.getState();
        configureAmazonBudget();
        BulkByteBudget.resetForStart();
        BulkByteBudget.applyRateLimitPressure(429, "tool-burp-findings", "Prepared bulk", 5_000L);
        long ceiling = BulkByteBudget.currentMaxBytes();

        int wireBytes = (int) Math.min(Integer.MAX_VALUE, ceiling);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("length", wireBytes);
        body.put("offset", 0);
        body.put("b64", Base64.getEncoder().encodeToString(new byte[wireBytes]));
        body.put("text", null);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("body", body);
        Map<String, Object> pair = new LinkedHashMap<>();
        pair.put("response", response);
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("requests_responses", List.of(pair));

        PreparedExportDocument prepared = ExportDocumentIdentity.prepare("tool-burp-findings", "findings", doc);
        if (!BulkByteBudget.exceedsLiveBudget(prepared.resolvedBulkBytes())) {
            byte[] bigger = new byte[wireBytes * 2];
            body.put("length", bigger.length);
            body.put("b64", Base64.getEncoder().encodeToString(bigger));
            prepared = ExportDocumentIdentity.prepare("tool-burp-findings", "findings", doc);
        }
        assertThat(prepared.resolvedBulkBytes()).isGreaterThan(ceiling);

        PreparedExportDocument fitted = SearchBodyPrefixFitter.fitToLiveBudget(prepared);
        assertThat(fitted.resolvedBulkBytes()).isLessThanOrEqualTo(ceiling);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> rr = (List<Map<String, Object>>) fitted.document().get("requests_responses");
        @SuppressWarnings("unchecked")
        Map<String, Object> fittedBody =
                (Map<String, Object>) ((Map<String, Object>) rr.get(0).get("response")).get("body");
        assertThat(fittedBody.get("truncated")).isEqualTo(Boolean.TRUE);
    }

    @Test
    void fitToLiveBudget_trimsTrailingListElementsWhenStringsAlreadyEmpty() {
        previous = RuntimeConfig.getState();
        configureAmazonBudget();
        BulkByteBudget.resetForStart();
        BulkByteBudget.applyRateLimitPressure(429, "tool-burp-findings", "Prepared bulk", 5_000L);
        long ceiling = BulkByteBudget.currentMaxBytes();

        // Many medium nested pairs: after string shrink, list trim must bring NDJSON under budget.
        List<Map<String, Object>> pairs = new ArrayList<>();
        int pairPad = 8 * 1024;
        for (int i = 0; i < 200; i++) {
            Map<String, Object> header = new LinkedHashMap<>();
            header.put("name", "X-Pad");
            header.put("value", "z".repeat(pairPad));
            Map<String, Object> request = new LinkedHashMap<>();
            request.put("headers", List.of(header));
            Map<String, Object> pair = new LinkedHashMap<>();
            pair.put("request", request);
            pairs.add(pair);
        }
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("requests_responses", pairs);
        PreparedExportDocument prepared = ExportDocumentIdentity.prepare("tool-burp-findings", "findings", doc);
        assertThat(prepared.resolvedBulkBytes()).isGreaterThan(ceiling);

        PreparedExportDocument fitted = SearchBodyPrefixFitter.fitToLiveBudget(prepared);
        assertThat(fitted.resolvedBulkBytes()).isLessThanOrEqualTo(ceiling);
        // String shrink and/or trailing-list trim may both contribute; only require a fit.
        assertThat(SearchBodyPrefixFitter.didTruncate(prepared, fitted)).isTrue();
    }

    @Test
    void truncationAccounting_countsStableOperationOnlyOnce() {
        PreparedExportDocument prepared = ExportDocumentIdentity.prepare(
                "tool-burp-findings", "findings", Map.of("message", "large"));

        boolean first = ExportStats.recordSearchBodyPrefixTruncationOnce(
                prepared.operationId(), prepared.indexKey());
        boolean retry = ExportStats.recordSearchBodyPrefixTruncationOnce(
                prepared.operationId(), prepared.indexKey());

        assertThat(first).isTrue();
        assertThat(retry).isFalse();
        assertThat(ExportStats.getSearchBodyPrefixTruncations()).isEqualTo(1);
        assertThat(ExportStats.getSearchBodyPrefixTruncations("findings")).isEqualTo(1);
    }

    @Test
    void fitToBudget_usesExplicitCeilingWithoutMutatingOriginal() {
        Map<String, Object> document = trafficDocWithBody(256 * 1024);
        PreparedExportDocument original =
                ExportDocumentIdentity.prepare("tool-burp-traffic", "traffic", document);
        Map<String, Object> originalPreparedDocument = original.document();
        long target = 128 * 1024L;

        PreparedExportDocument fitted = SearchBodyPrefixFitter.fitToBudget(original, target);

        assertThat(fitted).isNotSameAs(original);
        assertThat(fitted.resolvedBulkBytes()).isLessThanOrEqualTo(target);
        assertThat(original.document()).isSameAs(originalPreparedDocument);
        assertThat(((Map<?, ?>) original.document().get("meta")).get("search_truncated")).isNull();
    }

    @Test
    void fitToBudget_laterLargerBudgetCanDeriveHigherFidelityFromOriginal() {
        PreparedExportDocument original = ExportDocumentIdentity.prepare(
                "tool-burp-traffic", "traffic", trafficDocWithBody(768 * 1024));

        PreparedExportDocument floorFit = SearchBodyPrefixFitter.fitToBudget(original, 128 * 1024L);
        PreparedExportDocument recoveredFit = SearchBodyPrefixFitter.fitToBudget(original, 512 * 1024L);

        assertThat(floorFit.resolvedBulkBytes()).isLessThanOrEqualTo(128 * 1024L);
        assertThat(recoveredFit.resolvedBulkBytes()).isLessThanOrEqualTo(512 * 1024L);
        assertThat(recoveredFit.resolvedBulkBytes()).isGreaterThan(floorFit.resolvedBulkBytes());
        assertThat(((Map<?, ?>) original.document().get("meta")).get("search_truncated")).isNull();
    }

    @Test
    void fitToBudget_preservedMetadataCanRemainOverAbsoluteMaximum() {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", "1");
        meta.put("opaque", "x".repeat((int) BulkByteBudget.ADAPTIVE_MAX_BYTES + 1024));
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("meta", meta);
        document.put("request", Map.of(
                "url", Map.of("raw", "https://large.example/download?id=secret")));
        PreparedExportDocument original =
                ExportDocumentIdentity.prepare("tool-burp-traffic", "traffic", document);

        PreparedExportDocument fitted = SearchBodyPrefixFitter.fitToBudget(
                original, BulkByteBudget.ADAPTIVE_MAX_BYTES);

        assertThat(fitted.resolvedBulkBytes()).isGreaterThan(BulkByteBudget.ADAPTIVE_MAX_BYTES);
        assertThat(((Map<?, ?>) original.document().get("meta")).get("opaque"))
                .isEqualTo(meta.get("opaque"));
        assertThat(SearchBodyPrefixFitter.diagnosticRequestUrl(original))
                .isEqualTo("https://large.example/download?id=secret");
    }

    @Test
    void diagnosticRequestUrl_fallsBackToFindingTargetAndSanitizesLineBreaks() {
        PreparedExportDocument finding = ExportDocumentIdentity.prepare(
                "tool-burp-findings",
                "findings",
                Map.of("target", Map.of("url", "https://target.example/a?x=1\r\nforged")));

        assertThat(SearchBodyPrefixFitter.diagnosticRequestUrl(finding))
                .isEqualTo("https://target.example/a?x=1  forged");
    }

    private static void configureAmazonBudget() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_SETTINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, "", false, true,
                        true, ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                        true, ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                        true, "https://opensearch.url:9200", "", "",
                        ConfigState.OPEN_SEARCH_TLS_VERIFY,
                        ConfigState.defaultOpenSearchOptions(),
                        ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey(),
                        "https://amazon-opensearch.example",
                        ConfigState.defaultOpenSearchAmazonOptions(),
                        "http://localhost:9201",
                        ConfigState.defaultElasticsearchOptions()),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
    }

    private static Map<String, Object> trafficDocWithBody(int wireBytes) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("length", wireBytes);
        body.put("offset", 0);
        body.put("b64", Base64.getEncoder().encodeToString(new byte[wireBytes]));
        body.put("text", "x".repeat(Math.min(wireBytes, 4096)));
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("body", body);
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("response", response);
        doc.put("meta", Map.of(
                "schema_version", "1",
                "extension_version", "test",
                "indexed_at", "2026-07-31T00:00:00Z"));
        return doc;
    }
}
