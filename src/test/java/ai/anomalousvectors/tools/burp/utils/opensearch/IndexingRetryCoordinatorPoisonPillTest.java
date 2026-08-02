package ai.anomalousvectors.tools.burp.utils.opensearch;

import ai.anomalousvectors.tools.burp.sinks.TrafficRouteBucket;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the poison-pill behaviour: permanently rejected items are dropped (not re-queued), counted
 * via {@link ExportStats#recordPermanentDrop(String, long)}, and logged once; transient failures
 * pass through to the caller's re-queue list.
 */
class IndexingRetryCoordinatorPoisonPillTest {

    private final List<String> events = new CopyOnWriteArrayList<>();
    private final Logger.LogListener listener = (level, message) -> events.add(level + "|" + message);

    @BeforeEach
    public void registerLogListener() {
        ExportStats.resetForTests();
        Logger.resetState();
        Logger.registerListener(listener);
    }

    @AfterEach
    public void unregisterLogListener() {
        Logger.unregisterListener(listener);
        Logger.resetState();
        ExportStats.resetForTests();
        events.clear();
    }

    @Test
    void permanentFailures_areDropped_andTransientFailuresReturnedForRetry() throws Exception {
        List<PreparedExportDocument> batch = preparedBatch(
                "traffic-index", "traffic",
                List.of(
                        trafficDoc("Proxy History", "permanent-1"),
                        trafficDoc("Repeater", "transient-1"),
                        trafficDoc("Proxy History", "permanent-2"),
                        trafficDoc("Repeater", "transient-2")));

        List<OpenSearchClientWrapper.FailedItem> failed = List.of(
                new OpenSearchClientWrapper.FailedItem(0, "mapper_parsing_exception", "immense term"),
                new OpenSearchClientWrapper.FailedItem(1, "es_rejected_execution_exception", "queue full"),
                new OpenSearchClientWrapper.FailedItem(2, "illegal_argument_exception", "nested limit exceeded"),
                new OpenSearchClientWrapper.FailedItem(3, "unavailable_shards_exception", "red"));

        List<PreparedExportDocument> retryList = filterOnEdt(batch, failed, 0, "test-index", "traffic");

        assertThat(retryList).containsExactly(batch.get(1), batch.get(3));
        assertThat(ExportStats.getPermanentDrops("traffic")).isEqualTo(2);
        assertThat(ExportStats.getTotalPermanentDrops()).isEqualTo(2);
        assertThat(ExportStats.getPermanentDropReasonCount(
                ExportStats.PERMANENT_DROP_REASON_MAPPING)).isEqualTo(2);
        assertThat(ExportStats.getTrafficSourcePermanentDrops("proxy_history_snapshot")).isEqualTo(2);
        assertThat(ExportStats.getTrafficToolTypePermanentDrops("REPEATER")).isZero();
        assertThat(TrafficRouteBucket.resolveOpenSearchSourcePermanentDrops("PROXY_HISTORY")).isEqualTo(2);
        assertThat(events)
                .anySatisfy(e -> assertThat(e)
                        .contains("[OpenSearch] Dropped 2 permanently rejected document(s) from retry for index test-index"));
    }

    @Test
    void allPermanentFailures_returnsEmptyRetryList() throws Exception {
        List<PreparedExportDocument> batch = preparedBatch(
                "sitemap-index", "sitemap", List.of(docFor("a"), docFor("b")));
        List<OpenSearchClientWrapper.FailedItem> failed = List.of(
                new OpenSearchClientWrapper.FailedItem(0, "mapper_parsing_exception", "bad"),
                new OpenSearchClientWrapper.FailedItem(1, "strict_dynamic_mapping_exception", "bad"));

        List<PreparedExportDocument> retryList = filterOnEdt(batch, failed, 0, "sitemap-index", "sitemap");

        assertThat(retryList).isEmpty();
        assertThat(ExportStats.getPermanentDrops("sitemap")).isEqualTo(2);
    }

    @Test
    void maximumFitFailure_logsOneRichErrorAndDoesNotRetry() throws Exception {
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("meta", Map.of(
                "schema_version", "1",
                "opaque", "x".repeat((int) BulkByteBudget.ADAPTIVE_MAX_BYTES + 1024)));
        document.put("request", Map.of(
                "url", Map.of("raw", "https://large.example/download?token=visible")));
        PreparedExportDocument prepared =
                ExportDocumentIdentity.prepare("traffic-index", "traffic", document);
        List<OpenSearchClientWrapper.FailedItem> failed = List.of(
                new OpenSearchClientWrapper.FailedItem(
                        0,
                        BulkErrorClassification.SEARCH_MAX_BUDGET_EXCEEDED_TYPE,
                        "cannot fit"));

        List<PreparedExportDocument> retryList =
                filterOnEdt(List.of(prepared), failed, 0, "traffic-index", "traffic");

        assertThat(retryList).isEmpty();
        assertThat(ExportStats.getPermanentDrops("traffic")).isEqualTo(1);
        assertThat(ExportStats.getPermanentDropReasonCount(
                ExportStats.PERMANENT_DROP_REASON_MAX_FIT)).isEqualTo(1);
        List<String> maximumFitEvents = events.stream()
                        .filter(event -> event.contains("cannot fit the absolute bulk ceiling"))
                        .toList();
        assertThat(maximumFitEvents).hasSize(1);
        assertThat(maximumFitEvents.get(0))
                .contains("requestUrl=https://large.example/download?token=visible")
                .contains("operationId=" + prepared.operationId())
                .contains("absoluteMaxBytes=" + BulkByteBudget.ADAPTIVE_MAX_BYTES);
        assertThat(events).noneMatch(event ->
                event.contains("Dropped 1 permanently rejected document(s)"));
    }

    @Test
    void missingFailureDetails_treatsEntireBatchAsTransient() throws Exception {
        List<PreparedExportDocument> batch = preparedBatch(
                "findings-index", "findings", List.of(docFor("a"), docFor("b")));

        List<PreparedExportDocument> retryList =
                filterOnEdt(batch, List.of(), 0, "findings-index", "findings");

        assertThat(retryList).containsExactlyElementsOf(batch);
        assertThat(ExportStats.getPermanentDrops("findings")).isZero();
    }

    @Test
    void partialSuccessWithoutFailureIdentities_requeuesWholeStableIdBatch() throws Exception {
        List<PreparedExportDocument> batch = preparedBatch(
                "findings-index", "findings", List.of(docFor("a"), docFor("b")));

        List<PreparedExportDocument> retryList =
                filterOnEdt(batch, List.of(), 1, "findings-index", "findings");

        assertThat(retryList).containsExactlyElementsOf(batch);
        assertThat(ExportStats.getPermanentDrops("findings")).isZero();
    }

    @Test
    void nonExactFailureIdentitySet_requeuesWholeBatchWithoutPermanentDrop() throws Exception {
        List<PreparedExportDocument> batch = preparedBatch("traffic-index", "traffic", List.of(docFor("a")));
        List<OpenSearchClientWrapper.FailedItem> failed = List.of(
                new OpenSearchClientWrapper.FailedItem(0, "mapper_parsing_exception", "bad"),
                new OpenSearchClientWrapper.FailedItem(5, "mapper_parsing_exception", "phantom"),
                new OpenSearchClientWrapper.FailedItem(-1, "mapper_parsing_exception", "phantom"));

        List<PreparedExportDocument> retryList =
                filterOnEdt(batch, failed, 0, "traffic-index", "traffic");

        assertThat(retryList).containsExactlyElementsOf(batch);
        assertThat(ExportStats.getPermanentDrops("traffic")).isZero();
    }

    /**
     * Runs {@link IndexingRetryCoordinator#filterTransientFailures} on the EDT so that any
     * listener dispatch from {@code logErrorPanelOnly} happens synchronously before assertions.
     */
    private static List<PreparedExportDocument> filterOnEdt(
            List<PreparedExportDocument> batch,
            List<OpenSearchClientWrapper.FailedItem> failed,
            int knownSuccessCount,
            String indexName,
            String indexKey) throws Exception {
        AtomicReference<List<PreparedExportDocument>> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() ->
                ref.set(IndexingRetryCoordinator.filterTransientFailures(
                        batch, failed, knownSuccessCount, indexName, indexKey)));
        return ref.get();
    }

    private static Map<String, Object> docFor(String marker) {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("marker", marker);
        return doc;
    }

    private static Map<String, Object> trafficDoc(String reportingTool, String marker) {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("marker", marker);
        doc.put("burp", Map.of("reporting_tool", reportingTool));
        return doc;
    }

    private static List<PreparedExportDocument> preparedBatch(
            String indexName,
            String indexKey,
            List<Map<String, Object>> documents) {
        return documents.stream()
                .map(document -> ExportDocumentIdentity.prepare(indexName, indexKey, document))
                .toList();
    }
}
