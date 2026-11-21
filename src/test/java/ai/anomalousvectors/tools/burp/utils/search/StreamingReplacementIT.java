package ai.anomalousvectors.tools.burp.utils.search;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.LinkedBlockingQueue;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import ai.anomalousvectors.tools.burp.sinks.ExportReporterLifecycle;
import ai.anomalousvectors.tools.burp.sinks.TrafficQueueEntry;
import ai.anomalousvectors.tools.burp.testutils.OpenSearchReachable;
import ai.anomalousvectors.tools.burp.testutils.OpenSearchTestIndex;
import ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport;
import ai.anomalousvectors.tools.burp.testutils.Reflect;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.BulkOutcomeBreakdown;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;
import ai.anomalousvectors.tools.burp.utils.export.SearchDocumentRevision;
import tools.jackson.databind.JsonNode;

/** Exercises real database ordering, retry acknowledgments and exact capture separation. */
@Tag("integration")
@ResourceLock("traffic-opensearch-index")
class StreamingReplacementIT {
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void latestRevisionWinsAcrossPreparedAndLiveSenders(boolean liveSender) throws Exception {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");
        ConfigState.State previous = RuntimeConfig.getState();
        ExportReporterLifecycle.resetForTests();
        try {
            RuntimeConfig.updateState(new ConfigState.State(List.of("traffic"), "all", List.of(),
                    PartialFieldOpenSearchTestSupport.openSearchSinks(),
                    ConfigState.DEFAULT_SETTINGS_SUB, List.of("proxy"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES, null));
            RuntimeConfig.setExportRunning(true);
            try (OpenSearchTestIndex scope = OpenSearchTestIndex.open("traffic")) {
                var client = OpenSearchReachable.getClient();
                client.indices().create(b -> b.index(scope.name()));
                var newer = snapshot(scope.name(), "stream-a", 2, "newer");
                assertThat(send(newer, liveSender).created()).isEqualTo(1);
                assertThat(send(snapshot(scope.name(), "stream-a", 1, "older"), liveSender).noop()).isEqualTo(1);
                // A lost response can cause the exact same prepared operation to be retried.
                assertThat(send(newer, liveSender).noop()).isEqualTo(1);
                assertThat(send(snapshot(scope.name(), "stream-a", 3, "latest"), liveSender).updated()).isEqualTo(1);
                assertThat(send(snapshot(scope.name(), "stream-b", 1, "latest"), liveSender).created()).isEqualTo(1);
                var stored = client.get(b -> b.index(scope.name()).id("stream-a"), JsonNode.class);
                assertThat(stored.version()).isEqualTo(3);
                assertThat(Objects.requireNonNull(stored.source()).path("response").path("body").path("text").asString())
                        .isEqualTo("latest");
                client.indices().refresh(b -> b.index(scope.name()));
                assertThat(client.count(b -> b.index(scope.name())).count()).isEqualTo(2);
                assertThat(IndexingRetryCoordinator.getInstance().snapshotQueuedDocuments(scope.name())).isEmpty();
            }
        } finally {
            ExportReporterLifecycle.resetForTests();
            RuntimeConfig.updateState(previous);
            SearchConnector.closeAll();
        }
    }

    private static PreparedExportDocument snapshot(String index, String id, long version, String body) {
        return ExportDocumentIdentity.prepareStreaming(index, "traffic",
                Map.of("response", Map.of("body", Map.of("text", body))), "proxy",
                new SearchDocumentRevision(id, version));
    }

    private static BulkOutcomeBreakdown send(PreparedExportDocument document, boolean liveSender) {
        String baseUrl = PartialFieldOpenSearchTestSupport.baseUrl();
        if (!liveSender) {
            var result = PreparedBulkSender.push(baseUrl, document.indexName(), List.of(document));
            assertThat(result.failedItems).isEmpty();
            return result.breakdown();
        }
        var queue = new LinkedBlockingQueue<TrafficQueueEntry>();
        queue.add(TrafficQueueEntry.class.cast(Reflect.callStatic(TrafficQueueEntry.class, "fromPrepared", document)));
        var result = ChunkedBulkSender.push(baseUrl, document.indexName(), "traffic", queue,
                10, 5L * 1024 * 1024, 10);
        assertThat(result.failedItems).isEmpty();
        if (result.breakdown.noop() > 0) {
            assertThat(result.successBytes).isZero();
            assertThat(result.trafficToolTypeSuccessCounts).isEmpty();
            assertThat(result.trafficSourceSuccessCounts).isEmpty();
        }
        return result.breakdown;
    }
}
