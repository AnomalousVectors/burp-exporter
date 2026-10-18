package ai.anomalousvectors.tools.burp.sinks;

import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.assertj.core.api.Assertions.assertThat;

import ai.anomalousvectors.tools.burp.sinks.OpenSearchSink.IndexResult;
import ai.anomalousvectors.tools.burp.testutils.OpenSearchReachable;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;

/**
 * Concurrency smoke test: creating multiple indices in parallel should not deadlock or throw.
 * Root-owned cleanup runs after all selected Jupiter tests finish.
 */
@Tag("integration")
@ExtendWith(OpenSearchCleanupExtension.class)
class OpenSearchSinkConcurrencyIT {

    // Standard short names
    private static final List<String> SOURCES = List.of("sitemap", "findings", "traffic", "settings", "exporter");

    // Expected full names for each short name
    private static Map<String, String> expectedNames() {
        return Map.of(
                "exporter", IndexNaming.indexNameForShortName("exporter"),
                "sitemap", IndexNaming.indexNameForShortName("sitemap"),
                "findings", IndexNaming.indexNameForShortName("findings"),
                "settings", IndexNaming.indexNameForShortName("settings"),
                "traffic", IndexNaming.indexNameForShortName("traffic")
        );
    }

    @Test
    void createIndexes_concurrently_completes_withoutDeadlock() throws Exception {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        try (ExecutorService pool = Executors.newFixedThreadPool(SOURCES.size())) {
            List<Callable<IndexResult>> tasks = SOURCES.stream()
                    .map(shortName -> (Callable<IndexResult>) () ->
                            OpenSearchReachable.createIndexFromResource(shortName))
                    .toList();

            List<Future<IndexResult>> results = pool.invokeAll(tasks);

            for (Future<IndexResult> f : results) {
                IndexResult res;
                try {
                    res = f.get();
                } catch (ExecutionException e) {
                    throw new AssertionError("Task threw exception", e.getCause());
                }
                String expectedFull = expectedNames().get(res.shortName());
                assertThat(res.fullName()).isEqualTo(expectedFull);
                assertThat(res.status()).isIn(IndexResult.Status.CREATED, IndexResult.Status.EXISTS);
            }
        }
    }
}
