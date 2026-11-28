package ai.anomalousvectors.tools.burp.utils.concurrent;

import static ai.anomalousvectors.tools.burp.testutils.SnapshotExportEngineTestSupport.fileOnlyTrafficState;
import static ai.anomalousvectors.tools.burp.testutils.SnapshotExportEngineTestSupport.awaitSnapshotMemoryReleased;
import static ai.anomalousvectors.tools.burp.testutils.SnapshotExportEngineTestSupport.preparedTrafficDoc;
import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import ai.anomalousvectors.tools.burp.sinks.ExportReporterLifecycle;
import ai.anomalousvectors.tools.burp.utils.DiskSpaceGuard;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

/** Tests snapshot construction and delivery ownership with two small, bounded offline fixtures. */
@Timeout(20)
class SnapshotMemoryDeliveryTest {
    @TempDir
    Path directory;

    @AfterEach
    void reset() {
        ExportReporterLifecycle.resetForTests();
        DiskSpaceGuard.resetForTests();
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void reservationSurvivesStalledDeliveryAndCancellation(boolean cancel) throws Exception {
        RuntimeConfig.updateState(fileOnlyTrafficState(directory));
        RuntimeConfig.setExportRunning(true);
        var token = RuntimeConfig.currentExportRunToken();
        String index = IndexNaming.indexNameForShortName("traffic");
        CountDownLatch writing = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger builds = new AtomicInteger();
        DiskSpaceGuard.setUsableSpaceOverride(path -> {
            if (Thread.currentThread().getName().startsWith("burp-exporter-snapshot-flush-")) {
                writing.countDown();
                try {
                    if (!release.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("Fixture write timeout");
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("Fixture write interrupted", interrupted);
                }
            }
            return Long.MAX_VALUE;
        });
        try (var worker = Executors.newSingleThreadExecutor()) {
            var result = worker.submit(() -> SnapshotExportEngine.run(
                    List.of(1, 2), 2, 1_048_576L, 250, null, null, "", index, "traffic",
                    SnapshotExportEngine.ItemPreparer.estimated(item -> Long.MAX_VALUE, item -> {
                        builds.incrementAndGet();
                        return preparedTrafficDoc(index, item, 512L);
                    }), null));
            try {
                assertThat(writing.await(3, TimeUnit.SECONDS)).isTrue();
                assertThat(builds.get()).isEqualTo(1);
                assertThat(ExportStats.getSnapshotBuildAheadReservedPermits()).isEqualTo(1_024);
                if (cancel) {
                    RuntimeConfig.setExportRunning(false);
                    SnapshotExportEngine.cancelRun(token);
                    assertThat(ExportStats.getSnapshotBuildAheadReservedPermits()).isEqualTo(1_024);
                }
                release.countDown();
                var completed = result.get(5, TimeUnit.SECONDS);
                assertThat(awaitSnapshotMemoryReleased(5_000L)).isTrue();
                assertThat(ExportStats.getSnapshotBuildAheadReservedPermits()).isZero();
                if (cancel) {
                    assertThat(builds.get()).isEqualTo(1);
                } else {
                    assertThat(completed.attempted()).isEqualTo(2);
                    assertThat(completed.success()).isEqualTo(2);
                }
            } finally {
                release.countDown();
                RuntimeConfig.setExportRunning(false);
                SnapshotExportEngine.cancelRun(token);
                result.cancel(true);
                worker.shutdownNow();
                assertThat(worker.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
            }
        }
    }

    @Test
    void estimatorFailurePreservesExportAndPreparationFailureReleasesCapacity() throws Exception {
        RuntimeConfig.updateState(fileOnlyTrafficState(directory));
        RuntimeConfig.setExportRunning(true);
        String index = IndexNaming.indexNameForShortName("traffic");
        var result = SnapshotExportEngine.run(
                List.of(1, 2, 3), 2, 1_048_576L, 250, null, null, "", index, "traffic",
                SnapshotExportEngine.ItemPreparer.estimated(item -> {
                    throw new IllegalStateException("Unavailable size");
                }, item -> {
                    if (item == 2) throw new IllegalStateException("Malformed fixture");
                    return preparedTrafficDoc(index, item, 512L);
                }), null);
        assertThat(result.attempted()).isEqualTo(2);
        assertThat(result.preparationFailures()).isEqualTo(1);
        assertThat(ExportStats.getSnapshotBuildAheadReservedPermits()).isZero();
    }
}
