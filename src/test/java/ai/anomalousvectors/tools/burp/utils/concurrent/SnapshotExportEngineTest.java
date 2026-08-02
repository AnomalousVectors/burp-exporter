package ai.anomalousvectors.tools.burp.utils.concurrent;

import static ai.anomalousvectors.tools.burp.testutils.SnapshotExportEngineTestSupport.fileOnlyTrafficState;
import static ai.anomalousvectors.tools.burp.testutils.SnapshotExportEngineTestSupport.preparedTrafficDoc;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.Collections;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.sinks.ExportReporterLifecycle;
import ai.anomalousvectors.tools.burp.testutils.TestPathSupport;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

/** Unit tests for {@link SnapshotExportEngine} worker sizing, empty-input behavior, and scale paths. */
class SnapshotExportEngineTest {

    @Test
    void defaultBuildWorkers_isWithinExpectedRange() {
        int workers = SnapshotExportEngine.defaultBuildWorkers();
        assertThat(workers).isBetween(1, 4);
    }

    @Test
    void queueCapacity_scalesWithWorkersAndChunkTargetWithinBounds() {
        assertThat(SnapshotExportEngine.queueCapacity(1, 1)).isEqualTo(64);
        assertThat(SnapshotExportEngine.queueCapacity(4, 100)).isBetween(64, 512);
        assertThat(SnapshotExportEngine.queueCapacity(4, 250)).isBetween(64, 512);
        assertThat(SnapshotExportEngine.queueCapacity(4, 10_000)).isEqualTo(512);
    }

    @Test
    void buildAheadReservationPermits_boundsQueuedPreparedBytes() {
        assertThat(SnapshotExportEngine.buildAheadReservationPermits(0L)).isEqualTo(1);
        assertThat(SnapshotExportEngine.buildAheadReservationPermits(64L * 1024L)).isEqualTo(1);
        assertThat(SnapshotExportEngine.buildAheadReservationPermits((64L * 1024L) + 1L)).isEqualTo(2);
        assertThat(SnapshotExportEngine.buildAheadReservationPermits(
                        SnapshotExportEngine.MAX_BUILD_AHEAD_BYTES))
                .isEqualTo(1_024);
        assertThat(SnapshotExportEngine.buildAheadReservationPermits(Long.MAX_VALUE)).isEqualTo(1_024);
        assertThat(SnapshotExportEngine.buildAheadReservationBytes(1)).isEqualTo(64L * 1024L);
        assertThat(SnapshotExportEngine.buildAheadReservationBytes(1_024))
                .isEqualTo(SnapshotExportEngine.MAX_BUILD_AHEAD_BYTES);
    }

    @Test
    void run_emptyItems_returnsZeroCounters() {
        SnapshotExportEngine.Result result = SnapshotExportEngine.run(
                List.of(),
                2,
                5_000_000L,
                250,
                null,
                null,
                "https://opensearch.url:9200",
                "burp-exporter-test",
                "traffic",
                item -> null,
                null);

        assertThat(result.attempted()).isZero();
        assertThat(result.success()).isZero();
        assertThat(result.chunks()).isZero();
        assertThat(result.buildWallMs()).isZero();
        assertThat(result.buildCpuMs()).isZero();
        assertThat(result.flushMs()).isZero();
        assertThat(result.buildWorkers()).isEqualTo(2);
    }

    @Test
    void run_nullItems_returnsZeroCounters() {
        SnapshotExportEngine.Result result = SnapshotExportEngine.run(
                null,
                1,
                5_000_000L,
                250,
                null,
                null,
                "https://opensearch.url:9200",
                "burp-exporter-test",
                "traffic",
                unused -> new PreparedExportDocument(
                        "interrupted-gate-test", "idx", "traffic", java.util.Map.of(), 1L, new byte[0]),
                null);

        assertThat(result.attempted()).isZero();
        assertThat(result.buildWorkers()).isEqualTo(1);
    }

    @Test
    void run_largeItemCount_fileOnly_splitsChunksByByteCap() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("snapshot-engine-byte-cap");
            RuntimeConfig.updateState(fileOnlyTrafficState(root));
            RuntimeConfig.setExportRunning(true);

            String indexName = IndexNaming.indexNameForShortName("traffic");
            int itemCount = 2_000;
            long bytesPerDoc = 50_000L;
            List<Integer> items = IntStream.range(0, itemCount).boxed().toList();
            AtomicLong maxObservedChunkBytes = new AtomicLong();

            SnapshotExportEngine.Result result = SnapshotExportEngine.run(
                    items,
                    2,
                    5L * 1024 * 1024,
                    500,
                    null,
                    null,
                    "",
                    indexName,
                    "traffic",
                    item -> preparedTrafficDoc(indexName, item, bytesPerDoc),
                    (chunk, outcome, nextTarget) -> maxObservedChunkBytes.updateAndGet(
                            prev -> Math.max(prev, chunk.stream().mapToLong(
                                    document -> document.resolvedBulkBytes()).sum())));

            int countOnlyChunks = (itemCount + 499) / 500;
            assertThat(result.attempted()).isEqualTo(itemCount);
            assertThat(result.chunks()).isGreaterThan(countOnlyChunks);
            assertThat(maxObservedChunkBytes.get()).isLessThanOrEqualTo(5L * 1024 * 1024);
        } finally {
            ExportReporterLifecycle.resetForTests();
        }
    }

    @Test
    void run_moderateItemCount_fileOnly_completesWithExpectedThroughput() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("snapshot-engine-scale");
            RuntimeConfig.updateState(fileOnlyTrafficState(root));
            RuntimeConfig.setExportRunning(true);

            String indexName = IndexNaming.indexNameForShortName("traffic");
            int itemCount = 4_000;
            List<Integer> items = IntStream.range(0, itemCount).boxed().toList();

            SnapshotExportEngine.Result result = SnapshotExportEngine.run(
                    items,
                    SnapshotExportEngine.defaultBuildWorkers(),
                    5_000_000L,
                    250,
                    null,
                    null,
                    "",
                    indexName,
                    "traffic",
                    item -> preparedTrafficDoc(indexName, item, 2_048L),
                    null);

            assertThat(result.attempted()).isEqualTo(itemCount);
            assertThat(result.success()).isEqualTo(itemCount);
            assertThat(result.chunks()).isPositive();
            assertThat(result.buildWallMs()).isPositive();
            assertThat(ExportStats.getPeakSnapshotBuildAheadReservedBytes()).isPositive();
            assertThat(ExportStats.getSnapshotBuildAheadReservedBytes()).isZero();
        } finally {
            ExportReporterLifecycle.resetForTests();
        }
    }

    @Test
    void run_preparerRuntimeException_countsFailureAndContinuesWorkerStride() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("snapshot-engine-preparation-failure");
            RuntimeConfig.updateState(fileOnlyTrafficState(root));
            RuntimeConfig.setExportRunning(true);

            String indexName = IndexNaming.indexNameForShortName("traffic");
            SnapshotExportEngine.Result result = SnapshotExportEngine.run(
                    List.of(0, 1, 2, 3, 4),
                    1,
                    5_000_000L,
                    250,
                    null,
                    null,
                    "",
                    indexName,
                    "traffic",
                    item -> {
                        if (item == 1) {
                            throw new IllegalStateException("bad snapshot item");
                        }
                        return preparedTrafficDoc(indexName, item, 2_048L);
                    },
                    null);

            assertThat(result.preparationFailures()).isEqualTo(1);
            assertThat(result.attempted()).isEqualTo(4);
            assertThat(result.success()).isEqualTo(4);
        } finally {
            ExportReporterLifecycle.resetForTests();
        }
    }

    @Test
    void run_webSocketScaleHandoff_preservesCompletedChunksWithoutDefensiveCopy() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("snapshot-engine-ws-scale");
            RuntimeConfig.updateState(fileOnlyTrafficState(root));
            RuntimeConfig.setExportRunning(true);

            String indexName = IndexNaming.indexNameForShortName("traffic");
            int itemCount = 10_000;
            List<Integer> items = IntStream.range(0, itemCount).boxed().toList();
            List<List<PreparedExportDocument>> observedChunks =
                    Collections.synchronizedList(new ArrayList<>());

            SnapshotExportEngine.Result result = SnapshotExportEngine.run(
                    items,
                    SnapshotExportEngine.defaultBuildWorkers(),
                    5_000_000L,
                    250,
                    null,
                    null,
                    "",
                    indexName,
                    "traffic",
                    item -> preparedTrafficDoc(indexName, item, 512L),
                    (chunk, outcome, nextTarget) -> observedChunks.add(chunk));

            int observedDocs = observedChunks.stream().mapToInt(chunk -> chunk.size()).sum();
            assertThat(result.attempted()).isEqualTo(itemCount);
            assertThat(result.success()).isEqualTo(itemCount);
            assertThat(result.chunks()).isEqualTo(observedChunks.size());
            assertThat(observedDocs).isEqualTo(itemCount);
            assertThat(observedChunks).allSatisfy(chunk -> assertThat(chunk).isNotEmpty());
        } finally {
            ExportReporterLifecycle.resetForTests();
        }
    }
}
