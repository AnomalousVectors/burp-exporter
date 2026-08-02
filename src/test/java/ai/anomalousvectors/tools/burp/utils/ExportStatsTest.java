package ai.anomalousvectors.tools.burp.utils;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

import ai.anomalousvectors.tools.burp.utils.export.BulkOutcomeBreakdown;

class ExportStatsTest {

    @Test
    void recordLastActiveSearchCapacity_keepsFirstStopSnapshotAndResetsForNextRun() {
        ExportStats.resetForTests();

        ExportStats.recordLastActiveSearchCapacity(5L * 1024L * 1024L, 3);
        ExportStats.recordLastActiveSearchCapacity(1024L * 1024L, 1);

        assertThat(ExportStats.getLastActiveBulkByteBudget()).isEqualTo(5L * 1024L * 1024L);
        assertThat(ExportStats.getLastActiveSnapshotFlushCap()).isEqualTo(3);

        ExportStats.recordExportStartRequested();
        assertThat(ExportStats.getLastActiveBulkByteBudget()).isZero();
        assertThat(ExportStats.getLastActiveSnapshotFlushCap()).isZero();
    }

    @Test
    void bulkInFlight_startAndEndBracketActivity() {
        ExportStats.resetForTests();
        assertThat(ExportStats.getBulkInFlight()).isZero();
        ExportStats.recordBulkStart();
        ExportStats.recordBulkStart();
        assertThat(ExportStats.getBulkInFlight()).isEqualTo(2);
        ExportStats.recordBulkEnd();
        assertThat(ExportStats.getBulkInFlight()).isEqualTo(1);
        ExportStats.recordBulkEnd();
        assertThat(ExportStats.getBulkInFlight()).isZero();
    }

    @Test
    void recordBulkEnd_neverDropsBelowZero() {
        ExportStats.resetForTests();
        ExportStats.recordBulkEnd();
        ExportStats.recordBulkEnd();
        assertThat(ExportStats.getBulkInFlight()).isZero();
    }

    @Test
    void resetForTests_clearsBulkInFlight() {
        ExportStats.recordBulkStart();
        ExportStats.recordBulkStart();
        ExportStats.resetForTests();
        assertThat(ExportStats.getBulkInFlight()).isZero();
    }

    @Test
    void getIndexKeys_returnsAllFiveIndexKeys() {
        List<String> keys = ExportStats.getIndexKeys();
        assertThat(keys).containsExactly("traffic", "exporter", "settings", "sitemap", "findings");
    }

    @Test
    void getIndexKeys_containsExporterAndNotLegacyToolKey() {
        List<String> keys = ExportStats.getIndexKeys();
        assertThat(keys).contains("exporter").doesNotContain("tool");
    }

    @Test
    void getTrafficToolTypeKeys_excludesRemovedCollaboratorBucket() {
        assertThat(ExportStats.getTrafficToolTypeKeys())
                .contains("BURP_AI", "EXTENSIONS", "PROXY", "REPEATER", "UNKNOWN")
                .doesNotContain("COLLABORATOR");
    }

    @Test
    void recordSuccess_incrementsCountAndTotal() {
        long before = ExportStats.getSuccessCount("traffic");
        ExportStats.recordSuccess("traffic", 3);
        assertThat(ExportStats.getSuccessCount("traffic")).isEqualTo(before + 3);

        long totalBefore = ExportStats.getTotalSuccessCount();
        ExportStats.recordSuccess("findings", 2);
        assertThat(ExportStats.getTotalSuccessCount()).isEqualTo(totalBefore + 2);
    }

    @Test
    void recordFailure_incrementsCountAndTotal() {
        long before = ExportStats.getFailureCount("sitemap");
        ExportStats.recordFailure("sitemap", 1);
        assertThat(ExportStats.getFailureCount("sitemap")).isEqualTo(before + 1);

        long totalBefore = ExportStats.getTotalFailureCount();
        ExportStats.recordFailure("exporter", 1);
        assertThat(ExportStats.getTotalFailureCount()).isEqualTo(totalBefore + 1);
    }

    @Test
    void recordRetryRecovery_reducesOutstandingWithoutClearingAttempts() {
        ExportStats.resetForTests();
        ExportStats.recordFailure("sitemap", 50);
        assertThat(ExportStats.getOutstandingFailureCount("sitemap")).isEqualTo(50);

        ExportStats.recordRetryRecovery("sitemap", 50);
        assertThat(ExportStats.getFailureCount("sitemap")).isEqualTo(50);
        assertThat(ExportStats.getRecoveredFailureCount("sitemap")).isEqualTo(50);
        assertThat(ExportStats.getOutstandingFailureCount("sitemap")).isEqualTo(0);
        assertThat(ExportStats.getTotalOutstandingFailureCount()).isEqualTo(0);
    }

    @Test
    void permanentAndRetryDrops_reduceOutstandingWithoutClearingAttempts() {
        ExportStats.resetForTests();
        ExportStats.recordFailure("sitemap", 50);
        ExportStats.recordPermanentDrop("sitemap", 10);
        ExportStats.recordRetryQueueDrop("sitemap", 5);
        assertThat(ExportStats.getFailureCount("sitemap")).isEqualTo(50);
        assertThat(ExportStats.getOutstandingFailureCount("sitemap")).isEqualTo(35);
    }

    @Test
    void permanentDropReasons_areStableAndResetPerRun() {
        ExportStats.resetForTests();
        ExportStats.recordPermanentDropReason(ExportStats.PERMANENT_DROP_REASON_MAX_FIT, 2);
        ExportStats.recordPermanentDropReason(ExportStats.PERMANENT_DROP_REASON_STOP, 1);

        assertThat(ExportStats.getPermanentDropReasonCounts())
                .containsEntry(ExportStats.PERMANENT_DROP_REASON_MAX_FIT, 2L)
                .containsEntry(ExportStats.PERMANENT_DROP_REASON_STOP, 1L);

        ExportStats.resetForRun();
        assertThat(ExportStats.getPermanentDropReasonCounts()).isEmpty();
    }

    @Test
    void recordRetryAttempt_incrementsPerIndexAndTotal() {
        ExportStats.resetForTests();
        ExportStats.recordRetryAttempt("traffic", 10);
        ExportStats.recordRetryAttempt("traffic", 5);
        ExportStats.recordRetryAttempt("sitemap", 2);
        assertThat(ExportStats.getRetryAttempts("traffic")).isEqualTo(15);
        assertThat(ExportStats.getRetryAttempts("sitemap")).isEqualTo(2);
        assertThat(ExportStats.getTotalRetryAttempts()).isEqualTo(17);
        ExportStats.recordRetryAttempt("traffic", 0);
        assertThat(ExportStats.getRetryAttempts("traffic")).isEqualTo(15);
    }

    @Test
    void clearLastError_removesStoredMessage() {
        ExportStats.resetForTests();
        ExportStats.recordLastError("sitemap", "Bulk push had 50 failure(s)");
        assertThat(ExportStats.getLastError("sitemap")).contains("50");
        ExportStats.clearLastError("sitemap");
        assertThat(ExportStats.getLastError("sitemap")).isNull();
    }

    @Test
    void recordPermanentDrop_incrementsPerIndexAndTotal() {
        long beforeTraffic = ExportStats.getPermanentDrops("traffic");
        long beforeTotal = ExportStats.getTotalPermanentDrops();
        ExportStats.recordPermanentDrop("traffic", 3);
        assertThat(ExportStats.getPermanentDrops("traffic")).isEqualTo(beforeTraffic + 3);
        assertThat(ExportStats.getTotalPermanentDrops()).isEqualTo(beforeTotal + 3);
    }

    @Test
    void recordPermanentDrop_withZeroOrNegative_doesNotChangeCount() {
        long before = ExportStats.getPermanentDrops("sitemap");
        ExportStats.recordPermanentDrop("sitemap", 0);
        ExportStats.recordPermanentDrop("sitemap", -5);
        assertThat(ExportStats.getPermanentDrops("sitemap")).isEqualTo(before);
    }

    @Test
    void recordExportedBytes_incrementsPerIndexAndTotal() {
        long beforeTraffic = ExportStats.getExportedBytes("traffic");
        long beforeTotal = ExportStats.getTotalExportedBytes();
        ExportStats.recordExportedBytes("traffic", 2048);
        assertThat(ExportStats.getExportedBytes("traffic")).isEqualTo(beforeTraffic + 2048);
        assertThat(ExportStats.getTotalExportedBytes()).isEqualTo(beforeTotal + 2048);
    }

    @Test
    void recordSuccess_withZeroOrNegative_doesNotChangeCount() {
        long before = ExportStats.getSuccessCount("settings");
        ExportStats.recordSuccess("settings", 0);
        ExportStats.recordSuccess("settings", -1);
        assertThat(ExportStats.getSuccessCount("settings")).isEqualTo(before);
    }

    @Test
    void recordLastLiveBulkDurationMs_setsDuration() {
        ExportStats.recordLastLiveBulkDurationMs("traffic", 150);
        assertThat(ExportStats.getLastLiveBulkDurationMs("traffic")).isEqualTo(150);
    }

    @Test
    void recordLastError_setsAndTruncatesError() {
        ExportStats.recordLastError("traffic", "short");
        assertThat(ExportStats.getLastError("traffic")).isEqualTo("short");

        String longMsg = "a".repeat(300);
        ExportStats.recordLastError("traffic", longMsg);
        String got = ExportStats.getLastError("traffic");
        assertThat(got).endsWith("...");
        assertThat(got.length()).isLessThanOrEqualTo(203);

        ExportStats.recordLastError("traffic", null);
        assertThat(ExportStats.getLastError("traffic")).isNull();
        ExportStats.recordLastError("traffic", "");
        assertThat(ExportStats.getLastError("traffic")).isNull();
    }

    @Test
    void getters_forUnknownIndex_returnsZeroOrNull() {
        String unknown = "unknown-index-key";
        assertThat(ExportStats.getSuccessCount(unknown)).isEqualTo(0);
        assertThat(ExportStats.getFailureCount(unknown)).isEqualTo(0);
        assertThat(ExportStats.getLastLiveBulkDurationMs(unknown)).isEqualTo(-1);
        assertThat(ExportStats.getLastError(unknown)).isNull();
    }

    @Test
    void getQueueSize_returnsNonNegativeForEachIndexKey() {
        for (String indexKey : ExportStats.getIndexKeys()) {
            int size = ExportStats.getQueueSize(indexKey);
            assertThat(size).isGreaterThanOrEqualTo(0);
        }
    }

    @Test
    void recordTrafficQueueDrop_incrementsAndGetTrafficQueueDrops_returnsValue() {
        long before = ExportStats.getTrafficQueueDrops();
        ExportStats.recordTrafficQueueDrop(1);
        assertThat(ExportStats.getTrafficQueueDrops()).isEqualTo(before + 1);
        ExportStats.recordTrafficQueueDrop(3);
        assertThat(ExportStats.getTrafficQueueDrops()).isEqualTo(before + 4);
    }

    @Test
    void recordTrafficQueueDrop_zeroOrNegative_doesNotChangeCount() {
        long before = ExportStats.getTrafficQueueDrops();
        ExportStats.recordTrafficQueueDrop(0);
        ExportStats.recordTrafficQueueDrop(-1);
        assertThat(ExportStats.getTrafficQueueDrops()).isEqualTo(before);
    }

    @Test
    void recordTrafficToolSourceFallback_incrementsCounter() {
        long before = ExportStats.getTrafficToolSourceFallbacks();
        ExportStats.recordTrafficToolSourceFallback();
        ExportStats.recordTrafficToolSourceFallback();
        assertThat(ExportStats.getTrafficToolSourceFallbacks()).isEqualTo(before + 2);
    }

    @Test
    void trafficSpillCounters_recordAndReadTotals() {
        long enqueuedBefore = ExportStats.getTrafficSpillEnqueued();
        long dequeuedBefore = ExportStats.getTrafficSpillDequeued();
        long droppedBefore = ExportStats.getTrafficSpillDrops();
        long recoveredBefore = ExportStats.getTrafficSpillRecovered();
        long prunedBefore = ExportStats.getTrafficSpillExpiredPruned();
        long reasonBefore = ExportStats.getTrafficDropReasonCount("spill_rejected_drop_oldest");

        ExportStats.recordTrafficSpillEnqueued(3);
        ExportStats.recordTrafficSpillDequeued(2);
        ExportStats.recordTrafficSpillDrop(1);
        ExportStats.recordTrafficSpillRecovered(4);
        ExportStats.recordTrafficSpillExpiredPruned(5);
        ExportStats.recordTrafficDropReason("spill_rejected_drop_oldest", 6);

        assertThat(ExportStats.getTrafficSpillEnqueued()).isEqualTo(enqueuedBefore + 3);
        assertThat(ExportStats.getTrafficSpillDequeued()).isEqualTo(dequeuedBefore + 2);
        assertThat(ExportStats.getTrafficSpillDrops()).isEqualTo(droppedBefore + 1);
        assertThat(ExportStats.getTrafficSpillRecovered()).isEqualTo(recoveredBefore + 4);
        assertThat(ExportStats.getTrafficSpillExpiredPruned()).isEqualTo(prunedBefore + 5);
        assertThat(ExportStats.getTrafficDropReasonCount("spill_rejected_drop_oldest")).isEqualTo(reasonBefore + 6);
    }

    @Test
    void recordRetryQueueDrop_incrementsPerIndexAndTotal() {
        long beforeTraffic = ExportStats.getRetryQueueDrops("traffic");
        long beforeExporter = ExportStats.getRetryQueueDrops("exporter");
        long beforeTotal = ExportStats.getTotalRetryQueueDrops();
        ExportStats.recordRetryQueueDrop("traffic", 2);
        assertThat(ExportStats.getRetryQueueDrops("traffic")).isEqualTo(beforeTraffic + 2);
        assertThat(ExportStats.getTotalRetryQueueDrops()).isEqualTo(beforeTotal + 2);
        ExportStats.recordRetryQueueDrop("exporter", 1);
        assertThat(ExportStats.getRetryQueueDrops("exporter")).isEqualTo(beforeExporter + 1);
        assertThat(ExportStats.getTotalRetryQueueDrops()).isEqualTo(beforeTotal + 3);
    }

    @Test
    void recordRetryQueueDrop_zeroOrNegative_doesNotChangeCount() {
        long before = ExportStats.getRetryQueueDrops("sitemap");
        ExportStats.recordRetryQueueDrop("sitemap", 0);
        ExportStats.recordRetryQueueDrop("sitemap", -1);
        assertThat(ExportStats.getRetryQueueDrops("sitemap")).isEqualTo(before);
    }

    @Test
    void recordOpenSearchSuccess_updatesLastSuccessAndResetsConsecutiveFailures() {
        ExportStats.resetForTests();
        assertThat(ExportStats.getOpenSearchLastSuccessAtMs()).isEqualTo(-1L);
        assertThat(ExportStats.getOpenSearchConsecutiveFailures()).isEqualTo(0L);

        ExportStats.recordOpenSearchFailure();
        ExportStats.recordOpenSearchFailure();
        assertThat(ExportStats.getOpenSearchConsecutiveFailures()).isEqualTo(2L);

        long beforeSuccess = System.currentTimeMillis();
        ExportStats.recordOpenSearchSuccess();
        assertThat(ExportStats.getOpenSearchConsecutiveFailures()).isEqualTo(0L);
        assertThat(ExportStats.getOpenSearchLastSuccessAtMs()).isGreaterThanOrEqualTo(beforeSuccess);
    }

    @Test
    void recordRetryDrainBulkSuccess_countsExportsWithoutReCountingFailures() {
        ExportStats.resetForTests();
        ExportStats.recordFailure("traffic", 5);
        assertThat(ExportStats.getFailureCount("traffic")).isEqualTo(5L);
        assertThat(ExportStats.getExportedCount("traffic")).isZero();

        // Simulates a partial drain recovery: 3 succeeded, 2 still failed in the bulk response.
        ExportStats.recordRetryDrainBulkSuccess("traffic", BulkOutcomeBreakdown.classified(3, 5));
        ExportStats.recordRetryRecovery("traffic", 3);

        assertThat(ExportStats.getExportedCount("traffic")).isEqualTo(3L);
        assertThat(ExportStats.getFailureCount("traffic")).isEqualTo(5L);
        assertThat(ExportStats.getRecoveredFailureCount("traffic")).isEqualTo(3L);
        assertThat(ExportStats.getOutstandingFailureCount("traffic")).isEqualTo(2L);

        // Contrast: recordBulkBreakdown would incorrectly inflate Failures by the still-failed 2.
        ExportStats.recordBulkBreakdown("traffic", BulkOutcomeBreakdown.classified(0, 2));
        assertThat(ExportStats.getFailureCount("traffic")).isEqualTo(7L);
    }

    @Test
    void softOutageAndCapacityEventCounters_incrementAndResetOnStart() {
        ExportStats.resetForTests();
        assertThat(ExportStats.getSoftOutageEntries()).isZero();
        assertThat(ExportStats.getCapacityPressureEvents()).isZero();

        ExportStats.recordSoftOutageEntry();
        ExportStats.recordSoftOutageEntry();
        ExportStats.recordCapacityPressureEvent();
        assertThat(ExportStats.getSoftOutageEntries()).isEqualTo(2L);
        assertThat(ExportStats.getCapacityPressureEvents()).isEqualTo(1L);

        ExportStats.recordExportStartRequested();
        assertThat(ExportStats.getSoftOutageEntries()).isZero();
        assertThat(ExportStats.getCapacityPressureEvents()).isZero();
    }

    @Test
    void searchBodyPrefixTruncations_incrementAndResetOnStart() {
        ExportStats.resetForTests();
        assertThat(ExportStats.getSearchBodyPrefixTruncations()).isZero();

        ExportStats.recordSearchBodyPrefixTruncation("traffic");
        ExportStats.recordSearchBodyPrefixTruncation("findings");
        assertThat(ExportStats.getSearchBodyPrefixTruncations()).isEqualTo(2L);
        assertThat(ExportStats.getSearchBodyPrefixTruncations("traffic")).isEqualTo(1L);
        assertThat(ExportStats.getSearchBodyPrefixTruncations("findings")).isEqualTo(1L);

        ExportStats.recordExportStartRequested();
        assertThat(ExportStats.getSearchBodyPrefixTruncations()).isZero();
        assertThat(ExportStats.getSearchBodyPrefixTruncations("traffic")).isZero();
    }

    @Test
    void recordSkipReason_incrementsPerReasonAndTotal_andIgnoresBlankOrZero() {
        ExportStats.resetForTests();
        ExportStats.recordSkipReason("scope", 3);
        ExportStats.recordSkipReason("tool_disabled", 1);
        ExportStats.recordSkipReason(null, 5);
        ExportStats.recordSkipReason("  ", 2);
        ExportStats.recordSkipReason("scope", 0);
        ExportStats.recordSkipReason("scope", -4);

        assertThat(ExportStats.getSkipReasonCount("scope")).isEqualTo(3);
        assertThat(ExportStats.getSkipReasonCount("tool_disabled")).isEqualTo(1);
        assertThat(ExportStats.getTotalSkipCount()).isEqualTo(4);

        Map<String, Long> counts = ExportStats.getSkipReasonCounts();
        assertThat(counts).containsEntry("scope", 3L).containsEntry("tool_disabled", 1L);
    }

    @Test
    void getOldestQueuedAgeMs_withEmptyQueue_returnsMinusOne() {
        ExportStats.resetForTests();
        for (String indexKey : ExportStats.getIndexKeys()) {
            assertThat(ExportStats.getOldestQueuedAgeMs(indexKey)).isEqualTo(-1L);
        }
    }

    @Test
    void getThroughputDocsPerSecLast60s_afterRecordSuccess_reflectsCount() {
        ExportStats.recordSuccess("traffic", 60);
        double t = ExportStats.getThroughputDocsPerSecLast60s();
        assertThat(t).isGreaterThanOrEqualTo(1.0);
    }

    @Test
    void getThroughputDocsPerSecLast60s_returnsNonNegative() {
        assertThat(ExportStats.getThroughputDocsPerSecLast60s()).isGreaterThanOrEqualTo(0.0);
    }

    @Test
    void recordSuccess_zeroOrNegative_doesNotAffectThroughput() {
        double before = ExportStats.getThroughputDocsPerSecLast60s();
        ExportStats.recordSuccess("traffic", 0);
        ExportStats.recordSuccess("traffic", -1);
        assertThat(ExportStats.getThroughputDocsPerSecLast60s()).isEqualTo(before);
    }

    @Test
    void recordExportStartRequested_thenTrafficSuccess_setsStartToFirstTrafficMetric() {
        ExportStats.recordExportStartRequested();
        assertThat(ExportStats.getStartToFirstTrafficMs()).isEqualTo(-1);
        ExportStats.recordSuccess("traffic", 1);
        assertThat(ExportStats.getStartToFirstTrafficMs()).isGreaterThanOrEqualTo(0);
    }

    @Test
    void recordSnapshotLastRun_storesPerReporterKey() {
        ExportStats.recordSnapshotLastRun(
                ExportStats.SNAPSHOT_SITEMAP, 50, 48, 1200, 200, 2, 1_000_000L, 400, 800, 100, 2);
        ExportStats.SnapshotLastRunStats sitemap = ExportStats.getSnapshotLastRun(ExportStats.SNAPSHOT_SITEMAP);
        assertThat(sitemap).isNotNull();
        assertThat(sitemap.attempted()).isEqualTo(50);
        assertThat(ExportStats.getSnapshotLastRun(ExportStats.SNAPSHOT_FINDINGS)).isNull();
    }

    @Test
    void recordProxyHistorySnapshot_storesLatestSnapshotStats() {
        ExportStats.recordProxyHistorySnapshot(200, 190, 4000, 300, 4, 8_000_000L, 900, 3200, 800, 3);
        ExportStats.SnapshotLastRunStats s = ExportStats.getLastProxyHistorySnapshot();
        assertThat(s).isNotNull();
        assertThat(s.attempted()).isEqualTo(200);
        assertThat(s.success()).isEqualTo(190);
        assertThat(s.durationMs()).isEqualTo(4000);
        assertThat(s.finalChunkTarget()).isEqualTo(300);
        assertThat(s.chunks()).isEqualTo(4);
        assertThat(s.buildWallMs()).isEqualTo(900);
        assertThat(s.buildCpuMs()).isEqualTo(3200);
        assertThat(s.flushMs()).isEqualTo(800);
        assertThat(s.buildWorkers()).isEqualTo(3);
        assertThat(s.avgChunkDocs()).isEqualTo(50.0);
        assertThat(s.avgChunkBytes()).isEqualTo(2_000_000L);
        assertThat(s.docsPerSecond()).isGreaterThan(0.0);
        assertThat(ExportStats.getCurrentProxyHistoryChunkTarget()).isEqualTo(-1);
    }

    @Test
    void runPeakCounters_resetOnExportStart_andTrackHighWaterMarks() {
        ExportStats.resetForTests();
        ExportStats.observeExportPressureSamples(12, 4_096L, 3, 2_048L, 5, 1_024L);
        assertThat(ExportStats.getPeakTrafficQueueDocs()).isEqualTo(12);
        assertThat(ExportStats.getPeakTrafficQueueBytes()).isEqualTo(4_096L);
        assertThat(ExportStats.getPeakSpillDocs()).isEqualTo(3);
        assertThat(ExportStats.getPeakRetryQueueDocs()).isEqualTo(5);

        ExportStats.observeExportPressureSamples(8, 2_048L, 7, 4_096L, 2, 512L);
        assertThat(ExportStats.getPeakTrafficQueueDocs()).isEqualTo(12);
        assertThat(ExportStats.getPeakSpillDocs()).isEqualTo(7);

        ExportStats.recordSnapshotLastRun(
                ExportStats.SNAPSHOT_PROXY_HISTORY, 100, 100, 1_000, 400, 2, 2_000_000L, 200, 400, 900, 2);
        ExportStats.recordSnapshotChunkFlushMs(300L);
        ExportStats.recordSnapshotChunkFlushMs(700L);
        ExportStats.recordSnapshotChunkFlushMs(500L);
        assertThat(ExportStats.getPeakSnapshotChunkTarget()).isEqualTo(400);
        assertThat(ExportStats.getPeakSnapshotFlushMs()).isEqualTo(700);

        ExportStats.reserveSnapshotBuildAhead(4, 256L * 1024L);
        ExportStats.reserveSnapshotBuildAhead(2, 128L * 1024L);
        ExportStats.releaseSnapshotBuildAhead(2, 128L * 1024L);
        assertThat(ExportStats.getSnapshotBuildAheadReservedPermits()).isEqualTo(4);
        assertThat(ExportStats.getSnapshotBuildAheadReservedBytes()).isEqualTo(256L * 1024L);
        assertThat(ExportStats.getPeakSnapshotBuildAheadReservedPermits()).isEqualTo(6);
        assertThat(ExportStats.getPeakSnapshotBuildAheadReservedBytes()).isEqualTo(384L * 1024L);

        ExportStats.recordExportStartRequested();
        assertThat(ExportStats.getPeakTrafficQueueDocs()).isZero();
        assertThat(ExportStats.getPeakSnapshotChunkTarget()).isZero();
        assertThat(ExportStats.getPeakSnapshotFlushMs()).isZero();
        assertThat(ExportStats.getSnapshotBuildAheadReservedPermits()).isZero();
        assertThat(ExportStats.getPeakSnapshotBuildAheadReservedPermits()).isZero();
    }

    @Test
    void trafficSourceStats_recordAndRead_bySourceKey() {
        long liveSuccessBefore = ExportStats.getTrafficSourceSuccessCount("proxy_live_http");
        long liveFailureBefore = ExportStats.getTrafficSourceFailureCount("proxy_live_http");
        ExportStats.recordTrafficSourceSuccess("proxy_live_http", 5);
        ExportStats.recordTrafficSourceFailure("proxy_live_http", 2);
        assertThat(ExportStats.getTrafficSourceSuccessCount("proxy_live_http"))
                .isEqualTo(liveSuccessBefore + 5);
        assertThat(ExportStats.getTrafficSourceFailureCount("proxy_live_http"))
                .isEqualTo(liveFailureBefore + 2);
    }
}
