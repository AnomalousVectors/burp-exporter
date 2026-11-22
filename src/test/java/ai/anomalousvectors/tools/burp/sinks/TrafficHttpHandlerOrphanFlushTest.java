package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.ArgumentMatchers.any;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import ai.anomalousvectors.tools.burp.testutils.TestPathSupport;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import burp.api.montoya.core.ToolType;

/**
 * Regression test for {@link TrafficHttpHandlerSupport} orphan flushing.
 *
 * <p>Verifies that requests whose pending timestamp has aged past the orphan timeout are drained
 * into {@link TrafficExportQueue} and then removed from the pending-orphan map. The test
 * registers pending orphans via package-private test hooks so it stays independent of Burp's
 * {@code ObjectFactoryLocator}, which is not wired in unit tests.</p>
 */
class TrafficHttpHandlerOrphanFlushTest {

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void preparationOrAdmissionFailureIsAccountedAndLaterTicksContinue(boolean admissionFailure) throws Exception {
        Path root = TestPathSupport.createDirectory("orphan-flush-fault");
        ConfigState.State previous = RuntimeConfig.getState();
        RuntimeConfig.updateState(fileOnlyTrafficState(root));
        RuntimeConfig.setExportRunning(true);
        ExportStats.resetForTests();
        List<String> errors = new java.util.concurrent.CopyOnWriteArrayList<>();
        Logger.LogListener listener = (level, message) -> {
            if (message.contains("Orphan export failed")) {
                errors.add(message);
            }
        };
        try (var queue = mockStatic(TrafficExportQueue.class)) {
            Logger.registerListener(listener);
            TrafficHttpHandlerSupport.clearPendingOrphansForTest();
            if (admissionFailure) {
                seedAgedPendingOrphan(10, ToolType.REPEATER);
                queue.when(() -> TrafficExportQueue.offerForRun(any(), any()))
                        .thenThrow(new IllegalStateException("admission fault"));
            } else {
                Map<String, Object> broken = org.mockito.Mockito.spy(
                        new LinkedHashMap<String, Object>(Map.of("url", "https://example.test/fault")));
                when(broken.entrySet()).thenThrow(new IllegalStateException("preparation fault"));
                TrafficHttpHandlerSupport.registerPendingOrphanForTest(10, broken, ToolType.REPEATER,
                        TrafficHttpHandlerSupport.RequestStageResolution.none());
            }
            TrafficHttpHandlerSupport.flushOrphanedRequestsForTest();
            assertPendingOrphanRemoved(10);
            assertThat(FileExportStats.getFailureCount("traffic")).isEqualTo(1);
            assertThat(FileExportStats.getTrafficToolTypeFailureCount("repeater")).isEqualTo(1);
            assertThat(ExportStats.getFailureCount("traffic")).isZero();
            javax.swing.SwingUtilities.invokeAndWait(() -> { });
            assertThat(errors).hasSize(1);

            queue.reset();
            queue.when(() -> TrafficExportQueue.offerForRun(any(), any())).thenReturn(true);
            seedAgedPendingOrphan(11, ToolType.REPEATER);
            TrafficHttpHandlerSupport.flushOrphanedRequestsForTest();
            TrafficHttpHandlerSupport.flushOrphanedRequestsForTest();
            queue.verify(() -> TrafficExportQueue.offerForRun(any(), any()), org.mockito.Mockito.times(1));
            assertPendingOrphanRemoved(11);
            assertThat(FileExportStats.getFailureCount("traffic")).isEqualTo(1);
        } finally {
            Logger.unregisterListener(listener);
            TrafficHttpHandlerSupport.stop();
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.updateState(previous);
            ExportStats.resetForTests();
        }
    }

    @Test
    void realFixedRateTaskSurvivesPreparationFailure() throws Exception {
        Path root = TestPathSupport.createDirectory("orphan-recurring-fault");
        ConfigState.State previous = RuntimeConfig.getState();
        RuntimeConfig.updateState(fileOnlyTrafficState(root));
        RuntimeConfig.setExportRunning(true);
        java.util.concurrent.ScheduledExecutorService scheduler =
                java.util.concurrent.Executors.newSingleThreadScheduledExecutor();
        java.util.concurrent.CountDownLatch failed = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch admitted = new java.util.concurrent.CountDownLatch(1);
        try {
            TrafficHttpHandlerSupport.clearPendingOrphansForTest();
            TrafficExportQueue.clearPendingWork();
            Map<String, Object> broken = org.mockito.Mockito.spy(
                    new LinkedHashMap<String, Object>(Map.of("url", "https://example.test/fault")));
            when(broken.entrySet()).thenAnswer(invocation -> {
                failed.countDown();
                throw new IllegalStateException("preparation fault");
            });
            TrafficHttpHandlerSupport.registerPendingOrphanForTest(20, broken, ToolType.REPEATER,
                    TrafficHttpHandlerSupport.RequestStageResolution.none());
            var recurring = scheduler.scheduleAtFixedRate(() -> {
                // Mockito static scopes belong to the calling thread, including the real worker.
                try (var queue = mockStatic(TrafficExportQueue.class)) {
                    queue.when(() -> TrafficExportQueue.offerForRun(any(), any())).thenAnswer(invocation -> {
                        admitted.countDown();
                        return true;
                    });
                    TrafficHttpHandlerSupport.flushOrphanedRequestsForTest();
                }
            }, 0, 10, java.util.concurrent.TimeUnit.MILLISECONDS);
            assertThat(failed.await(2, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
            seedAgedPendingOrphan(21, ToolType.REPEATER);
            assertThat(admitted.await(2, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
            assertPendingOrphanRemoved(21);
            assertThat(recurring.isDone()).isFalse();
        } finally {
            scheduler.shutdownNow();
            assertThat(scheduler.awaitTermination(2, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
            TrafficHttpHandlerSupport.stop();
            TrafficExportQueue.stopWorker();
            TrafficExportQueue.clearPendingWork();
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void flushOrphanedRequests_drainsAgedEntryToExportQueue() throws Exception {
        Path root = TestPathSupport.createDirectory("traffic-handler-orphan-flush");
        RuntimeConfig.updateState(fileOnlyTrafficState(root));
        RuntimeConfig.setExportRunning(true);
        try {
            TrafficExportQueue.clearPendingWork();
            TrafficHttpHandlerSupport.clearPendingOrphansForTest();

            int messageId = 4242;
            seedAgedPendingOrphan(messageId, ToolType.REPEATER);

            int sizeBefore = TrafficExportQueue.getCurrentSize();
            TrafficHttpHandlerSupport.flushOrphanedRequestsForTest();
            int sizeAfter = TrafficExportQueue.getCurrentSize();

            assertThat(sizeAfter - sizeBefore >= 1 || waitForFileExport(root)).isTrue();
            assertPendingOrphanRemoved(messageId);
        } finally {
            RuntimeConfig.setExportRunning(false);
            TrafficExportQueue.clearPendingWork();
            TrafficHttpHandlerSupport.clearPendingOrphansForTest();
        }
    }

    @Test
    void flushOrphanedRequests_dropsAgedEntryWhenToolTypeDeselected() throws Exception {
        Path root = TestPathSupport.createDirectory("traffic-handler-orphan-deselected");
        RuntimeConfig.updateState(fileOnlyTrafficState(root, List.of("proxy")));
        RuntimeConfig.setExportRunning(true);
        try {
            TrafficExportQueue.clearPendingWork();
            TrafficHttpHandlerSupport.clearPendingOrphansForTest();

            int messageId = 4343;
            seedAgedPendingOrphan(messageId, ToolType.REPEATER);

            int sizeBefore = TrafficExportQueue.getCurrentSize();
            TrafficHttpHandlerSupport.flushOrphanedRequestsForTest();
            int sizeAfter = TrafficExportQueue.getCurrentSize();

            assertThat(sizeAfter).isEqualTo(sizeBefore);
            assertPendingOrphanRemoved(messageId);
        } finally {
            RuntimeConfig.setExportRunning(false);
            TrafficExportQueue.clearPendingWork();
            TrafficHttpHandlerSupport.clearPendingOrphansForTest();
        }
    }

    private static void seedAgedPendingOrphan(int messageId, ToolType toolType) {
        Map<String, Object> skeleton = new LinkedHashMap<>();
        skeleton.put("url", "https://example.test/orphan");
        skeleton.put("host", "example.test");
        skeleton.put("port", 443);
        skeleton.put("burp", Map.of("reporting_tool", toolType.toolName(), "message_id", messageId));

        TrafficHttpHandlerSupport.registerPendingOrphanForTest(
                messageId,
                skeleton,
                toolType,
                TrafficHttpHandlerSupport.RequestStageResolution.none());
    }

    private static boolean waitForFileExport(Path root) throws Exception {
        long deadline = System.currentTimeMillis() + 2_000;
        while (System.currentTimeMillis() < deadline) {
            try (var files = Files.walk(root)) {
                if (files.filter(Files::isRegularFile).anyMatch(TrafficHttpHandlerOrphanFlushTest::hasContent)) {
                    return true;
                }
            }
            java.util.concurrent.TimeUnit.MILLISECONDS.sleep(50);
        }
        return false;
    }

    private static boolean hasContent(Path path) {
        try {
            return Files.size(path) > 0;
        } catch (java.io.IOException e) {
            return false;
        }
    }

    private static void assertPendingOrphanRemoved(int messageId) {
        assertThat(TrafficHttpHandlerSupport.containsPendingOrphanForTest(messageId))
                .as("flushOrphanedRequests must remove drained entries")
                .isFalse();
    }

    private static ConfigState.State fileOnlyTrafficState(Path root) {
        return fileOnlyTrafficState(root, List.of("repeater"));
    }

    private static ConfigState.State fileOnlyTrafficState(Path root, List<String> trafficToolTypes) {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(
                        true,
                        root.toString(),
                        true,
                        false,
                        true,
                        ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                        false,
                        ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                        false,
                        "",
                        "",
                        "",
                        ConfigState.OPEN_SEARCH_TLS_VERIFY),
                ConfigState.DEFAULT_SETTINGS_SUB,
                trafficToolTypes,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);
    }
}
