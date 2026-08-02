package ai.anomalousvectors.tools.burp.sinks;

import java.util.List;
import java.util.function.BooleanSupplier;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.concurrent.StartupSnapshotCoordinator;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchAuth;

/**
 * Revalidates search indexes and reseeds reproducible snapshots after authorization recovery.
 *
 * <p>The recovery path never deletes an index. Missing indexes are recreated from bundled
 * mappings, while incompatible existing indexes keep the destination paused. A replay is required
 * when the cluster identity changed or any selected index had to be created.</p>
 */
public final class SearchRecoveryBootstrap {

    static final long REPLAY_WATCHDOG_LOG_MS = 30_000L;

    private SearchRecoveryBootstrap() {
    }

    /**
     * Ensures selected indexes remain usable after a successful authorization probe.
     *
     * <p>Performs synchronous network I/O and may create missing indices or validate existing
     * settings and mappings. Caller must not invoke on the EDT. Operational failures are reported
     * in the returned outcome.</p>
     *
     * @param baseUrl active search destination URL
     * @param clusterIdentityChanged whether the root probe reports a different cluster UUID
     * @param token active export-run token
     * @return recovery outcome with replay requirement and operator detail
     */
    public static RecoveryPreparation ensureSelectedIndexes(
            String baseUrl,
            boolean clusterIdentityChanged,
            ExportRunToken token) {
        List<String> sources = RuntimeConfig.getState().dataSources();
        OpenSearchAuth auth = OpenSearchAuth.fromRuntime(RuntimeConfig.searchDestinationKind());
        List<OpenSearchSink.IndexResult> results = OpenSearchSink.createSelectedIndexes(
                baseUrl,
                sources,
                auth,
                () -> RuntimeConfig.isExportRunActive(token));
        OpenSearchSink.IndexResult failed = results.stream()
                .filter(result -> result.status() == OpenSearchSink.IndexResult.Status.FAILED)
                .findFirst()
                .orElse(null);
        if (failed != null) {
            String detail = failed.error() == null || failed.error().isBlank()
                    ? "selected index validation failed"
                    : failed.fullName() + ": " + failed.error();
            return new RecoveryPreparation(false, false, detail);
        }
        boolean indexCreated = results.stream()
                .anyMatch(result -> result.status() == OpenSearchSink.IndexResult.Status.CREATED);
        return new RecoveryPreparation(
                true,
                clusterIdentityChanged || indexCreated,
                indexCreated ? "one or more selected indexes were recreated" : "selected indexes verified");
    }

    /**
     * Replays reproducible snapshots into a replaced or emptied search destination.
     *
     * <p>Files are suppressed only for this replay so already-written evidence is not duplicated.
     * Live traffic remains queued by {@link TrafficExportQueue} until the caller clears the
     * authorization pause.</p>
     *
     * <p>This method blocks while prior and replay snapshot lanes quiesce, stops and restarts
     * recurring reporters, and performs synchronous search writes. Caller must not invoke on the
     * EDT. Watchdog intervals emit progress warnings and are not completion deadlines.</p>
     *
     * @param token active export-run token
     * @return {@code true} when replay work completed while the token remained active
     */
    public static boolean replaySelectedSnapshots(ExportRunToken token) {
        if (!RuntimeConfig.isExportRunActive(token)) {
            return false;
        }
        StartupSnapshotCoordinator.cancelRun(token);
        if (!awaitCoordinatorIdle(token, REPLAY_WATCHDOG_LOG_MS, "prior_snapshot_quiesce")) {
            return false;
        }

        stopReplayableReporters();
        try {
            return runReplayWithWatchdog(
                    token,
                    REPLAY_WATCHDOG_LOG_MS,
                    SearchRecoveryBootstrap::scheduleSelectedSnapshots,
                    () -> finishSynchronousReplay(token));
        } finally {
            restartRecurringReporters();
        }
    }

    /**
     * Runs one token-scoped replay while periodic timeouts remain watchdog events, not deadlines.
     */
    static boolean runReplayWithWatchdog(
            ExportRunToken token,
            long watchdogMs,
            Runnable scheduleReplay,
            BooleanSupplier finishReplay) {
        if (!RuntimeConfig.isExportRunActive(token) || scheduleReplay == null || finishReplay == null) {
            return false;
        }
        RuntimeConfig.setSearchRecoveryReplay(true);
        try {
            StartupSnapshotCoordinator.beginRun(token);
            try {
                scheduleReplay.run();
            } catch (RuntimeException | Error failure) {
                StartupSnapshotCoordinator.cancelRun(token);
                throw failure;
            } finally {
                StartupSnapshotCoordinator.activateRun(token);
            }
            if (!awaitCoordinatorIdle(token, watchdogMs, "snapshot_replay")) {
                return false;
            }
            return RuntimeConfig.isExportRunActive(token) && finishReplay.getAsBoolean();
        } finally {
            RuntimeConfig.setSearchRecoveryReplay(false);
        }
    }

    /** Waits through repeated watchdog intervals while the replay token remains authoritative. */
    private static boolean awaitCoordinatorIdle(
            ExportRunToken token,
            long watchdogMs,
            String phase) {
        long intervalMs = Math.max(1L, watchdogMs);
        while (RuntimeConfig.isExportRunActive(token)) {
            if (StartupSnapshotCoordinator.awaitIdle(token, intervalMs)) {
                return true;
            }
            if (Thread.currentThread().isInterrupted() || !RuntimeConfig.isExportRunActive(token)) {
                return false;
            }
            Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                    + " Authorization recovery replay watchdog:"
                    + " phase=" + phase
                    + " waitedMs=" + intervalMs
                    + " action=continue_awaiting_replay.");
        }
        return false;
    }

    private static void scheduleSelectedSnapshots() {
        SettingsIndexReporter.pushSnapshotNow();
        FindingsIndexReporter.pushSnapshotNow();
        SitemapIndexReporter.pushSnapshotNow();
        ProxyHistoryIndexReporter.pushSnapshotNow();
        if (historicProxySelected()) {
            ProxyWebSocketIndexReporter.pushHistoricSnapshotNow();
        }
    }

    private static boolean finishSynchronousReplay(ExportRunToken token) {
        if (!RepeaterTabsIndexReporter.replaySearchRecoverySnapshot(token)) {
            return false;
        }
        ExporterIndexConfigReporter.pushConfigSnapshot();
        ExporterIndexStatsReporter.pushSnapshotNow();
        return RuntimeConfig.isExportRunActive(token);
    }

    private static void stopReplayableReporters() {
        ExporterIndexStatsReporter.stop();
        SettingsIndexReporter.stop();
        FindingsIndexReporter.stop();
        SitemapIndexReporter.stop();
        ProxyWebSocketIndexReporter.stop();
        ProxyHistoryIndexReporter.stop();
    }

    private static void restartRecurringReporters() {
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        ExporterIndexStatsReporter.start();
        SettingsIndexReporter.start();
        FindingsIndexReporter.start();
        SitemapIndexReporter.start();
        ProxyWebSocketIndexReporter.startLivePoll();
    }

    private static boolean historicProxySelected() {
        List<String> trafficTypes = RuntimeConfig.getState().trafficToolTypes();
        return trafficTypes != null && trafficTypes.contains("proxy_history");
    }

    /**
     * Result of index revalidation before authorization recovery resumes sends.
     *
     * @param ready whether all selected indexes are usable
     * @param replayRequired whether reproducible snapshots must be reseeded
     * @param detail concise operator-facing outcome
     */
    public record RecoveryPreparation(boolean ready, boolean replayRequired, String detail) {
    }
}
