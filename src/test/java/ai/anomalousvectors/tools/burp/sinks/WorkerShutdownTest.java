package ai.anomalousvectors.tools.burp.sinks;

import static ai.anomalousvectors.tools.burp.testutils.LazySchedulers.peek;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.callStatic;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.getStatic;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.setStatic;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.LockSupport;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.testutils.Reflect;
import ai.anomalousvectors.tools.burp.ui.ConfigPanel;
import ai.anomalousvectors.tools.burp.utils.concurrent.LazyScheduler;
import ai.anomalousvectors.tools.burp.utils.concurrent.Workers;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.opensearch.IndexingRetryCoordinator;

/**
 * Proves that every extension-owned background worker terminates deterministically when its
 * {@code stop()} / {@code shutdown} entry point is invoked.
 *
 * <p>The contract inventory below covers every production owner found by the source-factory
 * census. Owners with identical lifecycle policy are grouped only when their concrete names are
 * listed. The census intentionally fails when a thread, executor, lazy scheduler, or Swing timer
 * is added or removed without updating this inventory and its focused coverage.</p>
 */
class WorkerShutdownTest {

    private static final List<Pattern> OWNER_FACTORY_PATTERNS = List.of(
            Pattern.compile("new\\s+Thread\\s*\\("),
            Pattern.compile("Executors\\.new"),
            Pattern.compile("new\\s+LazyScheduler\\s*\\("),
            Pattern.compile("new\\s+Timer\\s*\\("));

    private static final Map<String, Integer> EXPECTED_OWNER_FACTORIES = Map.ofEntries(
            Map.entry("sinks/BodyEnumerationSkippedLog.java", 1),
            Map.entry("sinks/CompressedWireBodyParamsLog.java", 1),
            Map.entry("sinks/ExporterIndexLogForwarder.java", 2),
            Map.entry("sinks/ExporterIndexStatsReporter.java", 1),
            Map.entry("sinks/ExportReporterLifecycle.java", 1),
            Map.entry("sinks/FindingsIndexReporter.java", 1),
            Map.entry("sinks/ProxyHistoryIndexReporter.java", 1),
            Map.entry("sinks/ProxyLiveMetadataCorrelator.java", 1),
            Map.entry("sinks/RepeaterSwingTabWalker.java", 2),
            Map.entry("sinks/RepeaterTabsIndexReporter.java", 1),
            Map.entry("sinks/SettingsIndexReporter.java", 1),
            Map.entry("sinks/SitemapIndexReporter.java", 1),
            Map.entry("sinks/TrafficExportQueue.java", 1),
            Map.entry("sinks/TrafficHttpHandlerSupport.java", 1),
            Map.entry("ui/ConfigPanel.java", 4),
            Map.entry("ui/controller/ConfigController.java", 2),
            Map.entry("ui/LogPanel.java", 1),
            Map.entry("ui/StatsPanel.java", 1),
            Map.entry("utils/concurrent/EdtMonitor.java", 2),
            Map.entry("utils/concurrent/LazyScheduler.java", 2),
            Map.entry("utils/concurrent/SnapshotExportEngine.java", 2),
            Map.entry("utils/concurrent/SnapshotFlushExecutor.java", 1),
            Map.entry("utils/concurrent/StartupSnapshotCoordinator.java", 2),
            Map.entry("utils/opensearch/IndexingRetryCoordinator.java", 1));

    /**
     * Lifecycle contracts represented by the factory census.
     *
     * <p>Periodic LazyScheduler owners (stats, settings, findings, sitemap, Proxy History,
     * Proxy reconciliation, orphan export, and both parameter-integrity flushers) start lazily,
     * stop through their owner or {@link ExportReporterLifecycle}, unload through that lifecycle,
     * restart lazily, wait at most {@link Workers#DEFAULT_SHUTDOWN_TIMEOUT_MS}, and interrupt their
     * scheduled executor. Their owner tests plus this class cover termination. Traffic queue and
     * retry workers start on admitted work, stop and unload with bounded joins, and restart lazily;
     * this class covers both cooperative and non-cooperative termination.</p>
     *
     * <p>The Config Start executor starts lazily, uses the shared one-second unload wait, and is
     * replaced for reload. Config action executors are constructed per controller and close by
     * immediate interruption plus generation-fenced callbacks; reattachment creates a new
     * controller. The raw Stop owner starts per Stop, is force-interrupted and joined for at most
     * one second on unload, and is replaced per run. The log forwarder is constructed once per
     * extension load and receives the same bounded unload shutdown.</p>
     *
     * <p>Startup coordination, snapshot flush/dual-sink pools, and per-snapshot build pools are
     * run-token owned, cancelled on Stop/unload, bounded by the shared Stop/unload budget, and
     * recreated for later runs. The short-lived connection-reclaim and Repeater-summary threads
     * are generation fenced; reclaim is boundedly awaited and the summary cannot publish across a
     * cleared run. Repeater walk timers are EDT-owned and generation fenced. Config hint, Log
     * debounce, and Stats refresh timers are EDT-owned, non-blocking, and stopped or rendered
     * harmless by panel lifecycle. EdtMonitor is snapshot-reference-counted and terminates when
     * the last snapshot exits.</p>
     *
     * <p>Cached search clients are closed asynchronously on Stop and synchronously on unload;
     * restart is lazy. Montoya registrations are created at initialize, are inactive on Stop, and
     * are deregistered on unload. Logger/runtime UI listeners register on load or panel attach and
     * unregister/clear on removal or unload. These non-factory owners are covered by
     * ExporterLifecycleTest, LogPanelLoggerLifecycleHeadlessTest, StatsPanel lifecycle tests, and
     * connector cache/TLS tests.</p>
     */

    @Test
    void lifecycleInventory_matchesEveryProductionWorkerFactory() throws Exception {
        Path sourceRoot = Path.of("src", "main", "java", "ai", "anomalousvectors", "tools", "burp");
        Map<String, Integer> actual = new java.util.TreeMap<>();
        try (Stream<Path> paths = Files.walk(sourceRoot)) {
            paths.filter(path -> path.toString().endsWith(".java")).forEach(path -> {
                String source;
                try {
                    source = Files.readString(path);
                } catch (java.io.IOException e) {
                    throw new java.io.UncheckedIOException(e);
                }
                int count = OWNER_FACTORY_PATTERNS.stream()
                        .mapToInt(pattern -> (int) pattern.matcher(source).results().count())
                        .sum();
                if (count > 0) {
                    actual.put(sourceRoot.relativize(path).toString().replace('\\', '/'), count);
                }
            });
        }

        assertThat(actual).containsExactlyInAnyOrderEntriesOf(EXPECTED_OWNER_FACTORIES);
    }

    @BeforeEach
    public void resetExportRunningFlag() {
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStarting(false);
        RuntimeConfig.setExportStopping(false);
    }

    @AfterEach
    public void stopAllWorkers() {
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStarting(false);
        RuntimeConfig.setExportStopping(false);
        TrafficExportQueue.stopWorker();
        TrafficExportQueue.clearPendingWork();
        TrafficHttpHandlerSupport.stop();
        ProxyHistoryIndexReporter.stop();
        IndexingRetryCoordinator.getInstance().stopDrainThread();
        IndexingRetryCoordinator.getInstance().clearPendingWork();
    }

    @Test
    void trafficHttpHandlerSupport_stop_terminatesOrphanScheduler() throws Exception {
        callStatic(TrafficHttpHandlerSupport.class, "ensureOrphanSchedulerStarted");
        ScheduledExecutorService started = peek(TrafficHttpHandlerSupport.class, "ORPHAN_SCHEDULER");
        assertThat(started).isNotNull();

        TrafficHttpHandlerSupport.stop();

        assertThat(peek(TrafficHttpHandlerSupport.class, "ORPHAN_SCHEDULER")).isNull();
        assertThat(started.isShutdown()).isTrue();
        assertThat(started.awaitTermination(2, TimeUnit.SECONDS)).isTrue();
    }

    @Test
    void trafficExportQueue_stopWorker_terminatesDrainWorker() throws Exception {
        RuntimeConfig.updateState(new ConfigState.State(
                java.util.List.of("traffic"),
                "all",
                java.util.List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                java.util.List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.setExportStarting(true);
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("burp", Map.of("reporting_tool", "Proxy"));
        TrafficExportQueue.offer(doc);

        Thread started = Thread.class.cast(getStatic(TrafficExportQueue.class, "drainWorker"));
        assertThat(started).isNotNull();
        assertThat(started.isAlive()).isTrue();

        TrafficExportQueue.stopWorker();

        started.join(2_000);
        assertThat(started.isAlive()).isFalse();
        assertThat(Thread.class.cast(getStatic(TrafficExportQueue.class, "drainWorker"))).isNull();
        TrafficExportQueue.clearPendingWork();
    }

    @Test
    void proxyHistoryIndexReporter_stop_terminatesScheduler() throws Exception {
        LazyScheduler holder = LazyScheduler.class.cast(getStatic(ProxyHistoryIndexReporter.class, "SCHEDULER"));
        ScheduledExecutorService started = holder.getOrStart();
        assertThat(started).isNotNull();

        ProxyHistoryIndexReporter.stop();

        assertThat(peek(ProxyHistoryIndexReporter.class, "SCHEDULER")).isNull();
        assertThat(started.isShutdown()).isTrue();
        assertThat(started.awaitTermination(2, TimeUnit.SECONDS)).isTrue();
    }

    @Test
    void indexingRetryCoordinator_stopDrainThread_terminatesDrainThread() throws Exception {
        IndexingRetryCoordinator coordinator = new IndexingRetryCoordinator();
        RuntimeConfig.setExportRunning(true);
        try {
            Reflect.call(coordinator, "ensureDrainThreadStarted");

            Thread started = Reflect.get(coordinator, "drainThread", Thread.class);
            assertThat(started).isNotNull();
            assertThat(started.isAlive()).isTrue();

            coordinator.stopDrainThread();

            started.join(2_000);
            assertThat(started.isAlive()).isFalse();
            assertThat(coordinator.isDrainThreadAlive()).isFalse();
        } finally {
            coordinator.stopDrainThread();
            coordinator.clearPendingWork();
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.resetExportRunForTests();
        }
    }

    @Test
    void indexingRetryCoordinator_stopRetainsLiveOwnerAndRefusesReplacement() throws Exception {
        IndexingRetryCoordinator coordinator = new IndexingRetryCoordinator();
        AtomicBoolean release = new AtomicBoolean();
        Thread stubbornOwner = new Thread(() -> {
            while (!release.get()) {
                LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(10L));
                Thread.interrupted();
            }
        }, "retry-owner-test");
        Reflect.set(coordinator, "drainThread", stubbornOwner);
        stubbornOwner.start();

        try {
            assertThat(coordinator.stopDrainThread(10L)).isFalse();
            assertThat(Reflect.get(coordinator, "drainThread", Thread.class)).isSameAs(stubbornOwner);
            Reflect.call(coordinator, "ensureDrainThreadStarted");
            assertThat(Reflect.get(coordinator, "drainThread", Thread.class)).isSameAs(stubbornOwner);
        } finally {
            release.set(true);
            LockSupport.unpark(stubbornOwner);
            stubbornOwner.join(1_000L);
        }

        assertThat(coordinator.stopDrainThread(10L)).isTrue();
        assertThat(Reflect.get(coordinator, "drainThread", Thread.class)).isNull();
    }

    @Test
    void configPanel_shutdownStartupExecutor_terminatesAndReplacesExecutor() throws Exception {
        ExecutorService before = ExecutorService.class.cast(getStatic(ConfigPanel.class, "startupExecutor"));
        assertThat(before.isShutdown()).isFalse();

        ConfigPanel.shutdownStartupExecutor();

        assertThat(before.isShutdown()).isTrue();
        assertThat(before.awaitTermination(2, TimeUnit.SECONDS)).isTrue();

        ExecutorService after = ExecutorService.class.cast(getStatic(ConfigPanel.class, "startupExecutor"));
        assertThat(after).isNotSameAs(before);
        assertThat(after.isShutdown()).isFalse();
    }

    @Test
    void trafficHttpHandlerSupport_stop_isIdempotent() {
        TrafficHttpHandlerSupport.stop();
        TrafficHttpHandlerSupport.stop();
        assertThat(peek(TrafficHttpHandlerSupport.class, "ORPHAN_SCHEDULER")).isNull();
    }

    @Test
    void proxyHistoryIndexReporter_stop_isIdempotent() {
        ProxyHistoryIndexReporter.stop();
        ProxyHistoryIndexReporter.stop();
        assertThat(peek(ProxyHistoryIndexReporter.class, "SCHEDULER")).isNull();
    }

    @Test
    void trafficExportQueue_stopWorker_whenNotStarted_isNoOp() {
        setStatic(TrafficExportQueue.class, "drainWorker", null);
        TrafficExportQueue.stopWorker();
        assertThat(Thread.class.cast(getStatic(TrafficExportQueue.class, "drainWorker"))).isNull();
    }
}
