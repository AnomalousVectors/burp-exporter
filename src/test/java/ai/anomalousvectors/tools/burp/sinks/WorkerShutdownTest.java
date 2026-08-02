package ai.anomalousvectors.tools.burp.sinks;

import static ai.anomalousvectors.tools.burp.testutils.LazySchedulers.peek;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.callStatic;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.getStatic;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.setStatic;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.LockSupport;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.testutils.Reflect;
import ai.anomalousvectors.tools.burp.ui.ConfigPanel;
import ai.anomalousvectors.tools.burp.utils.concurrent.LazyScheduler;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.opensearch.IndexingRetryCoordinator;

/**
 * Proves that every extension-owned background worker terminates deterministically when its
 * {@code stop()} / {@code shutdown} entry point is invoked.
 *
 * <p>Covers the five owners enumerated during the BApp Store acceptance-criteria audit:
 * {@link TrafficHttpHandlerSupport}, {@link TrafficExportQueue}, {@link ProxyHistoryIndexReporter},
 * {@link IndexingRetryCoordinator}, and {@link ConfigPanel}'s static startup executor.</p>
 */
class WorkerShutdownTest {

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
