package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.Serial;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import ai.anomalousvectors.tools.burp.testutils.LazySchedulers;
import ai.anomalousvectors.tools.burp.testutils.TestPathSupport;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.concurrent.ExportRunContext;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.sitemap.SiteMap;
import burp.api.montoya.project.Project;

/** Exercises held source reads and log entries across actual run-token transitions. */
@Timeout(20)
class ReporterRunBoundaryTest {
    private final ConfigState.State previousState = RuntimeConfig.getState();

    @AfterEach
    void cleanup() {
        ExportReporterLifecycle.resetForTests();
        RuntimeConfig.updateState(previousState);
    }

    @Test
    void queuedOldLogIsDiscardedButCurrentLogStillDrains() throws Exception {
        RuntimeConfig.setExportRunning(false);
        ExporterIndexLogForwarder forwarder = new ExporterIndexLogForwarder();
        HeldLogQueue queue = new HeldLogQueue();
        Field field = ExporterIndexLogForwarder.class.getDeclaredField("queue");
        field.setAccessible(true);
        field.set(forwarder, queue);
        try {
            Path root = TestPathSupport.createDirectory("log-run-boundary");
            start(root.resolve("old"));
            var old = RuntimeConfig.currentExportRunToken();
            forwarder.onLog("INFO", "old-run-marker");
            assertThat(queue.taken.await(5, TimeUnit.SECONDS)).isTrue();
            RuntimeConfig.setExportRunning(false);
            FileExportService.resetForRuntime();
            start(root.resolve("current"));
            queue.release.countDown();
            ExportRunContext.call(old, () -> { forwarder.onLog("INFO", "stale-context-marker"); return null; });
            forwarder.onLog("INFO", "current-run-marker");
            Path file = root.resolve("current/tool-burp-exporter.ndjson");
            awaitContains(file, "current-run-marker");
            assertThat(Files.readString(file)).doesNotContain("old-run-marker", "stale-context-marker");
        } finally {
            queue.release.countDown();
            forwarder.stop();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void delayedSettingsCannotWriteOrSuppressCurrentSnapshot(boolean failOldRead) throws Exception {
        MontoyaApi api = mock(MontoyaApi.class);
        BurpSuite suite = mock(BurpSuite.class);
        when(api.burpSuite()).thenReturn(suite);
        when(suite.exportUserOptionsAsJson()).thenReturn("{}");
        CountDownLatch reading = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger calls = new AtomicInteger();
        when(suite.exportProjectOptionsAsJson()).thenAnswer(invocation -> {
            if (calls.getAndIncrement() == 0) {
                reading.countDown();
                awaitUncooperative(release);
                if (failOldRead) throw new IllegalStateException("old-read-failure-marker");
                return "{\"marker\":\"old-run-settings\"}";
            }
            return "{\"marker\":\"current-run-settings\"}";
        });
        MontoyaApiProvider.set(api);
        List<String> events = new CopyOnWriteArrayList<>();
        Logger.LogListener listener = (level, message) -> events.add(message);
        Logger.registerListener(listener);
        try (var worker = Executors.newSingleThreadExecutor()) {
            Path root = TestPathSupport.createDirectory("settings-run-boundary");
            start(root.resolve("old"));
            CompletableFuture<Void> old = CompletableFuture.runAsync(SettingsIndexReporter::pushSnapshotIfChanged, worker);
            try {
                assertThat(reading.await(5, TimeUnit.SECONDS)).isTrue();
                RuntimeConfig.setExportRunning(false);
                SettingsIndexReporter.stop();
                FileExportService.resetForRuntime();
                start(root.resolve("current"));
                SettingsIndexReporter.pushSnapshotIfChanged();
                release.countDown();
                old.get(5, TimeUnit.SECONDS);
                SettingsIndexReporter.pushSnapshotIfChanged();
                Path file = root.resolve("current/tool-burp-settings.ndjson");
                assertThat(Files.readString(file)).contains("current-run-settings").doesNotContain("old-run-settings");
                assertThat(Files.readAllLines(file)).hasSize(2);
                assertThat(events).noneMatch(message -> message.contains("old-read-failure-marker"));
            } finally {
                release.countDown();
            }
        } finally {
            Logger.unregisterListener(listener);
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void heldStartupReadDoesNotBlockStopOrEnableTheNextRunsPolling(boolean findings) throws Exception {
        MontoyaApi api = mock(MontoyaApi.class);
        SiteMap siteMap = mock(SiteMap.class);
        when(api.siteMap()).thenReturn(siteMap);
        MontoyaApiProvider.set(api);
        CountDownLatch reading = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        if (findings) {
            when(siteMap.issues()).thenAnswer(invocation -> { reading.countDown(); awaitUncooperative(release); return List.of(); });
        } else {
            when(siteMap.requestResponses()).thenAnswer(invocation -> { reading.countDown(); awaitUncooperative(release); return List.of(); });
        }
        Path root = TestPathSupport.createDirectory("startup-read-boundary");
        start(root);
        try (var stopWorker = Executors.newSingleThreadExecutor()) {
            if (findings) FindingsIndexReporter.pushSnapshotNow();
            else SitemapIndexReporter.pushSnapshotNow();
            assertThat(reading.await(5, TimeUnit.SECONDS)).isTrue();
            var old = RuntimeConfig.currentExportRunToken();
            RuntimeConfig.setExportRunning(false);
            try {
                CompletableFuture.runAsync(() -> {
                    if (findings) FindingsIndexReporter.stop(); else SitemapIndexReporter.stop();
                }, stopWorker).get(2, TimeUnit.SECONDS);
                start(root);
                if (findings) FindingsIndexReporter.start(); else SitemapIndexReporter.start();
                release.countDown();
                assertThat(ai.anomalousvectors.tools.burp.utils.concurrent.StartupSnapshotCoordinator
                        .awaitIdle(old, 5_000)).isTrue();
                assertThat(LazySchedulers.peek(findings ? FindingsIndexReporter.class : SitemapIndexReporter.class,
                        "SCHEDULER")).isNull();
            } finally {
                release.countDown();
            }
        }
    }

    @Test
    void lateMetadataFallbackCannotConsumeTheNewRunsDiagnostic() throws Exception {
        MontoyaApi api = mock(MontoyaApi.class);
        BurpSuite suite = mock(BurpSuite.class);
        Project project = mock(Project.class);
        when(api.burpSuite()).thenReturn(suite);
        when(api.project()).thenReturn(project);
        when(suite.exportProjectOptionsAsJson()).thenReturn("{}");
        when(suite.exportUserOptionsAsJson()).thenReturn("{}");
        CountDownLatch reading = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        when(project.id()).thenAnswer(invocation -> {
            reading.countDown();
            awaitUncooperative(release);
            return null;
        });
        MontoyaApiProvider.set(api);
        try (var worker = Executors.newSingleThreadExecutor()) {
            Path root = TestPathSupport.createDirectory("metadata-run-boundary");
            start(root);
            CompletableFuture<Void> old = CompletableFuture.runAsync(SettingsIndexReporter::pushSnapshotNow, worker);
            try {
                assertThat(reading.await(5, TimeUnit.SECONDS)).isTrue();
                RuntimeConfig.setExportRunning(false);
                SettingsIndexReporter.stop();
                start(root);
                release.countDown();
                old.get(5, TimeUnit.SECONDS);
                Field flag = SettingsIndexReporter.class.getDeclaredField("projectIdFallbackLogged");
                flag.setAccessible(true);
                assertThat(java.util.concurrent.atomic.AtomicBoolean.class.cast(flag.get(null))).isFalse();
            } finally {
                release.countDown();
            }
        }
    }

    @Test
    void staleCallerCannotRebindAnyOrdinaryReporterEntryPoint() throws Exception {
        Path root = TestPathSupport.createDirectory("stale-reporter-entries");
        start(root);
        var old = RuntimeConfig.currentExportRunToken();
        RuntimeConfig.setExportRunning(false);
        start(root);
        ExportRunContext.call(old, () -> {
            SettingsIndexReporter.pushSnapshotNow();
            SettingsIndexReporter.pushSnapshotIfChanged();
            ExporterIndexConfigReporter.pushConfigSnapshot();
            ExporterIndexStatsReporter.pushSnapshotNow();
            SitemapIndexReporter.pushNewItemsOnly();
            FindingsIndexReporter.pushNewIssuesOnly();
            return null;
        });
        try (var entries = Files.list(root)) {
            assertThat(entries.toList()).isEmpty();
        }
    }

    @Test
    void lateReporterExitCannotReleaseTheNewRunsPass() {
        ReporterRunActivity activity = new ReporterRunActivity();
        RuntimeConfig.setExportRunning(true);
        var old = RuntimeConfig.currentExportRunToken();
        assertThat(activity.tryEnter()).isTrue();
        RuntimeConfig.setExportRunning(false);
        activity.clear();
        RuntimeConfig.setExportRunning(true);
        assertThat(activity.tryEnter()).isTrue();
        ExportRunContext.call(old, () -> { activity.exit(); return null; });
        assertThat(activity.tryEnter()).isFalse();
        activity.exit();
        assertThat(activity.tryEnter()).isTrue();
        activity.exit();
    }

    private static void start(Path root) {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_SETTINGS, ConfigKeys.SRC_SITEMAP, ConfigKeys.SRC_FINDINGS, ConfigKeys.SRC_EXPORTER),
                ConfigKeys.SCOPE_ALL, List.of(),
                new ConfigState.Sinks(true, root.toString(), false, true, false, "", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES, ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS, null));
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.setExportStarting(false);
    }

    private static void awaitContains(Path file, String expected) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < deadline) {
            if (Files.exists(file) && Files.readString(file).contains(expected)) return;
            TimeUnit.MILLISECONDS.sleep(20);
        }
        assertThat(file).exists();
        assertThat(Files.readString(file)).contains(expected);
    }

    private static void awaitUncooperative(CountDownLatch latch) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (latch.getCount() != 0) {
            try {
                assertThat(latch.await(Math.max(1, deadline - System.nanoTime()), TimeUnit.NANOSECONDS)).isTrue();
            } catch (InterruptedException ignored) {
                // Model a public API that consumes interruption; ownership must still reject its result.
            }
        }
    }

    private static final class HeldLogQueue extends ArrayBlockingQueue<Object> {
        @Serial private static final long serialVersionUID = 1L;
        private final transient CountDownLatch taken = new CountDownLatch(1);
        private final transient CountDownLatch release = new CountDownLatch(1);
        private HeldLogQueue() { super(1000); }
        @Override public Object poll(long timeout, TimeUnit unit) throws InterruptedException {
            Object document = super.poll(timeout, unit);
            if (document != null) { taken.countDown(); awaitUncooperative(release); }
            return document;
        }
    }
}
