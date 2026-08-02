package ai.anomalousvectors.tools.burp.sinks;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import ai.anomalousvectors.tools.burp.utils.ExportAdmissionController;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.concurrent.Workers;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClientWrapper;

/**
 * Forwards selected exporter log events to the Exporter index.
 *
 * <p>Registers as a {@link Logger.LogListener}; each log event is queued and pushed asynchronously
 * by a single worker thread. Events are forwarded only when export is ready, the
 * {@code exporter} source is enabled, the corresponding exporter log level is selected, and at
 * least one sink is active. While Soft Outage or hard cooldown is active, enqueue and drain
 * pause so tiny exporter singles do not compete with payload recovery.</p>
 *
 * <p>Delivery is fire-and-forget: failures are not logged back into the same stream to avoid
 * feedback loops. If the queue is full while healthy, the newest event is rejected (no
 * drop-oldest churn during capacity pressure).</p>
 */
public final class ExporterIndexLogForwarder implements Logger.LogListener {

    private static final String SCHEMA_VERSION = "1";
    private static final String EVENT_TYPE = "log";
    private static final int QUEUE_CAPACITY = 1000;

    private final BlockingQueue<Map<String, Object>> queue = new ArrayBlockingQueue<>(QUEUE_CAPACITY);
    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "burp-exporter-log-forwarder");
        t.setDaemon(true);
        return t;
    });

    /**
     * Starts the background worker that drains queued exporter log documents.
     *
     * <p>Safe to construct during extension startup. The worker is daemon-backed and remains idle
     * until runtime export state allows queued events to be emitted.</p>
     */
    public ExporterIndexLogForwarder() {
        worker.submit(this::drainLoop);
    }

    /**
     * Stops the background drain worker and clears any queued log documents.
     *
     * <p>Safe to call multiple times. Used during extension unload so hot reload does
     * not leave a stale forwarder thread behind. Delegates termination to {@link Workers}
     * so shutdown semantics match every other extension-owned worker.</p>
     */
    public void stop() {
        queue.clear();
        Workers.awaitExecutorShutdown(worker, Workers.DEFAULT_SHUTDOWN_TIMEOUT_MS);
    }

    /**
     * Queues one exporter log event when the current runtime configuration allows export.
     *
     * <p>Safe to call from any thread. Returns immediately when export is not ready, the
     * {@code exporter} source is disabled, the current level is not selected, or no sink is
     * enabled.</p>
     */
    @Override
    public void onLog(String level, String message) {
        if (!RuntimeConfig.isExportReady()) {
            return;
        }
        if (!RuntimeConfig.isDataSourceEnabled(ai.anomalousvectors.tools.burp.utils.config.ConfigKeys.SRC_EXPORTER)) {
            return;
        }
        if (!RuntimeConfig.isExporterLogLevelEnabled(normalizeLevel(level))) {
            return;
        }
        if (!RuntimeConfig.isAnySinkEnabled()) {
            return;
        }
        // High-volume Amazon bulk lifecycle TRACE/INFO must never become exporter documents; that
        // creates a feedback loop (log → exporter bulk → more lifecycle TRACE → more exporter docs).
        // Periodic exporter-stats operator lines are also excluded: they describe the stats push
        // itself and would otherwise create extra exporter documents beside each snapshot.
        if (isBulkLifecycleNoise(message) || isExporterStatsOperatorNoise(message)) {
            return;
        }
        if (ExportAdmissionController.shouldPauseExporterNonFinal()) {
            return;
        }
        Map<String, Object> doc = new LinkedHashMap<>();
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("level", level != null ? level : "INFO");
        event.put("source", "burp-exporter");
        event.put("thread", Thread.currentThread().getName());
        event.put("type", EVENT_TYPE);
        event.put("summary", message != null ? message : "");
        doc.put("event", event);
        doc.put("meta", ExportMetaFields.meta(SCHEMA_VERSION));

        // Reject newest when full — avoid drop-oldest churn under pressure.
        queue.offer(doc);
    }

    private static boolean isBulkLifecycleNoise(String message) {
        if (message == null || message.isBlank()) {
            return false;
        }
        return message.contains("Bulk HTTP request started:")
                || message.contains("Bulk HTTP response received:")
                || message.contains("Bulk HTTP slow response:");
    }

    /**
     * Returns whether a log line describes an exporter-stats push and must not be re-indexed.
     *
     * @param message panel/log text
     * @return {@code true} when forwarding would create a feedback document beside the snapshot
     */
    private static boolean isExporterStatsOperatorNoise(String message) {
        if (message == null || message.isBlank()) {
            return false;
        }
        return message.contains("[PeriodicExport] Exporter stats:")
                || message.contains("[SnapshotExport] Exporter stats:")
                || message.contains("[Stats] Final exporter stats push:");
    }

    private void drainLoop() {
        while (true) {
            try {
                if (!RuntimeConfig.isExportRunning()) {
                    queue.clear();
                    TimeUnit.SECONDS.sleep(1);
                    continue;
                }
                if (!RuntimeConfig.isExportReady()) {
                    queue.clear();
                    TimeUnit.SECONDS.sleep(1);
                    continue;
                }

                if (!RuntimeConfig.isAnySinkEnabled()) {
                    queue.clear();
                    TimeUnit.SECONDS.sleep(1);
                    continue;
                }
                if (!RuntimeConfig.isDataSourceEnabled(ai.anomalousvectors.tools.burp.utils.config.ConfigKeys.SRC_EXPORTER)) {
                    queue.clear();
                    TimeUnit.SECONDS.sleep(1);
                    continue;
                }
                if (!RuntimeConfig.isAnyExporterLogLevelEnabled()) {
                    queue.clear();
                    TimeUnit.SECONDS.sleep(1);
                    continue;
                }
                if (ExportAdmissionController.shouldPauseExporterNonFinal()) {
                    TimeUnit.SECONDS.sleep(1);
                    continue;
                }

                Map<String, Object> doc = queue.poll(1, TimeUnit.SECONDS);
                if (doc == null) continue;
                // Export state can change while poll waits. Recheck before dispatch so a document
                // from a completed run cannot create an index during the next Start bootstrap.
                if (!RuntimeConfig.isExportReady()
                        || !RuntimeConfig.isAnySinkEnabled()
                        || !RuntimeConfig.isDataSourceEnabled(
                                ai.anomalousvectors.tools.burp.utils.config.ConfigKeys.SRC_EXPORTER)) {
                    continue;
                }
                if (!RuntimeConfig.isExporterLogLevelEnabled(normalizeLevel(eventLevel(doc)))) {
                    continue;
                }

                String baseUrl = RuntimeConfig.searchBaseUrl();
                boolean openSearchActive = RuntimeConfig.isSearchActive();
                boolean ok = OpenSearchClientWrapper.pushDocument(baseUrl, RuntimeConfig.indexNameForKey("exporter"), "exporter", doc);
                SingleDocOutcomeRecorder.record("exporter", ok, openSearchActive,
                        "Exporter log push failed");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception ignored) {
                // Fire-and-forget; avoid feedback loop
            }
        }
    }

    private static String eventLevel(Map<String, Object> doc) {
        Object eventObj = doc.get("event");
        if (eventObj instanceof Map<?, ?> event) {
            Object level = event.get("level");
            return level == null ? null : String.valueOf(level);
        }
        return null;
    }

    private static String normalizeLevel(String level) {
        return level == null ? "" : level.trim().toLowerCase(java.util.Locale.ROOT);
    }
}
