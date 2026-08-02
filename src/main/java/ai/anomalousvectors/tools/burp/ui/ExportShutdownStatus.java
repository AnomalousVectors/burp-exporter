package ai.anomalousvectors.tools.burp.ui;

import java.util.List;
import java.util.Locale;

import ai.anomalousvectors.tools.burp.sinks.TrafficExportQueue;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.opensearch.BatchSizeController;
import ai.anomalousvectors.tools.burp.utils.opensearch.IndexingRetryCoordinator;

/**
 * User-visible control-status text for cooperative export shutdown.
 *
 * <p>Messages reflect actual behavior: the traffic drain worker finishes the in-flight bulk
 * batch before exit, live traffic/spill queues are cleared, and OpenSearch retry queues are
 * drained for a bounded budget before any remainder is discarded.</p>
 */
public final class ExportShutdownStatus {

    private static final String PREFIX = "Stopping: ";

    private ExportShutdownStatus() {}

    /**
     * Point-in-time queue depths captured on the EDT when the user clicks Stop.
     *
     * @param trafficQueued in-memory traffic queue size
     * @param spillQueued spill file queue size
     * @param retryQueued total documents across per-index retry queues
     * @param batchSize current traffic bulk batch size cap
     */
    public record Snapshot(int trafficQueued, int spillQueued, int retryQueued, int batchSize) {

        /**
         * Returns live traffic and spill documents that Stop clears without retrying.
         *
         * @return nonnegative traffic and spill backlog
         */
        public int trafficBacklog() {
            return Math.max(0, trafficQueued) + Math.max(0, spillQueued);
        }

        /**
         * Returns retry-queue documents that Stop attempts to drain before discard.
         *
         * @return nonnegative retry backlog
         */
        public int retryBacklog() {
            return Math.max(0, retryQueued);
        }

        /**
         * Returns all documents represented by the Stop-time snapshot.
         *
         * @return nonnegative traffic, spill, and retry backlog total
         */
        public int totalBacklog() {
            return trafficBacklog() + retryBacklog();
        }
    }

    /**
     * Captures queue depths and batch size for Stop status messaging.
     *
     * <p>Caller must invoke on the EDT.</p>
     *
     * @return point-in-time Stop status snapshot
     */
    public static Snapshot capture() {
        int trafficQueued = TrafficExportQueue.getCurrentSize();
        int spillQueued = TrafficExportQueue.getCurrentSpillSize();
        int retryQueued = totalRetryQueueDepth();
        int batchSize = BatchSizeController.getInstance().getCurrentBatchSize();
        return new Snapshot(trafficQueued, spillQueued, retryQueued, batchSize);
    }

    /**
     * Returns the initial status line shown immediately when Stop is clicked.
     *
     * @param snapshot non-null Stop-time queue snapshot
     * @return initial stopping message
     * @throws NullPointerException if {@code snapshot} is {@code null}
     */
    public static String initialStoppingMessage(Snapshot snapshot) {
        StringBuilder detail = new StringBuilder("waiting for in-flight traffic batch");
        int traffic = snapshot.trafficBacklog();
        int retry = snapshot.retryBacklog();
        if (traffic > 0 && retry > 0) {
            detail.append(", then clearing ").append(formatWhole(traffic))
                    .append(" traffic docs and draining ").append(formatWhole(retry))
                    .append(" retries");
        } else if (retry > 0) {
            detail.append(", then draining ").append(formatWhole(retry)).append(" retries");
        } else if (traffic > 0) {
            detail.append(", then clearing ").append(formatWhole(traffic)).append(" queued docs");
        }
        return PREFIX + detail + " …";
    }

    /**
     * Returns status while the traffic drain worker is shutting down.
     *
     * @return waiting-for-batch message; the in-flight bulk may still complete
     */
    public static String waitingForBatchMessage() {
        return PREFIX + "waiting for in-flight traffic batch …";
    }

    /**
     * Returns status while memory and spill queues are cleared after the worker stops.
     *
     * @param snapshot non-null Stop-time queue snapshot
     * @return queue-clearing message
     * @throws NullPointerException if {@code snapshot} is {@code null}
     */
    public static String clearingQueuedTrafficMessage(Snapshot snapshot) {
        int traffic = snapshot.trafficBacklog();
        if (traffic > 0) {
            return PREFIX + "clearing " + formatWhole(traffic) + " queued traffic docs …";
        }
        return PREFIX + "clearing queued traffic …";
    }

    /**
     * Status while Stop waits for the background retry drain to finish an in-flight bulk.
     *
     * <p>The retry queue can look empty while documents are held in that push; Stop must join
     * before deciding there is nothing to drain.</p>
     *
     * @return waiting-for-retry-push message
     */
    public static String waitingForInFlightRetryMessage() {
        return PREFIX + "waiting for in-flight retry push …";
    }

    /**
     * Status while Stop actively retries the OpenSearch retry queue.
     *
     * @param retryQueued documents currently waiting for retry
     * @return retry-drain message; negative values are treated as zero
     */
    public static String drainingRetriesMessage(int retryQueued) {
        int queued = Math.max(0, retryQueued);
        if (queued > 0) {
            return PREFIX + "draining " + formatWhole(queued) + " retry docs …";
        }
        return PREFIX + "checking retry queue …";
    }

    /**
     * Returns status while the final exporter stats snapshot is pushed.
     *
     * @return final-stats-push message
     */
    public static String pushingFinalStatsMessage() {
        return PREFIX + "pushing final exporter stats …";
    }

    /**
     * Returns status while selected file artifacts receive final validation.
     *
     * @return file-validation message
     */
    public static String validatingFileArtifactsMessage() {
        return PREFIX + "validating file artifacts …";
    }

    /**
     * Returns status while destination client pools are closed.
     *
     * @return connection-closing message
     */
    public static String closingConnectionsMessage() {
        return PREFIX + "closing destination connections …";
    }

    /**
     * Returns status while a second Stop click requests force-abort.
     *
     * @return force-stopping message
     */
    public static String forceStoppingMessage() {
        return PREFIX + "force-stop requested; skipping remaining remote waits …";
    }

    /**
     * Returns final status when shutdown completed via force-abort.
     *
     * @return force-stopped message
     */
    public static String forceStoppedMessage() {
        return "Force-stopped";
    }

    /**
     * Returns final status when ordinary shutdown is complete.
     *
     * @return stopped message
     */
    public static String stoppedMessage() {
        return "Stopped";
    }

    private static int totalRetryQueueDepth() {
        IndexingRetryCoordinator coordinator = IndexingRetryCoordinator.getInstance();
        int total = 0;
        List<String> keys = ExportStats.getIndexKeys();
        for (String indexKey : keys) {
            String indexName = RuntimeConfig.indexNameForKey(indexKey);
            total += coordinator.getQueueSize(indexName);
        }
        return total;
    }

    private static String formatWhole(int value) {
        return String.format(Locale.ROOT, "%,d", value);
    }
}
