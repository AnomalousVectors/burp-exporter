package ai.anomalousvectors.tools.burp.testutils;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.LockSupport;

import ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotFlushExecutor;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

/** Shared helpers for {@link ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotExportEngine} tests. */
public final class SnapshotExportEngineTestSupport {

    private SnapshotExportEngineTestSupport() {}

    /**
     * Returns a file-only runtime state that routes snapshot flushes through {@code FileExportService}.
     */
    public static ConfigState.State fileOnlyTrafficState(Path root) {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(
                        true,
                        root.toString(),
                        true,
                        false,
                        false,
                        "",
                        "",
                        "",
                        ConfigState.OPEN_SEARCH_TLS_VERIFY),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy_history"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);
    }

    /**
     * Builds a prepared traffic document whose NDJSON length matches {@code estimatedBytes}.
     *
     * <p>Chunk assembly uses {@link PreparedExportDocument#resolvedBulkBytes()}, so tests that
     * exercise byte caps must keep the serialized payload size aligned with the requested estimate.
     * </p>
     */
    public static PreparedExportDocument preparedTrafficDoc(String indexName, int sequence, long estimatedBytes) {
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("sequence", sequence);
        document.put("request", Map.of("url", "https://example.test/item/" + sequence));
        String operationId = "snapshot-test-" + sequence;
        byte[] prefix = ("{\"index\":{\"_id\":\"" + operationId + "\"}}\n"
                + "{\"sequence\":" + sequence + ",\"pad\":\"").getBytes(StandardCharsets.UTF_8);
        byte[] suffix = "\"}\n".getBytes(StandardCharsets.UTF_8);
        int target = (int) Math.max(prefix.length + suffix.length, Math.min(Integer.MAX_VALUE, estimatedBytes));
        byte[] ndjson = new byte[target];
        System.arraycopy(prefix, 0, ndjson, 0, prefix.length);
        int padLen = target - prefix.length - suffix.length;
        if (padLen > 0) {
            Arrays.fill(ndjson, prefix.length, prefix.length + padLen, (byte) 'x');
        }
        System.arraycopy(suffix, 0, ndjson, target - suffix.length, suffix.length);
        return new PreparedExportDocument(
                operationId, indexName, "traffic", document, ndjson.length, ndjson);
    }

    /**
     * Polls until both snapshot flush pools report zero active workers or the deadline passes.
     *
     * @return {@code true} when both pools are idle
     */
    public static boolean awaitFlushPoolsIdle(long timeoutMs) {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            SnapshotFlushExecutor.Snapshot stats = SnapshotFlushExecutor.stats();
            if (stats.flush().activeCount() == 0 && stats.dualSink().activeCount() == 0) {
                return true;
            }
            LockSupport.parkNanos(50_000_000L);
        }
        SnapshotFlushExecutor.Snapshot stats = SnapshotFlushExecutor.stats();
        return stats.flush().activeCount() == 0 && stats.dualSink().activeCount() == 0;
    }
}
