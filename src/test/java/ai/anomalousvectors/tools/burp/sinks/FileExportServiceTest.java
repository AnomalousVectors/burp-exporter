package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.testutils.TestPathSupport;
import ai.anomalousvectors.tools.burp.utils.ControlStatusBridge;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;
import ai.anomalousvectors.tools.burp.utils.FileUtil;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

class FileExportServiceTest {

    private final ConfigState.State previous = RuntimeConfig.getState();

    @Test
    void emit_writesOperationIdOnlyInBulkActionMetadata() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-service");
            RuntimeConfig.updateState(fileExportState(root, true, Long.MAX_VALUE, false, 95));

            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName("traffic");
            PreparedExportDocument prepared = ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());

            FileExportService.emit(prepared);

            String jsonl = Files.readString(root.resolve(indexName + ".jsonl"));
            String ndjson = Files.readString(root.resolve(indexName + ".ndjson"));

            assertThat(jsonl).contains("https://acme.com/api");
            assertThat(jsonl).doesNotContain(prepared.operationId());
            assertThat(ndjson).contains(
                    "{\"index\":{\"_id\":\"" + prepared.operationId() + "\"}}");
            assertThat(ndjson).doesNotContain("\"export_id\"");
        });
    }

    @Test
    void emit_keepsSingleFilePerFormat_andDoesNotRoll() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-single-file");
            RuntimeConfig.updateState(fileExportState(root, true, Long.MAX_VALUE, false, 95));

            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName("traffic");
            PreparedExportDocument first = ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());
            PreparedExportDocument second = ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument("https://acme.com/api/2"));

            FileExportService.emit(first);
            FileExportService.emit(second);

            assertThat(root.resolve(indexName + ".jsonl")).exists();
            assertThat(root.resolve(indexName + ".ndjson")).exists();
            assertThat(root.resolve(indexName + "-0002.jsonl")).doesNotExist();
            assertThat(root.resolve(indexName + "-0002.ndjson")).doesNotExist();
        });
    }

    @Test
    void emit_writesNewlineTerminatedBulkNdjsonAndJsonlLines() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-newlines");
            RuntimeConfig.updateState(fileExportState(root, true, Long.MAX_VALUE, false, 95));

            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName("traffic");
            PreparedExportDocument prepared = ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());

            FileExportService.emit(prepared);

            String jsonl = Files.readString(root.resolve(indexName + ".jsonl"));
            String ndjson = Files.readString(root.resolve(indexName + ".ndjson"));

            assertThat(jsonl).endsWith("\n");
            assertThat(ndjson).endsWith("\n");
            assertThat(ndjson.lines().count()).isEqualTo(2);
        });
    }

    @Test
    void emit_writesJsonlAsDocumentOnlyLine() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-jsonl-shape");
            RuntimeConfig.updateState(fileExportState(root, true, Long.MAX_VALUE, false, 95));

            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName("traffic");
            PreparedExportDocument first = ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());
            PreparedExportDocument second = ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());

            FileExportService.emit(first);
            FileExportService.emit(second);

            List<String> jsonlLines = Files.readAllLines(root.resolve(indexName + ".jsonl"));
            assertThat(jsonlLines).hasSize(2);
            assertThat(jsonlLines.get(0)).startsWith("{");
            assertThat(jsonlLines.get(0)).doesNotContain("\"index\"");
            assertThat(jsonlLines.get(0)).doesNotContain("\"export_id\"");
            assertThat(jsonlLines.get(1)).doesNotContain("\"export_id\"");
        });
    }

    @Test
    void emit_appendsToExistingExporterFiles_insteadOfTruncating() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-append-existing");
            RuntimeConfig.updateState(fileExportState(root, true, Long.MAX_VALUE, false, 95));

            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName("traffic");
            Path jsonlPath = root.resolve(indexName + ".jsonl");
            Path ndjsonPath = root.resolve(indexName + ".ndjson");
            Files.writeString(jsonlPath, "{\"seed\":true}\n");
            Files.writeString(ndjsonPath, "{\"index\":{}}\n{\"seed\":true}\n");

            PreparedExportDocument prepared = ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());
            FileExportService.emit(prepared);

            List<String> jsonlLines = Files.readAllLines(jsonlPath);
            List<String> ndjsonLines = Files.readAllLines(ndjsonPath);
            assertThat(jsonlLines).hasSize(2);
            assertThat(jsonlLines.getFirst()).isEqualTo("{\"seed\":true}");
            assertThat(jsonlLines.getLast()).contains("https://acme.com/api");
            assertThat(ndjsonLines).hasSize(4);
            assertThat(ndjsonLines.getFirst()).isEqualTo("{\"index\":{}}");
            assertThat(ndjsonLines.get(1)).isEqualTo("{\"seed\":true}");
            assertThat(ndjsonLines.get(2)).isEqualTo(
                    "{\"index\":{\"_id\":\"" + prepared.operationId() + "\"}}");
            assertThat(ndjsonLines.get(3)).contains("https://acme.com/api");
        });
    }

    @Test
    void emit_recordsFileStatsForIndexAndTrafficSource() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-stats");
            RuntimeConfig.updateState(fileExportState(root, true, Long.MAX_VALUE, false, 95));

            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName("traffic");
            PreparedExportDocument prepared = ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());
            long beforeSuccess = FileExportStats.getSuccessCount("traffic");
            long beforeSource = FileExportStats.getTrafficToolTypeSuccessCount("PROXY");

            FileExportService.emit(prepared);

            assertThat(FileExportStats.getSuccessCount("traffic")).isEqualTo(beforeSuccess + 1);
            assertThat(FileExportStats.getTrafficToolTypeSuccessCount("PROXY")).isEqualTo(beforeSource + 1);
            assertThat(FileExportStats.getExportedBytes("traffic")).isGreaterThan(0L);
        });
    }

    @Test
    void emitPreparedChunk_writesEveryDocumentAndRecordsExactBatchStats() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-batch");
            RuntimeConfig.updateState(fileExportState(root, true, Long.MAX_VALUE, false, 95));
            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName(indexKey);
            List<PreparedExportDocument> prepared = List.of(
                    ExportDocumentIdentity.prepare(
                            indexName, indexKey, sampleDocument("https://acme.com/api/1")),
                    ExportDocumentIdentity.prepare(
                            indexName, indexKey, sampleDocument("https://acme.com/api/2")));

            FileExportService.emitPreparedChunk(prepared);
            FileExportService.validateRunArtifacts();

            Path jsonl = root.resolve(indexName + ".jsonl");
            Path ndjson = root.resolve(indexName + ".ndjson");
            assertThat(Files.readAllLines(jsonl)).hasSize(2);
            assertThat(Files.readAllLines(ndjson)).hasSize(4);
            assertThat(FileExportStats.getSuccessCount(indexKey)).isEqualTo(2L);
            assertThat(FileExportStats.getExportedBytes(indexKey))
                    .isEqualTo(Files.size(jsonl) + Files.size(ndjson));
            assertThat(FileExportStats.getArtifactIntegrity(indexKey))
                    .isEqualTo(FileExportStats.ArtifactIntegrity.OK);
        });
    }

    @Test
    void emit_whenOneFormatFails_recordsPartialBytesButNoDocumentSuccess() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-partial-format");
            RuntimeConfig.updateState(fileExportState(root, true, Long.MAX_VALUE, false, 95));
            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName(indexKey);
            Files.createDirectory(root.resolve(indexName + ".ndjson"));
            PreparedExportDocument prepared =
                    ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());

            FileExportService.emit(prepared);

            Path jsonl = root.resolve(indexName + ".jsonl");
            assertThat(jsonl).isRegularFile();
            assertThat(FileExportStats.getExportedBytes(indexKey)).isEqualTo(Files.size(jsonl));
            assertThat(FileExportStats.getSuccessCount(indexKey)).isZero();
            assertThat(FileExportStats.getFailureCount(indexKey)).isEqualTo(1L);
            assertThat(FileExportStats.getTrafficToolTypeSuccessCount("PROXY")).isZero();
            assertThat(FileExportStats.getTrafficToolTypeFailureCount("PROXY")).isEqualTo(1L);
            assertThat(FileExportStats.getLastError(indexKey)).isNotBlank();
        });
    }

    @Test
    void bulkSink_retriesAfterRollingBackPartialAppend_withoutDuplicatingBytes() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-safe-retry");
            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName(indexKey);
            PreparedExportDocument prepared = ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());
            AtomicInteger attempts = new AtomicInteger();
            BulkNdjsonFileSink sink = new BulkNdjsonFileSink(
                    root,
                    indexName,
                    indexKey,
                    (target, bytes) -> {
                        if (attempts.getAndIncrement() == 0) {
                            Files.write(
                                    target,
                                    java.util.Arrays.copyOf(bytes, bytes.length / 2),
                                    StandardOpenOption.CREATE,
                                    StandardOpenOption.APPEND);
                            throw new IOException("simulated partial append");
                        }
                        Files.write(
                                target,
                                bytes,
                                StandardOpenOption.CREATE,
                                StandardOpenOption.APPEND);
                    });

            long written = sink.appendDocument(prepared);

            assertThat(written).isEqualTo(prepared.bulkNdjsonBytes().length);
            assertThat(Files.readAllBytes(root.resolve(indexName + ".ndjson")))
                    .isEqualTo(prepared.bulkNdjsonBytes());
            assertThat(attempts).hasValue(2);
            assertThat(FileExportStats.getRetryAttemptCount(indexKey)).isEqualTo(1L);
        });
    }

    @Test
    void bulkSink_exhaustedRetries_rollsBackEveryPartialAppend() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-safe-retry-exhausted");
            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName(indexKey);
            Path target = root.resolve(indexName + ".ndjson");
            byte[] seed = "{\"index\":{}}\n{\"seed\":true}\n".getBytes(StandardCharsets.UTF_8);
            Files.write(target, seed);
            PreparedExportDocument prepared =
                    ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());
            AtomicInteger attempts = new AtomicInteger();
            BulkNdjsonFileSink sink = new BulkNdjsonFileSink(
                    root,
                    indexName,
                    indexKey,
                    (path, bytes) -> {
                        attempts.incrementAndGet();
                        Files.write(
                                path,
                                java.util.Arrays.copyOf(bytes, bytes.length / 2),
                                StandardOpenOption.CREATE,
                                StandardOpenOption.APPEND);
                        throw new IOException("simulated terminal partial append");
                    });

            long written = sink.appendDocument(prepared);

            assertThat(written).isZero();
            assertThat(Files.readAllBytes(target)).isEqualTo(seed);
            assertThat(attempts).hasValue(3);
            assertThat(FileExportStats.getRetryAttemptCount(indexKey)).isEqualTo(2L);
            assertThat(FileExportStats.getLastError(indexKey))
                    .contains("simulated terminal partial append");
        });
    }

    @Test
    void emit_stopsAllFileExport_whenTotalCapIsHit() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-total-cap");
            PreparedExportDocument first = ExportDocumentIdentity.prepare(IndexNaming.indexNameForShortName("traffic"), "traffic", sampleDocument());
            PreparedExportDocument second = ExportDocumentIdentity.prepare(IndexNaming.indexNameForShortName("settings"), "settings",
                    sampleDocument("https://acme.com/settings"));

            long firstBytes = new JsonlFileSink(root, first.indexName(), first.indexKey()).estimateBytes(first)
                    + new BulkNdjsonFileSink(root, first.indexName(), first.indexKey()).estimateBytes(first);
            RuntimeConfig.updateState(fileExportState(root, true, firstBytes + 10L, false, 95));

            FileExportService.emit(first);
            FileExportService.emit(second);

            assertThat(root.resolve(first.indexName() + ".jsonl")).exists();
            assertThat(root.resolve(first.indexName() + ".ndjson")).exists();
            assertThat(root.resolve(second.indexName() + ".jsonl")).doesNotExist();
            assertThat(root.resolve(second.indexName() + ".ndjson")).doesNotExist();
        });
    }

    @Test
    void emit_countsExistingExporterFilesTowardCap_and_reportsOpenSearchContinues() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-existing-cap");
            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName("traffic");
            Path existingJsonl = root.resolve(indexName + ".jsonl");
            Files.writeString(existingJsonl, "{\"seed\":true}\n");

            PreparedExportDocument prepared = ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());
            long plannedBytes = new JsonlFileSink(root, indexName, prepared.indexKey()).estimateBytes(prepared)
                    + new BulkNdjsonFileSink(root, indexName, prepared.indexKey()).estimateBytes(prepared);
            long existingBytes = Files.size(existingJsonl);
            RuntimeConfig.updateState(fileExportState(root, true, existingBytes + plannedBytes - 1L, false, 95, true));
            AtomicReference<String> status = new AtomicReference<>();
            ControlStatusBridge.register(status::set);

            FileExportService.emit(prepared);

            assertThat(Files.readString(existingJsonl)).isEqualTo("{\"seed\":true}\n");
            assertThat(root.resolve(indexName + ".ndjson")).doesNotExist();
            assertThat(status.get()).contains(RuntimeConfig.searchDestinationDisplayName() + " export continues.");
            assertThat(RuntimeConfig.isOpenSearchExportEnabled()).isTrue();
            assertThat(FileExportStats.getFailureCount("traffic")).isEqualTo(1L);
        });
    }

    @Test
    void createSelectedExportFiles_createsExpectedFilesWhenExporterSourceIsSelected() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-init");
            Path rootAbs = root.toAbsolutePath().normalize();
            RuntimeConfig.updateState(fileExportState(rootAbs, true, Long.MAX_VALUE, false, 95));

            List<FileExportService.FileInitResult> results =
                    FileExportService.createSelectedExportFiles(List.of("settings", "traffic", "exporter"));

            assertThat(results)
                    .extracting(result -> result.status())
                    .containsOnly(ai.anomalousvectors.tools.burp.utils.FileUtil.Status.CREATED);
            assertThat(rootAbs.resolve(IndexNaming.indexNameForShortName("settings") + ".jsonl")).exists();
            assertThat(rootAbs.resolve(IndexNaming.indexNameForShortName("settings") + ".ndjson")).exists();
            assertThat(rootAbs.resolve(IndexNaming.indexNameForShortName("traffic") + ".jsonl")).exists();
            assertThat(rootAbs.resolve(IndexNaming.indexNameForShortName("traffic") + ".ndjson")).exists();
            assertThat(rootAbs.resolve(IndexNaming.indexNameForShortName("exporter") + ".jsonl")).exists();
            assertThat(rootAbs.resolve(IndexNaming.indexNameForShortName("exporter") + ".ndjson")).exists();
        });
    }

    @Test
    void validateRunArtifacts_recordsBaselineAppendedFinalSizeAndIntegrity() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-integrity-ok")
                    .toAbsolutePath()
                    .normalize();
            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName(indexKey);
            Path ndjson = root.resolve(indexName + ".ndjson");
            byte[] seed = "{\"index\":{}}\n{\"seed\":true}\n".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            Files.write(ndjson, seed);
            RuntimeConfig.updateState(fileExportState(root, true, Long.MAX_VALUE, false, 95));
            FileExportService.createSelectedExportFiles(List.of(ConfigKeys.SRC_TRAFFIC));
            PreparedExportDocument prepared =
                    ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());

            FileExportService.emit(prepared);
            FileExportService.validateRunArtifacts();

            assertThat(FileExportStats.getArtifactCount(indexKey)).isEqualTo(2L);
            assertThat(FileExportStats.getArtifactBaselineBytes(indexKey)).isEqualTo(seed.length);
            assertThat(FileExportStats.getArtifactExpectedFinalBytes(indexKey))
                    .isEqualTo(seed.length + FileExportStats.getExportedBytes(indexKey));
            assertThat(FileExportStats.getArtifactFinalBytes(indexKey))
                    .isEqualTo(FileExportStats.getArtifactExpectedFinalBytes(indexKey));
            assertThat(FileExportStats.getArtifactIntegrity(indexKey))
                    .isEqualTo(FileExportStats.ArtifactIntegrity.OK);
        });
    }

    @Test
    void validateRunArtifacts_detectsDeletedSelectedFile_andFailsClosed() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-integrity-deleted")
                    .toAbsolutePath()
                    .normalize();
            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName(indexKey);
            RuntimeConfig.updateState(fileExportState(root, true, Long.MAX_VALUE, false, 95));
            FileExportService.createSelectedExportFiles(List.of(ConfigKeys.SRC_TRAFFIC));

            Files.delete(root.resolve(indexName + ".ndjson"));
            FileExportService.validateRunArtifacts();

            assertThat(FileExportStats.getArtifactIntegrity(indexKey))
                    .isEqualTo(FileExportStats.ArtifactIntegrity.FAILED);
            assertThat(FileExportStats.getLastError(indexKey))
                    .contains("integrity lost")
                    .contains(indexName + ".ndjson");
            PreparedExportDocument prepared =
                    ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());
            Path jsonl = root.resolve(indexName + ".jsonl");
            long remainingSize = Files.size(jsonl);
            FileExportService.emit(prepared);
            assertThat(Files.size(jsonl)).isEqualTo(remainingSize);
        });
    }

    @Test
    void validateRunArtifacts_detectsExternalAppend_andFailsClosed() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-integrity-append")
                    .toAbsolutePath()
                    .normalize();
            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName(indexKey);
            RuntimeConfig.updateState(fileExportState(root, true, Long.MAX_VALUE, false, 95));
            FileExportService.createSelectedExportFiles(List.of(ConfigKeys.SRC_TRAFFIC));
            Path jsonl = root.resolve(indexName + ".jsonl");
            Path ndjson = root.resolve(indexName + ".ndjson");
            Files.writeString(ndjson, "{\"external\":true}\n", StandardOpenOption.APPEND);

            FileExportService.validateRunArtifacts();

            assertThat(FileExportStats.getArtifactIntegrity(indexKey))
                    .isEqualTo(FileExportStats.ArtifactIntegrity.FAILED);
            assertThat(FileExportStats.getLastError(indexKey))
                    .contains("expected")
                    .contains("bytes but found");
            long jsonlSize = Files.size(jsonl);
            long ndjsonSize = Files.size(ndjson);
            FileExportService.emit(
                    ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument()));
            assertThat(Files.size(jsonl)).isEqualTo(jsonlSize);
            assertThat(Files.size(ndjson)).isEqualTo(ndjsonSize);
        });
    }

    @Test
    void createSelectedExportFiles_rejectsConcurrentRunForSameNormalizedDirectory() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-directory-lock")
                    .toAbsolutePath()
                    .normalize();
            RuntimeConfig.updateState(fileExportState(root, true, Long.MAX_VALUE, false, 95));
            List<FileExportService.FileInitResult> first =
                    FileExportService.createSelectedExportFiles(List.of(ConfigKeys.SRC_TRAFFIC));

            List<FileExportService.FileInitResult> second =
                    FileExportService.createSelectedExportFiles(List.of(ConfigKeys.SRC_TRAFFIC));

            assertThat(first).allMatch(result -> result.status() != FileUtil.Status.FAILED);
            assertThat(second).singleElement().satisfies(result -> {
                assertThat(result.status()).isEqualTo(FileUtil.Status.FAILED);
                assertThat(result.error()).contains("another exporter is using");
            });
        });
    }

    @Test
    void createSelectedExportFiles_rejectsExternalDirectoryLock() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-external-directory-lock")
                    .toAbsolutePath()
                    .normalize();
            RuntimeConfig.updateState(fileExportState(root, true, Long.MAX_VALUE, false, 95));
            Path lockPath = directoryLockPath(root);
            Files.createDirectories(lockPath.getParent());

            try (FileChannel channel = FileChannel.open(
                            lockPath,
                            StandardOpenOption.CREATE,
                            StandardOpenOption.WRITE);
                    FileLock ignored = channel.lock()) {
                List<FileExportService.FileInitResult> results =
                        FileExportService.createSelectedExportFiles(List.of(ConfigKeys.SRC_TRAFFIC));

                assertThat(results).singleElement().satisfies(result -> {
                    assertThat(result.status()).isEqualTo(FileUtil.Status.FAILED);
                    assertThat(result.error()).contains("another exporter is using");
                });
            }
        });
    }

    @Test
    void resetForRuntime_releasesDirectoryLockForNextRun() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-directory-lock-release")
                    .toAbsolutePath()
                    .normalize();
            RuntimeConfig.updateState(fileExportState(root, true, Long.MAX_VALUE, false, 95));
            List<FileExportService.FileInitResult> first =
                    FileExportService.createSelectedExportFiles(List.of(ConfigKeys.SRC_TRAFFIC));

            FileExportService.resetForRuntime();
            List<FileExportService.FileInitResult> second =
                    FileExportService.createSelectedExportFiles(List.of(ConfigKeys.SRC_TRAFFIC));

            assertThat(first).allMatch(result -> result.status() != FileUtil.Status.FAILED);
            assertThat(second).allMatch(result -> result.status() != FileUtil.Status.FAILED);
        });
    }

    private void withCleanup(ThrowingRunnable action) throws Exception {
        try {
            action.run();
        } finally {
            RuntimeConfig.updateState(previous);
            FileExportService.resetForTests();
            ControlStatusBridge.clear();
        }
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    private static Path directoryLockPath(Path root) {
        Path normalized = root.toAbsolutePath().normalize();
        String lockName = UUID.nameUUIDFromBytes(
                normalized.toString().getBytes(StandardCharsets.UTF_8)) + ".lock";
        return Path.of(
                System.getProperty("java.io.tmpdir"),
                "burp-exporter-directory-locks",
                lockName);
    }

    private static ConfigState.State fileExportState(Path root, boolean totalEnabled, long totalBytes,
                                                     boolean diskPercentEnabled, int diskPercent) {
        return fileExportState(root, totalEnabled, totalBytes, diskPercentEnabled, diskPercent, false);
    }

    private static ConfigState.State fileExportState(Path root, boolean totalEnabled, long totalBytes,
                                                     boolean diskPercentEnabled, int diskPercent,
                                                     boolean openSearchEnabled) {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(true, root.toString(), true, true,
                        totalEnabled, ConfigState.bytesToGb(totalBytes),
                        diskPercentEnabled, diskPercent,
                        openSearchEnabled, openSearchEnabled ? "https://opensearch.url:9200" : "", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        );
    }

    private static Map<String, Object> sampleDocument() {
        return sampleDocument("https://acme.com/api");
    }

    private static Map<String, Object> sampleDocument(String url) {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", "1");
        meta.put("indexed_at", "2026-03-27T00:00:00Z");

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("url", url);
        request.put("method", "GET");

        Map<String, Object> burp = new LinkedHashMap<>();
        burp.put("reporting_tool", "Proxy");

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("burp", burp);
        document.put("request", request);
        document.put("meta", meta);
        return document;
    }
}
