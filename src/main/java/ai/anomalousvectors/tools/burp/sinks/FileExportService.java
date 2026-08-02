package ai.anomalousvectors.tools.burp.sinks;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BooleanSupplier;

import ai.anomalousvectors.tools.burp.utils.ControlStatusBridge;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;
import ai.anomalousvectors.tools.burp.utils.FileUtil;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.concurrent.ExportRunContext;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

/**
 * Shared dispatcher for file-based exports.
 *
 * <p>This service fans out prepared documents to enabled on-disk formats. It is process-local and
 * safe for concurrent use.</p>
 */
public final class FileExportService {

    private static final Map<String, FileSink> JSONL_SINKS = new ConcurrentHashMap<>();
    private static final Map<String, FileSink> BULK_SINKS = new ConcurrentHashMap<>();
    private static final Map<String, RootState> ROOT_STATES = new ConcurrentHashMap<>();

    private FileExportService() { }

    /**
     * Emits one prepared document to all enabled file formats.
     *
     * <p>Safe to call from any thread. Performs synchronous disk I/O and updates file and traffic
     * counters. No-op when file export, recovery replay, or the originating run disallows the
     * write; write and integrity failures are recorded and logged rather than thrown.</p>
     *
     * @param document prepared document to append; {@code null} is ignored
     */
    public static void emit(PreparedExportDocument document) {
        if (document == null
                || !RuntimeConfig.isAnyFileExportEnabled()
                || RuntimeConfig.isSearchRecoveryReplay()
                || !ExportRunContext.allowsRunMutation()) {
            return;
        }
        long startedAtMs = System.currentTimeMillis();
        String root = RuntimeConfig.fileExportRoot();
        Path rootPath = Path.of(root);
        RootState rootState = rootState(rootPath);

        if (rootState.isGloballyDisabled()) {
            return;
        }

        FileSink jsonl = RuntimeConfig.isFileJsonlEnabled()
                ? jsonlSink(root, document.indexName(), document.indexKey()) : null;
        FileSink bulk = RuntimeConfig.isFileBulkNdjsonEnabled()
                ? bulkSink(root, document.indexName(), document.indexKey()) : null;
        long plannedBytes = 0L;
        if (jsonl != null) {
            plannedBytes += jsonl.estimateBytes(document);
        }
        if (bulk != null) {
            plannedBytes += bulk.estimateBytes(document);
        }
        if (!rootState.allowWrite(rootPath, plannedBytes)) {
            recordFailure(document, rootState.reason());
            return;
        }

        FileExportStats.recordLastError(document.indexKey(), null);
        long written = 0L;
        if (jsonl != null) {
            written += jsonl.appendDocument(document);
        }
        if (bulk != null) {
            written += bulk.appendDocument(document);
        }
        if (!ExportRunContext.allowsRunMutation()) {
            return;
        }
        if (written > 0L) {
            rootState.recordWrite(written);
            FileExportStats.recordExportedBytes(document.indexKey(), written);
        }
        if (plannedBytes > 0L && written == plannedBytes) {
            FileExportStats.recordSuccess(document.indexKey(), 1);
            FileExportStats.recordLastWriteDurationMs(document.indexKey(), System.currentTimeMillis() - startedAtMs);
            if (FileExportStats.getArtifactIntegrity(document.indexKey())
                    != FileExportStats.ArtifactIntegrity.FAILED) {
                FileExportStats.recordLastError(document.indexKey(), null);
            }
            recordTrafficSuccess(document);
        } else {
            recordFailure(document, "File export write produced no bytes.");
        }
    }

    /**
     * Emits a batch of prepared documents to all enabled file formats.
     *
     * <p>Delegates to {@link #emitPreparedChunk(List)} and therefore performs synchronous disk I/O
     * with the same run, recovery, integrity, and accounting behavior.</p>
     *
     * @param documents prepared documents to append; {@code null} or empty is ignored
     */
    public static void emitBatch(List<PreparedExportDocument> documents) {
        emitPreparedChunk(documents);
    }

    /**
     * Emits one snapshot bulk chunk with a single root disk check and batched bulk-ndjson append.
     *
     * <p>Safe to call from any thread. Performs synchronous disk I/O and updates file and traffic
     * counters. All documents must target the same logical index as the first entry. No-op when
     * file export, recovery replay, or the originating run disallows the write; failures are
     * recorded and logged rather than thrown.</p>
     *
     * @param documents non-null prepared documents for one logical index; empty is ignored
     */
    public static void emitPreparedChunk(List<PreparedExportDocument> documents) {
        if (documents == null
                || documents.isEmpty()
                || !RuntimeConfig.isAnyFileExportEnabled()
                || RuntimeConfig.isSearchRecoveryReplay()
                || !ExportRunContext.allowsRunMutation()) {
            return;
        }
        PreparedExportDocument first = documents.getFirst();
        String root = RuntimeConfig.fileExportRoot();
        Path rootPath = Path.of(root);
        RootState rootState = rootState(rootPath);
        if (rootState.isGloballyDisabled()) {
            return;
        }

        FileSink jsonl = RuntimeConfig.isFileJsonlEnabled()
                ? jsonlSink(root, first.indexName(), first.indexKey()) : null;
        FileSink bulk = RuntimeConfig.isFileBulkNdjsonEnabled()
                ? bulkSink(root, first.indexName(), first.indexKey()) : null;
        long plannedBytes = 0L;
        if (jsonl != null) {
            for (PreparedExportDocument document : documents) {
                plannedBytes += jsonl.estimateBytes(document);
            }
        }
        if (bulk != null) {
            for (PreparedExportDocument document : documents) {
                plannedBytes += bulk.estimateBytes(document);
            }
        }
        if (!rootState.allowWrite(rootPath, plannedBytes)) {
            String reason = rootState.reason();
            for (PreparedExportDocument document : documents) {
                recordFailure(document, reason);
            }
            return;
        }

        long startedAtMs = System.currentTimeMillis();
        FileExportStats.recordLastError(first.indexKey(), null);
        long written = 0L;
        if (jsonl != null) {
            written += jsonl.appendBatch(documents);
        }
        if (bulk != null) {
            written += bulk.appendBatch(documents);
        }
        if (!ExportRunContext.allowsRunMutation()) {
            return;
        }
        if (written > 0L) {
            rootState.recordWrite(written);
            FileExportStats.recordExportedBytes(first.indexKey(), written);
        }
        if (plannedBytes > 0L && written == plannedBytes) {
            FileExportStats.recordSuccess(first.indexKey(), documents.size());
            FileExportStats.recordLastWriteDurationMs(
                    first.indexKey(), System.currentTimeMillis() - startedAtMs);
            if (FileExportStats.getArtifactIntegrity(first.indexKey())
                    != FileExportStats.ArtifactIntegrity.FAILED) {
                FileExportStats.recordLastError(first.indexKey(), null);
            }
            for (PreparedExportDocument document : documents) {
                recordTrafficSuccess(document);
            }
        } else {
            for (PreparedExportDocument document : documents) {
                recordFailure(document, "File export write produced no bytes.");
            }
        }
    }

    /**
     * Disables file export for the current root for the remainder of the run.
     *
     * <p>Safe to call from any thread. Updates runtime destination state and posts the supplied
     * reason to the Log and control status; blank reasons or roots are ignored.</p>
     *
     * @param reason operator-facing disable reason
     */
    public static void disableCurrentRoot(String reason) {
        String root = RuntimeConfig.fileExportRoot();
        if (root == null || root.isBlank() || reason == null || reason.isBlank()) {
            return;
        }
        RuntimeConfig.disableFileDestination();
        rootState(Path.of(root)).disableAll(reason.trim(), false);
    }

    /**
     * Clears cached sink instances and releases run-scoped directory locks.
     *
     * <p>Call only after producers have stopped. Closing a state releases its cross-process file
     * lock; close failures are logged and do not propagate.</p>
     */
    public static void resetForRuntime() {
        JSONL_SINKS.clear();
        BULK_SINKS.clear();
        for (RootState state : ROOT_STATES.values()) {
            state.close();
        }
        ROOT_STATES.clear();
    }

    /**
     * Validates all selected output artifacts without releasing run-scoped file locks.
     *
     * <p>Safe to call after producers have stopped. Records final baseline/expected/observed sizes
     * and integrity state; replacement or size drift disables the file destination and is
     * logged.</p>
     */
    public static void validateRunArtifacts() {
        for (RootState state : ROOT_STATES.values()) {
            state.validateArtifacts();
        }
    }

    /**
     * Returns whether the active run registered any selected output artifacts.
     *
     * <p>Safe to call from any thread and does not perform disk I/O.</p>
     *
     * @return {@code true} when at least one root tracks an initialized artifact
     */
    public static boolean hasTrackedArtifacts() {
        for (RootState state : ROOT_STATES.values()) {
            if (state.hasArtifacts()) {
                return true;
            }
        }
        return false;
    }

    /** Clears cached sink instances, primarily for tests and lifecycle resets. */
    public static void resetForTests() {
        resetForRuntime();
        FileExportStats.resetForTests();
    }

    /**
     * Creates export files for the selected sources and enabled file formats.
     *
     * <p>Performs synchronous disk I/O, claims the configured root for this process, and records
     * artifact identity and baseline size. Operational failures are returned in the result
     * list.</p>
     *
     * @param selectedSources source keys whose index files should be initialized
     * @return one result per selected format/index, or one directory/path failure result
     */
    public static List<FileInitResult> createSelectedExportFiles(List<String> selectedSources) {
        return createSelectedExportFiles(selectedSources, () -> true);
    }

    /**
     * Creates export files while a caller-provided continuation signal permits work.
     *
     * <p>Performs synchronous disk I/O, claims the configured root for this process, and records
     * artifact identity and baseline size. Cancellation is checked between index initializations;
     * already-created results are retained. Operational failures are returned, not thrown.</p>
     *
     * @param selectedSources source keys whose index files should be initialized
     * @param shouldContinue continuation signal; {@code null} means continue
     * @return completed initialization results, which may be partial after cancellation
     */
    public static List<FileInitResult> createSelectedExportFiles(
            List<String> selectedSources,
            BooleanSupplier shouldContinue
    ) {
        Path rootPath;
        try {
            rootPath = FileUtil.requireAbsoluteDirectoryPath(RuntimeConfig.fileExportRoot());
        } catch (IOException e) {
            return List.of(new FileInitResult(
                    "files",
                    "(invalid path)",
                    null,
                    FileUtil.Status.FAILED,
                    e.getMessage()));
        }

        List<FileInitResult> results = new java.util.ArrayList<>();
        RootState state = rootState(rootPath);
        if (state.isGloballyDisabled() || !state.claimRun()) {
            String reason = state.isGloballyDisabled()
                    ? state.reason()
                    : "File export cannot start: another exporter is using "
                            + rootPath.toAbsolutePath().normalize() + ".";
            return List.of(new FileInitResult(
                    "files",
                    "(directory lock)",
                    rootPath,
                    FileUtil.Status.FAILED,
                    reason));
        }
        for (String shortName : IndexNaming.computeSelectedIndexKeys(selectedSources)) {
            if (shouldContinue != null && !shouldContinue.getAsBoolean()) {
                break;
            }
            String baseName = RuntimeConfig.indexNameForKey(shortName);
            String displayName = IndexNaming.displayNameForIndexKey(shortName);
            if (RuntimeConfig.isFileJsonlEnabled()) {
                String fileName = baseName + ".jsonl";
                Logger.logInfoPanelOnly("[Files] Creating file for " + displayName + " (.jsonl).");
                FileUtil.CreateResult created = FileUtil.ensureFiles(rootPath, List.of(fileName)).getFirst();
                Logger.logInfoPanelOnly("[Files] File result for " + displayName + " (.jsonl): " + created.status() + ".");
                boolean registered = state.registerArtifact(shortName, created);
                results.add(new FileInitResult(
                        shortName,
                        ".jsonl",
                        created.path(),
                        registered ? created.status() : FileUtil.Status.FAILED,
                        registered
                                ? created.error()
                                : created.error() != null ? created.error() : state.reason()));
            }
            if (RuntimeConfig.isFileBulkNdjsonEnabled()) {
                String fileName = baseName + ".ndjson";
                Logger.logInfoPanelOnly("[Files] Creating file for " + displayName + " (.ndjson).");
                FileUtil.CreateResult created = FileUtil.ensureFiles(rootPath, List.of(fileName)).getFirst();
                Logger.logInfoPanelOnly("[Files] File result for " + displayName + " (.ndjson): " + created.status() + ".");
                boolean registered = state.registerArtifact(shortName, created);
                results.add(new FileInitResult(
                        shortName,
                        ".ndjson",
                        created.path(),
                        registered ? created.status() : FileUtil.Status.FAILED,
                        registered
                                ? created.error()
                                : created.error() != null ? created.error() : state.reason()));
            }
        }
        return results;
    }

    private static FileSink jsonlSink(String root, String indexName, String indexKey) {
        Path rootPath = Path.of(root).toAbsolutePath().normalize();
        return JSONL_SINKS.computeIfAbsent(
                rootPath + "|" + indexName,
                key -> new JsonlFileSink(rootPath, indexName, indexKey));
    }

    private static FileSink bulkSink(String root, String indexName, String indexKey) {
        Path rootPath = Path.of(root).toAbsolutePath().normalize();
        return BULK_SINKS.computeIfAbsent(
                rootPath + "|" + indexName,
                key -> new BulkNdjsonFileSink(rootPath, indexName, indexKey));
    }

    static boolean verifyArtifactBeforeAppend(
            Path rootPath, String indexName, String indexKey, String extension) {
        return rootState(rootPath).verifyBeforeAppend(
                rootPath.resolve(indexName + extension), indexKey);
    }

    static void recordArtifactAppend(
            Path rootPath, String indexName, String indexKey, String extension, long bytes) {
        rootState(rootPath).recordAppend(
                rootPath.resolve(indexName + extension), indexKey, extension, bytes);
    }

    private static RootState rootState(Path rootPath) {
        String key = rootPath.toAbsolutePath().normalize().toString();
        return ROOT_STATES.computeIfAbsent(key, ignored -> RootState.initialize(rootPath));
    }

    private static void recordFailure(PreparedExportDocument document, String message) {
        FileExportStats.recordFailure(document.indexKey(), 1);
        if (FileExportStats.getLastError(document.indexKey()) == null) {
            FileExportStats.recordLastError(document.indexKey(), message);
        }
        recordTrafficFailure(document);
    }

    /**
     * Describes one file-export artifact initialization attempt.
     *
     * @param shortName logical index key, or {@code files} for a root-level failure
     * @param format file extension, or a parenthesized root-level failure category
     * @param path initialized path; may be {@code null} when path validation fails
     * @param status creation/availability status
     * @param error failure detail; {@code null} when initialization succeeded
     */
    public record FileInitResult(
            String shortName,
            String format,
            Path path,
            FileUtil.Status status,
            String error
    ) { }

    private static String summarize(Exception exception) {
        String message = exception.getMessage();
        return message == null || message.isBlank()
                ? exception.getClass().getSimpleName()
                : message;
    }

    /**
     * Credits a successful file write for a traffic document against its route bucket.
     *
     * <p>No-op for non-traffic documents and for prepared entries without a resolvable body.
     * Traffic-only side effect: increments {@link FileExportStats} per-route success counters
     * via {@link TrafficRouteBucket#recordFileSuccess(TrafficRouteBucket.Route, long)}.</p>
     *
     * @param document prepared document whose route should receive the credit
     */
    private static void recordTrafficSuccess(PreparedExportDocument document) {
        if (!"traffic".equals(document.indexKey()) || document.document() == null) {
            return;
        }
        TrafficRouteBucket.recordFileSuccess(TrafficRouteBucket.fromDocument(document.document()), 1);
    }

    /**
     * Attributes a failed file write for a traffic document against its route bucket.
     *
     * <p>No-op for non-traffic documents and for prepared entries without a resolvable body.
     * Traffic-only side effect: increments {@link FileExportStats} per-route failure counters
     * via {@link TrafficRouteBucket#recordFileFailure(TrafficRouteBucket.Route, long)}.</p>
     *
     * @param document prepared document whose route should receive the failure
     */
    private static void recordTrafficFailure(PreparedExportDocument document) {
        if (!"traffic".equals(document.indexKey()) || document.document() == null) {
            return;
        }
        TrafficRouteBucket.recordFileFailure(TrafficRouteBucket.fromDocument(document.document()), 1);
    }

    /**
     * Owns one normalized file root and its run-scoped integrity invariants.
     *
     * <p>Instance synchronization serializes artifact registration, expected-size changes,
     * validation, disable transitions, and lock release. The cross-process directory lock grants
     * one exporter ownership of the root. Each append must preserve the registered file identity
     * and advance observed size by exactly the recorded byte count; violations fail closed.</p>
     */
    private static final class RootState {
        private static final long INTEGRITY_RECHECK_NANOS =
                java.util.concurrent.TimeUnit.SECONDS.toNanos(5L);

        private final Path rootPath;
        private final Path lockPath;
        private final Map<Path, ArtifactState> artifacts = new LinkedHashMap<>();
        private long totalBytes;
        private volatile boolean globallyDisabled;
        private volatile String globalDisableReason;
        private boolean runClaimed;
        private FileChannel lockChannel;
        private FileLock directoryLock;
        private long lastIntegrityCheckNanos;

        private RootState(Path rootPath) {
            this.rootPath = rootPath.toAbsolutePath().normalize();
            String lockName = UUID.nameUUIDFromBytes(
                    this.rootPath.toString().getBytes(StandardCharsets.UTF_8)) + ".lock";
            this.lockPath = Path.of(
                    System.getProperty("java.io.tmpdir"),
                    "burp-exporter-directory-locks",
                    lockName);
        }

        static RootState initialize(Path rootPath) {
            RootState state = new RootState(rootPath);
            state.acquireDirectoryLock();
            state.scanExistingFiles();
            return state;
        }

        boolean isGloballyDisabled() {
            return globallyDisabled;
        }

        String reason() {
            return globalDisableReason;
        }

        synchronized boolean hasArtifacts() {
            return !artifacts.isEmpty();
        }

        synchronized boolean claimRun() {
            if (runClaimed) {
                return false;
            }
            runClaimed = true;
            return true;
        }

        synchronized boolean registerArtifact(
                String indexKey, FileUtil.CreateResult created) {
            if (created == null
                    || created.status() == FileUtil.Status.FAILED
                    || created.path() == null) {
                return created != null && created.status() != FileUtil.Status.FAILED;
            }
            Path path = created.path().toAbsolutePath().normalize();
            try {
                ArtifactSnapshot snapshot = snapshot(path);
                ArtifactState artifact =
                        new ArtifactState(indexKey, path, snapshot.identity(), snapshot.size());
                artifacts.put(path, artifact);
                FileExportStats.recordArtifactRegistration(indexKey, snapshot.size());
                String mode = created.status() == FileUtil.Status.CREATED ? "created" : "appending";
                Logger.logInfoPanelOnly("[Files] "
                        + path.getFileName() + " baseline=" + snapshot.size()
                        + " bytes mode=" + mode + ".");
                return true;
            } catch (IOException e) {
                disableForIntegrity(
                        indexKey,
                        "File export integrity initialization failed for "
                                + path.getFileName() + ": " + summarize(e));
                return false;
            }
        }

        synchronized boolean verifyBeforeAppend(Path path, String indexKey) {
            if (globallyDisabled) {
                return false;
            }
            Path normalized = path.toAbsolutePath().normalize();
            ArtifactState artifact = artifacts.get(normalized);
            if (artifact == null) {
                try {
                    if (!Files.exists(normalized)) {
                        Files.createFile(normalized);
                    }
                    ArtifactSnapshot snapshot = snapshot(normalized);
                    artifact = new ArtifactState(
                            indexKey, normalized, snapshot.identity(), snapshot.size());
                    artifacts.put(normalized, artifact);
                    FileExportStats.recordArtifactRegistration(indexKey, snapshot.size());
                } catch (IOException e) {
                    disableForIntegrity(
                            indexKey,
                            "File export integrity initialization failed for "
                                    + normalized.getFileName() + ": " + summarize(e));
                    return false;
                }
            }
            return verifyArtifact(artifact);
        }

        synchronized void recordAppend(
                Path path, String indexKey, String extension, long bytes) {
            if (bytes <= 0L) {
                return;
            }
            Path normalized = path.toAbsolutePath().normalize();
            ArtifactState artifact = artifacts.get(normalized);
            if (artifact == null) {
                disableForIntegrity(
                        indexKey,
                        "File export integrity state is missing for "
                                + normalized.getFileName() + " (" + extension + ").");
                return;
            }
            artifact.expectedSize += bytes;
            verifyArtifact(artifact);
        }

        synchronized void validateArtifacts() {
            Map<String, CompletionAggregate> aggregates = new LinkedHashMap<>();
            for (ArtifactState artifact : artifacts.values()) {
                boolean valid = verifyArtifact(artifact);
                long finalSize = observedSize(artifact.path);
                CompletionAggregate aggregate = aggregates.computeIfAbsent(
                        artifact.indexKey, ignored -> new CompletionAggregate());
                aggregate.baselineBytes += artifact.baselineSize;
                aggregate.expectedFinalBytes += artifact.expectedSize;
                aggregate.finalBytes += Math.max(0L, finalSize);
                aggregate.valid &= valid;
                if (!valid && aggregate.error == null) {
                    aggregate.error = FileExportStats.getLastError(artifact.indexKey);
                }
            }
            for (Map.Entry<String, CompletionAggregate> entry : aggregates.entrySet()) {
                CompletionAggregate aggregate = entry.getValue();
                FileExportStats.recordArtifactCompletion(
                        entry.getKey(),
                        aggregate.baselineBytes,
                        aggregate.expectedFinalBytes,
                        aggregate.finalBytes,
                        aggregate.valid
                                ? FileExportStats.ArtifactIntegrity.OK
                                : FileExportStats.ArtifactIntegrity.FAILED,
                        aggregate.error);
            }
        }

        synchronized boolean allowWrite(Path rootPath, long plannedBytes) {
            if (plannedBytes <= 0L || globallyDisabled) {
                return false;
            }
            if (!verifyArtifactsIfDue()) {
                return false;
            }
            if (RuntimeConfig.isFileDiskUsagePercentEnabled()) {
                Integer usedPercent = diskUsedPercent(rootPath);
                int threshold = RuntimeConfig.fileDiskUsagePercent();
                if (usedPercent != null && usedPercent >= threshold) {
                    disableAll("File export stopped: destination volume is at " + usedPercent
                            + "% used (threshold " + threshold + "%).", true);
                    return false;
                }
            }
            if (RuntimeConfig.isFileTotalCapEnabled() && totalBytes + plannedBytes > RuntimeConfig.fileTotalCapBytes()) {
                disableAll("File export stopped: total cap " + humanBytes(RuntimeConfig.fileTotalCapBytes())
                        + " reached under " + rootPath + ".", true);
                return false;
            }
            return true;
        }

        private boolean verifyArtifactsIfDue() {
            if (artifacts.isEmpty()) {
                return true;
            }
            long now = System.nanoTime();
            if (lastIntegrityCheckNanos != 0L
                    && now - lastIntegrityCheckNanos < INTEGRITY_RECHECK_NANOS) {
                return true;
            }
            lastIntegrityCheckNanos = now;
            boolean valid = true;
            for (ArtifactState artifact : artifacts.values()) {
                valid &= verifyArtifact(artifact);
            }
            return valid;
        }

        synchronized void recordWrite(long writtenBytes) {
            if (writtenBytes <= 0L) {
                return;
            }
            totalBytes += writtenBytes;
        }

        synchronized void disableAll(String reason, boolean continueOpensearch) {
            String suffix = continueOpensearch && !RuntimeConfig.searchBaseUrl().isBlank()
                    ? " " + RuntimeConfig.searchDestinationDisplayName() + " export continues."
                    : "";
            String message = reason + suffix;
            if (globallyDisabled && Objects.equals(globalDisableReason, message)) {
                return;
            }
            globallyDisabled = true;
            globalDisableReason = message;
            Logger.logError(message);
            ControlStatusBridge.post(message);
        }

        synchronized void close() {
            boolean ownedLock = directoryLock != null && directoryLock.isValid();
            try {
                if (ownedLock) {
                    directoryLock.release();
                }
            } catch (IOException e) {
                Logger.logWarnPanelOnly("[Files] Directory lock release failed for "
                        + rootPath + ": " + summarize(e));
            } finally {
                directoryLock = null;
            }
            try {
                if (lockChannel != null) {
                    lockChannel.close();
                }
            } catch (IOException e) {
                Logger.logWarnPanelOnly("[Files] Directory lock channel close failed for "
                        + rootPath + ": " + summarize(e));
            } finally {
                lockChannel = null;
            }
        }

        private void acquireDirectoryLock() {
            try {
                Files.createDirectories(rootPath);
                Files.createDirectories(lockPath.getParent());
                lockChannel = FileChannel.open(
                        lockPath,
                        StandardOpenOption.CREATE,
                        StandardOpenOption.WRITE,
                        LinkOption.NOFOLLOW_LINKS);
                try {
                    directoryLock = lockChannel.tryLock();
                } catch (OverlappingFileLockException e) {
                    directoryLock = null;
                }
                if (directoryLock == null) {
                    close();
                    globallyDisabled = true;
                    globalDisableReason =
                            "File export cannot start: another exporter is using " + rootPath + ".";
                    return;
                }
                byte[] owner = ("pid=" + ProcessHandle.current().pid()
                        + " started=" + Instant.now() + System.lineSeparator())
                        .getBytes(StandardCharsets.UTF_8);
                lockChannel.truncate(0L);
                lockChannel.position(0L);
                lockChannel.write(ByteBuffer.wrap(owner));
                lockChannel.force(false);
            } catch (IOException | RuntimeException e) {
                close();
                globallyDisabled = true;
                globalDisableReason = "File export cannot lock " + rootPath + ": " + summarize(e);
            }
        }

        private boolean verifyArtifact(ArtifactState artifact) {
            try {
                ArtifactSnapshot current = snapshot(artifact.path);
                if (!artifact.identity.matches(current.identity())) {
                    disableForIntegrity(
                            artifact.indexKey,
                            "File export integrity lost: "
                                    + artifact.path.getFileName() + " was replaced.");
                    return false;
                }
                if (current.size() != artifact.expectedSize) {
                    disableForIntegrity(
                            artifact.indexKey,
                            "File export integrity lost: "
                                    + artifact.path.getFileName()
                                    + " expected " + artifact.expectedSize
                                    + " bytes but found " + current.size() + ".");
                    return false;
                }
                return true;
            } catch (IOException e) {
                disableForIntegrity(
                        artifact.indexKey,
                        "File export integrity lost for "
                                + artifact.path.getFileName() + ": " + summarize(e));
                return false;
            }
        }

        private void disableForIntegrity(String indexKey, String reason) {
            FileExportStats.recordArtifactIntegrityFailure(indexKey, reason);
            disableAll(reason, true);
        }

        private static ArtifactSnapshot snapshot(Path path) throws IOException {
            BasicFileAttributes attributes = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!attributes.isRegularFile()) {
                throw new IOException("not a regular file: " + path);
            }
            return new ArtifactSnapshot(
                    new ArtifactIdentity(attributes.fileKey(), attributes.creationTime()),
                    attributes.size());
        }

        private static long observedSize(Path path) {
            try {
                return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                        ? Files.size(path)
                        : 0L;
            } catch (IOException | RuntimeException e) {
                return 0L;
            }
        }

        private void scanExistingFiles() {
            if (!Files.isDirectory(rootPath)) {
                return;
            }
            try {
                java.util.Set<Path> candidates = new java.util.LinkedHashSet<>();
                for (String baseName : RuntimeConfig.allIndexNames().values()) {
                    candidates.add(rootPath.resolve(baseName + ".jsonl"));
                    candidates.add(rootPath.resolve(baseName + ".ndjson"));
                }
                for (Path path : candidates) {
                    if (Files.isRegularFile(path)) {
                        totalBytes += Files.size(path);
                    }
                }
            } catch (IOException e) {
                Logger.logError("[Files] Size scan failed for " + rootPath + ": " + e.getMessage());
            }
        }

        private static Integer diskUsedPercent(Path rootPath) {
            try {
                Path target = Files.exists(rootPath) ? rootPath : rootPath.toAbsolutePath().getParent();
                if (target == null) {
                    target = rootPath.toAbsolutePath();
                }
                FileStore store = Files.getFileStore(target);
                long total = store.getTotalSpace();
                long usable = store.getUsableSpace();
                if (total <= 0L) {
                    return null;
                }
                long used = Math.max(0L, total - usable);
                return (int) Math.min(100L, Math.round((used * 100.0d) / total));
            } catch (IOException | RuntimeException e) {
                Logger.logError("[Files] Disk-usage check failed for " + rootPath + ": " + e.getMessage());
                return null;
            }
        }

        private static String humanBytes(long bytes) {
            long safe = Math.max(0L, bytes);
            double value = safe;
            String unit = "B";
            if (safe >= 1024L * 1024L * 1024L) {
                value = safe / (1024.0d * 1024.0d * 1024.0d);
                unit = "GiB";
            } else if (safe >= 1024L * 1024L) {
                value = safe / (1024.0d * 1024.0d);
                unit = "MiB";
            } else if (safe >= 1024L) {
                value = safe / 1024.0d;
                unit = "KiB";
            }
            return String.format(java.util.Locale.ROOT, unit.equals("B") ? "%.0f %s" : "%.2f %s", value, unit);
        }

        private static final class ArtifactState {
            final String indexKey;
            final Path path;
            final ArtifactIdentity identity;
            final long baselineSize;
            long expectedSize;

            ArtifactState(
                    String indexKey,
                    Path path,
                    ArtifactIdentity identity,
                    long baselineSize) {
                this.indexKey = indexKey;
                this.path = path;
                this.identity = identity;
                this.baselineSize = baselineSize;
                this.expectedSize = baselineSize;
            }
        }

        private static final class CompletionAggregate {
            long baselineBytes;
            long expectedFinalBytes;
            long finalBytes;
            boolean valid = true;
            String error;
        }

        private record ArtifactSnapshot(ArtifactIdentity identity, long size) { }

        private record ArtifactIdentity(Object fileKey, FileTime creationTime) {
            boolean matches(ArtifactIdentity other) {
                if (other == null) {
                    return false;
                }
                if (fileKey != null && other.fileKey != null) {
                    return Objects.equals(fileKey, other.fileKey);
                }
                return Objects.equals(creationTime, other.creationTime);
            }
        }
    }
}
