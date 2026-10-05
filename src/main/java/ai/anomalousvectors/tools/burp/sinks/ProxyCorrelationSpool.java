package ai.anomalousvectors.tools.burp.sinks;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import ai.anomalousvectors.tools.burp.utils.DiskSpaceGuard;
import ai.anomalousvectors.tools.burp.utils.ExportAdmissionController;
import ai.anomalousvectors.tools.burp.utils.BurpRuntimeMetadata;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.ManagedDiskPaths;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.StringKeyedMaps;

/**
 * Run-scoped disk store for live Proxy documents still awaiting their exact Proxy History row.
 *
 * <p>Each token owns one JSON file. Atomic replacement is attempted, with replace-existing fallback
 * on filesystems that do not support atomic moves. Files remain until the bound document is
 * accepted by {@link TrafficExportQueue} or the current export run ends. Artifacts left by an
 * interrupted process are discarded during initialization and are never replayed. Thread-safe.</p>
 */
class ProxyCorrelationSpool {

    enum PersistResult {
        STORED,
        REJECTED_LIMIT,
        REJECTED_LOW_DISK,
        FAILED
    }

    record StoredEntry(
            String token,
            int messageId,
            Integer listenerPort,
            long generation,
            Long requestSentMs,
            long createdAtEpochMs,
            Map<String, Object> document,
            boolean bound,
            boolean cleanupComplete) { }

    record DiscardResult(long filesDeleted, long bytesDeleted, long failures) {
        boolean complete() {
            return failures == 0L;
        }
    }

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() { };
    private static final String SCHEMA_VERSION = "1";
    private static final String FILE_TOKEN_SEPARATOR = "--";
    private static final long DEFAULT_MAX_FILES = 100_000L;
    private static final int MAX_COMPLETION_GUARDS = 100_000;
    private static final long FAILURE_LOG_INTERVAL_MS = 30_000L;

    private final Path directory;
    private final long maxBytes;
    private final long maxFiles;
    private final String projectId;
    private final ReentrantLock lock = new ReentrantLock();
    private final Map<String, Path> filesByToken = new LinkedHashMap<>();
    /*
     * Protected by lock. Completion guards prevent a concurrent active-run persistence operation
     * from recreating a document after destination handoff. The bounded set covers at most the
     * spool's configured file ceiling and discards guards in insertion order.
     */
    private final Set<String> completedTokens = new LinkedHashSet<>();
    private long totalBytes;
    private final AtomicLong permanentFailures = new AtomicLong();
    private final AtomicLong lastFailureLogMs = new AtomicLong(Long.MIN_VALUE);
    private final AtomicLong suppressedFailureLogs = new AtomicLong();

    ProxyCorrelationSpool() {
        this(
                ManagedDiskPaths.proxyCorrelationDirectory(),
                DiskSpaceGuard.PROXY_CORRELATION_MAX_BYTES,
                DEFAULT_MAX_FILES,
                resolveProjectId());
    }

    ProxyCorrelationSpool(Path directory, long maxBytes) {
        this(directory, maxBytes, DEFAULT_MAX_FILES, "test-project");
    }

    ProxyCorrelationSpool(Path directory, long maxBytes, long maxFiles, String projectId) {
        this.directory = directory;
        this.maxBytes = Math.max(1L, maxBytes);
        this.maxFiles = Math.max(1L, maxFiles);
        this.projectId = sanitizeProjectId(projectId);
        initialize();
    }

    PersistResult persist(StoredEntry entry) {
        if (entry == null
                || entry.token() == null
                || entry.token().isBlank()
                || entry.document() == null) {
            return PersistResult.FAILED;
        }
        byte[] payload;
        try {
            payload = JSON.writeValueAsBytes(envelope(entry));
        } catch (IOException e) {
            recordFailure("[ProxyCorrelation] Unable to serialize unresolved document: error="
                    + failureKind(e));
            return PersistResult.FAILED;
        }

        lock.lock();
        try {
            if (completedTokens.contains(entry.token())) {
                return PersistResult.STORED;
            }
            Files.createDirectories(directory);
            Path target = pathForToken(entry.token());
            long replacedBytes = Files.exists(target) ? Files.size(target) : 0L;
            boolean newFile = !Files.exists(target);
            if ((newFile && filesByToken.size() >= maxFiles)
                    || totalBytes - replacedBytes + payload.length > effectiveMaxBytesLocked()) {
                recordFailure("[ProxyCorrelation] Durable correlation spool reached its byte limit.");
                return PersistResult.REJECTED_LIMIT;
            }
            DiskSpaceGuard.ensureWritable(directory, payload.length, "Proxy correlation spool");
            Path temporary = target.resolveSibling(target.getFileName() + ".tmp");
            Files.write(
                    temporary,
                    payload,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE);
            moveAtomically(temporary, target);
            filesByToken.put(entry.token(), target);
            totalBytes = totalBytes - replacedBytes + payload.length;
            return PersistResult.STORED;
        } catch (DiskSpaceGuard.LowDiskSpaceException e) {
            recordFailure("[ProxyCorrelation] Durable correlation spool rejected a low-disk write.");
            return PersistResult.REJECTED_LOW_DISK;
        } catch (IOException e) {
            recordFailure("[ProxyCorrelation] Unable to persist unresolved document: error="
                    + failureKind(e));
            return PersistResult.FAILED;
        } finally {
            lock.unlock();
        }
    }

    StoredEntry load(String token) {
        lock.lock();
        try {
            Path path = filesByToken.get(token);
            if (path == null) {
                return null;
            }
            Map<String, Object> envelope = JSON.readValue(Files.readAllBytes(path), MAP_TYPE);
            StoredEntry entry = parseEnvelope(envelope);
            if (!token.equals(entry.token())) {
                throw new IOException("token does not match spool entry");
            }
            return entry;
        } catch (IOException | RuntimeException e) {
            recordFailure("[ProxyCorrelation] Unable to load durable spool entry: error="
                    + failureKind(e));
            return null;
        } finally {
            lock.unlock();
        }
    }

    boolean complete(String token) {
        return complete(token, true);
    }

    boolean complete(String token, boolean guardIfAbsent) {
        if (token == null || token.isBlank()) {
            return false;
        }
        lock.lock();
        try {
            Path path = filesByToken.remove(token);
            if (path == null && guardIfAbsent) {
                rememberCompletedTokenLocked(token);
            }
            if (path == null) {
                return true;
            }
            long bytes = Files.exists(path) ? Files.size(path) : 0L;
            Path delivered = path.resolveSibling(path.getFileName() + ".delivered");
            boolean originalMoved = false;
            try {
                moveAtomically(path, delivered);
                originalMoved = true;
            } catch (IOException moveFailure) {
                try {
                    Files.write(
                            delivered,
                            new byte[] {1},
                            StandardOpenOption.CREATE,
                            StandardOpenOption.TRUNCATE_EXISTING,
                            StandardOpenOption.WRITE);
                } catch (IOException tombstoneFailure) {
                    tombstoneFailure.addSuppressed(moveFailure);
                    throw tombstoneFailure;
                }
            }
            rememberCompletedTokenLocked(token);
            totalBytes = Math.max(0L, totalBytes - bytes);
            if (originalMoved) {
                try {
                    Files.deleteIfExists(delivered);
                } catch (IOException e) {
                    Logger.logWarnPanelOnly("[ProxyCorrelation] Delivered spool tombstone will be "
                            + "removed on the next initialization: error=" + failureKind(e));
                }
            }
            return true;
        } catch (IOException e) {
            filesByToken.put(token, pathForToken(token));
            recordFailure("[ProxyCorrelation] Unable to retire resolved spool entry: error="
                    + failureKind(e));
            return false;
        } finally {
            lock.unlock();
        }
    }

    int count() {
        lock.lock();
        try {
            return filesByToken.size();
        } finally {
            lock.unlock();
        }
    }

    long bytes() {
        lock.lock();
        try {
            return totalBytes;
        } finally {
            lock.unlock();
        }
    }

    long permanentFailures() {
        return permanentFailures.get();
    }

    private long effectiveMaxBytesLocked() {
        return Math.max(
                1L,
                Math.min(maxBytes, ExportAdmissionController.spillBudgetBytes(directory)));
    }

    private void rememberCompletedTokenLocked(String token) {
        completedTokens.add(token);
        while (completedTokens.size() > MAX_COMPLETION_GUARDS) {
            String oldest = completedTokens.iterator().next();
            completedTokens.remove(oldest);
        }
    }

    DiscardResult discardAll() {
        lock.lock();
        try {
            DiscardResult result = discardOwnedArtifactsLocked();
            filesByToken.clear();
            completedTokens.clear();
            totalBytes = 0L;
            return result;
        } finally {
            lock.unlock();
        }
    }

    void clearForTests() {
        discardAll();
        lock.lock();
        try {
            permanentFailures.set(0L);
            lastFailureLogMs.set(Long.MIN_VALUE);
            suppressedFailureLogs.set(0L);
        } finally {
            lock.unlock();
        }
    }

    private void initialize() {
        lock.lock();
        try {
            if (!Files.isDirectory(directory)) {
                return;
            }
            DiscardResult discarded = discardOwnedArtifactsLocked();
            if (discarded.filesDeleted() > 0L) {
                Logger.logInfoPanelOnly("[ProxyCorrelation] Discarded "
                        + discarded.filesDeleted() + " abandoned spool artifacts ("
                        + discarded.bytesDeleted() + " bytes)." );
            }
            if (!discarded.complete()) {
                recordFailure("[ProxyCorrelation] Unable to discard all abandoned spool artifacts: "
                        + "failures=" + discarded.failures());
            }
        } finally {
            lock.unlock();
        }
    }

    private DiscardResult discardOwnedArtifactsLocked() {
        long filesDeleted = 0L;
        long bytesDeleted = 0L;
        long failures = 0L;
        if (!Files.isDirectory(directory)) {
            return new DiscardResult(0L, 0L, 0L);
        }
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory)) {
            for (Path path : stream) {
                if (!isOwnedArtifact(path)) {
                    continue;
                }
                try {
                    long bytes = Files.size(path);
                    if (Files.deleteIfExists(path)) {
                        filesDeleted++;
                        bytesDeleted += bytes;
                    }
                } catch (IOException e) {
                    failures++;
                }
            }
        } catch (IOException e) {
            failures++;
        }
        return new DiscardResult(filesDeleted, bytesDeleted, failures);
    }

    private boolean isOwnedArtifact(Path path) {
        String name = path.getFileName().toString();
        if (!name.startsWith(projectId + FILE_TOKEN_SEPARATOR)) {
            return false;
        }
        return name.endsWith(".json")
                || name.endsWith(".json.tmp")
                || name.endsWith(".json.delivered")
                || name.endsWith(".json.corrupt");
    }

    private Map<String, Object> envelope(StoredEntry entry) {
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema_version", SCHEMA_VERSION);
        envelope.put("project_id", projectId);
        envelope.put("token", entry.token());
        envelope.put("message_id", entry.messageId());
        envelope.put("listener_port", entry.listenerPort());
        envelope.put("generation", entry.generation());
        envelope.put("request_sent_ms", entry.requestSentMs());
        envelope.put("created_at_epoch_ms", entry.createdAtEpochMs());
        envelope.put("document", entry.document());
        envelope.put("bound", entry.bound());
        envelope.put("cleanup_complete", entry.cleanupComplete());
        return envelope;
    }

    private StoredEntry parseEnvelope(Map<String, Object> envelope) throws IOException {
        if (!SCHEMA_VERSION.equals(String.valueOf(envelope.get("schema_version")))) {
            throw new IOException("unsupported schema version");
        }
        if (!projectId.equals(String.valueOf(envelope.get("project_id")))) {
            throw new IOException("project id does not match spool owner");
        }
        String token = String.valueOf(envelope.get("token"));
        Number messageId = number(envelope.get("message_id"), "message_id");
        Number createdAt = number(envelope.get("created_at_epoch_ms"), "created_at_epoch_ms");
        Number generation = number(envelope.get("generation"), "generation");
        Integer listenerPort = envelope.get("listener_port") instanceof Number value
                ? value.intValue()
                : null;
        Long requestSent = envelope.get("request_sent_ms") instanceof Number value
                ? value.longValue()
                : null;
        Object documentValue = envelope.get("document");
        if (!(documentValue instanceof Map<?, ?> document)) {
            throw new IOException("document is missing");
        }
        return new StoredEntry(
                token,
                messageId.intValue(),
                listenerPort,
                generation.longValue(),
                requestSent,
                createdAt.longValue(),
                StringKeyedMaps.copy(document),
                Boolean.TRUE.equals(envelope.get("bound")),
                Boolean.TRUE.equals(envelope.get("cleanup_complete")));
    }

    private static Number number(Object value, String name) throws IOException {
        if (value instanceof Number number) {
            return number;
        }
        throw new IOException(name + " is missing");
    }

    private Path pathForToken(String token) {
        if (!token.matches("[A-Za-z0-9-]{16,128}")) {
            throw new IllegalArgumentException("Invalid correlation token");
        }
        return directory.resolve(projectId + FILE_TOKEN_SEPARATOR + token + ".json");
    }

    private static String resolveProjectId() {
        try {
            var api = MontoyaApiProvider.get();
            if (api != null && api.project() != null) {
                String raw = api.project().id();
                if (raw != null && !raw.isBlank()) {
                    return sanitizeProjectId(raw);
                }
            }
        } catch (RuntimeException ignored) {
            // Runtime metadata remains available during normal unload transitions.
        }
        return BurpRuntimeMetadata.projectIdOrUnknown();
    }

    private static String sanitizeProjectId(String raw) {
        if (raw == null || raw.isBlank()) {
            return BurpRuntimeMetadata.UNKNOWN_PROJECT_ID;
        }
        StringBuilder result = new StringBuilder(raw.length());
        for (int index = 0; index < raw.length(); index++) {
            char value = raw.charAt(index);
            result.append(Character.isLetterOrDigit(value) || value == '-' || value == '_'
                    ? Character.toLowerCase(value)
                    : '-');
        }
        String normalized = result.toString().replaceAll("-{2,}", "-");
        normalized = normalized.replaceAll("^-+", "").replaceAll("-+$", "");
        return normalized.isBlank() ? BurpRuntimeMetadata.UNKNOWN_PROJECT_ID : normalized;
    }

    void moveAtomically(Path source, Path target) throws IOException {
        try {
            Files.move(
                    source,
                    target,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private void recordFailure(String message) {
        long failures = permanentFailures.incrementAndGet();
        long now = System.currentTimeMillis();
        long previous = lastFailureLogMs.get();
        if (previous == Long.MIN_VALUE
                || now - previous >= FAILURE_LOG_INTERVAL_MS) {
            if (lastFailureLogMs.compareAndSet(previous, now)) {
                long suppressed = suppressedFailureLogs.getAndSet(0L);
                Logger.logError(message + " failures=" + failures
                        + (suppressed > 0L ? ", suppressed=" + suppressed : "") + ".");
                return;
            }
        }
        suppressedFailureLogs.incrementAndGet();
    }

    private static String failureKind(Throwable failure) {
        return failure == null ? "unknown" : failure.getClass().getSimpleName();
    }
}
