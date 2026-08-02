package ai.anomalousvectors.tools.burp.sinks;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayDeque;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Predicate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.Version;
import ai.anomalousvectors.tools.burp.utils.ExportAdmissionController;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.DiskSpaceGuard;
import ai.anomalousvectors.tools.burp.utils.BurpRuntimeMetadata;
import ai.anomalousvectors.tools.burp.utils.ManagedDiskPaths;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

/**
 * File-backed FIFO queue used when in-memory traffic queue is full.
 *
 * <p>Each document is written as one JSON file in a dedicated spill directory under the managed
 * exporter temp root. This queue is process-local and best-effort: files are cleaned as they are
 * drained; malformed spill files are skipped with an error log. Thread-safe.</p>
 */
final class TrafficSpillFileQueue {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String SCHEMA_VERSION = "1";
    /**
     * Outcome of attempting to spill one traffic document.
     *
     * <p>{@link #REJECTED_LIMIT} means queue-specific file-count or byte limits prevented the
     * spill. {@link #REJECTED_LOW_DISK} means the shared disk guard refused the write before the
     * destination volume would fall below the safety reserve.</p>
     */
    enum OfferResult {
        QUEUED,
        REJECTED_LIMIT,
        REJECTED_LOW_DISK,
        FAILED
    }

    private static final String SPILL_SOURCE = "traffic_overflow";
    private static final long DEFAULT_MAX_AGE_MS = TimeUnit.DAYS.toMillis(3);
    private static final TypeReference<Map<String, Object>> DOC_TYPE = new TypeReference<>() { };

    private final Path directory;
    private final String projectId;
    private final long maxFiles;
    private final long maxBytes;
    private final long maxAgeMs;
    private final ReentrantLock lock = new ReentrantLock();
    private final Deque<Path> files = new ArrayDeque<>();
    private long totalBytes = 0;
    private long nextSequence = 1;
    private long recoveredCount = 0;
    private long recoveredBytes = 0;

    /**
     * Creates a queue with default limits under the managed exporter temp root.
     *
     * <p>The default managed-disk byte cap aligns with {@link DiskSpaceGuard#MAX_MANAGED_BYTES}.
     * Construction is thread-safe but performs disk initialization immediately.</p>
     */
    TrafficSpillFileQueue() {
        this(
                ManagedDiskPaths.spillDirectory(),
                100_000L,
                DiskSpaceGuard.MAX_MANAGED_BYTES,
                resolveProjectId(),
                DEFAULT_MAX_AGE_MS);
    }

    /**
     * Creates a queue with explicit location and limits.
     *
     * <p>Visible for tests.</p>
     *
     * @param directory spill directory path
     * @param maxFiles maximum number of queued spill files
     * @param maxBytes maximum total queued spill bytes
     */
    TrafficSpillFileQueue(Path directory, long maxFiles, long maxBytes) {
        this(directory, maxFiles, maxBytes, "test-project", DEFAULT_MAX_AGE_MS);
    }

    /**
     * Creates a queue with explicit location, limits, and project identity.
     *
     * <p>Visible for tests. Construction initializes on-disk state immediately and recovers any
     * compatible spill files already present in the directory.</p>
     */
    TrafficSpillFileQueue(Path directory, long maxFiles, long maxBytes, String projectId, long maxAgeMs) {
        this.directory = directory;
        this.projectId = sanitizeProjectId(projectId);
        this.maxFiles = Math.max(1, maxFiles);
        this.maxBytes = Math.max(1, maxBytes);
        this.maxAgeMs = Math.max(1, maxAgeMs);
        initializeFromDisk();
    }

    /**
     * Writes one document to the spill directory.
     *
     * @param document traffic document to persist
     * @return {@code true} when queued, {@code false} when limits prevent spill
     */
    boolean offer(Map<String, Object> document) {
        return offerDetailed(document) == OfferResult.QUEUED;
    }

    /**
     * Writes one document to the spill directory and returns the precise outcome.
     *
     * <p>Caller may invoke from any thread. This method acquires the queue lock, prunes expired
     * spill files, checks queue-specific limits, and then enforces the shared low-disk rule before
     * writing the new spill file.</p>
     *
     * @param document traffic document to persist
     * @return detailed enqueue result
     */
    OfferResult offerDetailed(Map<String, Object> document) {
        if (document == null) {
            return OfferResult.FAILED;
        }
        return offerPayload(buildPayload(buildSpillEnvelope(document)));
    }

    OfferResult offerDetailed(TrafficQueueEntry entry) {
        if (entry == null || entry.prepared() == null) {
            return OfferResult.FAILED;
        }
        return offerPayload(buildPayload(buildSpillEnvelope(entry.prepared())));
    }

    private OfferResult offerPayload(byte[] payload) {
        if (payload == null || payload.length == 0) {
            return OfferResult.FAILED;
        }
        lock.lock();
        try {
            pruneExpiredLocked(System.currentTimeMillis());
            long effectiveMax = effectiveMaxBytesLocked();
            if (files.size() >= maxFiles || (totalBytes + payload.length) > effectiveMax) {
                return OfferResult.REJECTED_LIMIT;
            }
            ensureDirectoryExists();
            DiskSpaceGuard.ensureWritable(directory, payload.length, "traffic spill");
            String name = String.format("%s-%020d.json", projectId, nextSequence++);
            Path target = directory.resolve(name);
            Path temp = directory.resolve(name + ".tmp");
            Files.write(temp, payload, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            files.addLast(target);
            totalBytes += payload.length;
            return OfferResult.QUEUED;
        } catch (DiskSpaceGuard.LowDiskSpaceException e) {
            return OfferResult.REJECTED_LOW_DISK;
        } catch (IOException e) {
            Logger.logError("[TrafficSpill] Write failed: " + e.getMessage());
            return OfferResult.FAILED;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns whether spill can still accept approximately {@code payloadBytes} more data.
     *
     * <p>Does not write. Used for Overview Full status and live admission without preparing a
     * document that would be rejected.</p>
     */
    boolean canAcceptBytes(long payloadBytes) {
        lock.lock();
        try {
            pruneExpiredLocked(System.currentTimeMillis());
            long need = Math.max(1L, payloadBytes);
            if (files.size() >= maxFiles || (totalBytes + need) > effectiveMaxBytesLocked()) {
                return false;
            }
            long usable = DiskSpaceGuard.usableSpacePublic(directory);
            if (usable < 0L) {
                return true;
            }
            return usable - need >= DiskSpaceGuard.MIN_FREE_BYTES;
        } finally {
            lock.unlock();
        }
    }

    /** Returns the effective spill byte budget (headroom-relative, capped by ctor max). */
    long effectiveBudgetBytes() {
        lock.lock();
        try {
            return effectiveMaxBytesLocked();
        } finally {
            lock.unlock();
        }
    }

    private long effectiveMaxBytesLocked() {
        long headroomBudget = ExportAdmissionController.spillBudgetBytes(directory);
        return Math.max(1L, Math.min(maxBytes, headroomBudget));
    }

    private byte[] buildPayload(Map<String, Object> envelope) {
        try {
            return JSON.writeValueAsBytes(envelope);
        } catch (IOException e) {
            Logger.logError("[TrafficSpill] Serialize failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Reads and removes the oldest spilled document.
     *
     * @return oldest spilled document, or {@code null} when empty
     */
    Map<String, Object> poll() {
        lock.lock();
        try {
            while (!files.isEmpty()) {
                Path file = files.removeFirst();
                byte[] payload;
                try {
                    payload = Files.readAllBytes(file);
                    Files.deleteIfExists(file);
                } catch (IOException e) {
                    Logger.logError("[TrafficSpill] Read/delete failed: " + e.getMessage());
                    continue;
                }
                totalBytes = Math.max(0, totalBytes - payload.length);
                try {
                    return extractDocument(payload);
                } catch (IOException e) {
                    Logger.logError("[TrafficSpill] Parse failed: " + e.getMessage());
                }
            }
            return null;
        } finally {
            lock.unlock();
        }
    }

    TrafficQueueEntry pollEntry() {
        lock.lock();
        try {
            while (!files.isEmpty()) {
                Path file = files.removeFirst();
                byte[] payload;
                try {
                    payload = Files.readAllBytes(file);
                    Files.deleteIfExists(file);
                } catch (IOException e) {
                    Logger.logError("[TrafficSpill] Read/delete failed: " + e.getMessage());
                    continue;
                }
                totalBytes = Math.max(0, totalBytes - payload.length);
                try {
                    return extractEntry(payload);
                } catch (IOException e) {
                    Logger.logError("[TrafficSpill] Parse failed: " + e.getMessage());
                }
            }
            return null;
        } finally {
            lock.unlock();
        }
    }

    /** Returns the current number of spilled documents. */
    int size() {
        lock.lock();
        try {
            return files.size();
        } finally {
            lock.unlock();
        }
    }

    /** Returns the current number of bytes occupied by spilled documents. */
    long bytes() {
        lock.lock();
        try {
            return totalBytes;
        } finally {
            lock.unlock();
        }
    }

    /** Returns age in ms of the oldest spilled document, or 0 when empty/unavailable. */
    long oldestAgeMs() {
        lock.lock();
        try {
            Path oldest = files.peekFirst();
            if (oldest == null) {
                return 0;
            }
            long lastModified = Files.getLastModifiedTime(oldest).toMillis();
            return Math.max(0, System.currentTimeMillis() - lastModified);
        } catch (IOException ignored) {
            return 0;
        } finally {
            lock.unlock();
        }
    }

    /** Returns spill file count recovered from disk during initialization. */
    long recoveredCount() {
        lock.lock();
        try {
            return recoveredCount;
        } finally {
            lock.unlock();
        }
    }

    /** Returns recovered spill byte count from disk during initialization. */
    long recoveredBytes() {
        lock.lock();
        try {
            return recoveredBytes;
        } finally {
            lock.unlock();
        }
    }

    /** Returns absolute spill directory path for diagnostics. */
    String directoryPath() {
        return directory.toAbsolutePath().toString();
    }

    /**
     * Clears all currently queued spill files owned by this queue instance.
     */
    void clear() {
        lock.lock();
        try {
            for (Path path : files) {
                deleteSpillFile(path);
            }
            files.clear();
            totalBytes = 0;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Removes spilled documents that match {@code predicate}.
     *
     * <p>This is used only for live config deselection, not the hot export path. Malformed or
     * unreadable spill files are removed because they cannot be routed safely.</p>
     */
    int removeIf(Predicate<Map<String, Object>> predicate) {
        if (predicate == null) {
            return 0;
        }
        lock.lock();
        try {
            int removed = 0;
            Iterator<Path> iterator = files.iterator();
            while (iterator.hasNext()) {
                Path file = iterator.next();
                long fileBytes = sizeOf(file);
                Map<String, Object> document = readDocumentForPurge(file);
                if (document == null || predicate.test(document)) {
                    deleteSpillFile(file);
                    iterator.remove();
                    totalBytes = Math.max(0, totalBytes - fileBytes);
                    removed++;
                }
            }
            return removed;
        } finally {
            lock.unlock();
        }
    }

    private void initializeFromDisk() {
        lock.lock();
        try {
            files.clear();
            totalBytes = 0;
            nextSequence = 1;
            recoveredCount = 0;
            recoveredBytes = 0;
            if (!Files.isDirectory(directory)) {
                return;
            }
            cleanupTempFilesLocked();
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory, "*.json")) {
                for (Path path : stream) {
                    if (isOwnedSpillFile(path)) {
                        files.add(path);
                    }
                }
            }
            Deque<Path> ordered = files.stream()
                    .sorted(Comparator.comparing(path -> path.getFileName().toString()))
                    .collect(ArrayDeque::new, (deque, path) -> deque.addLast(path), (left, right) -> left.addAll(right));
            files.clear();
            files.addAll(ordered);
            pruneExpiredLocked(System.currentTimeMillis());
            for (Path path : files) {
                try {
                    long fileBytes = Files.size(path);
                    totalBytes += fileBytes;
                    long seq = parseSequence(path);
                    if (seq >= nextSequence) {
                        nextSequence = seq + 1;
                    }
                } catch (IOException ignored) {
                    // Skip files that cannot be stat-ed; poll() will skip on read failure too.
                }
            }
            recoveredCount = files.size();
            recoveredBytes = totalBytes;
        } catch (IOException e) {
            Logger.logError("[TrafficSpill] Init failed: " + e.getMessage());
        } finally {
            lock.unlock();
        }
    }

    private void ensureDirectoryExists() throws IOException {
        Files.createDirectories(directory);
    }

    private Map<String, Object> readDocumentForPurge(Path file) {
        try {
            return extractDocument(Files.readAllBytes(file));
        } catch (IOException e) {
            Logger.logError("[TrafficSpill] Purge read failed: " + e.getMessage());
            return null;
        }
    }

    private static long sizeOf(Path file) {
        try {
            return Files.size(file);
        } catch (IOException ignored) {
            return 0L;
        }
    }

    private static long parseSequence(Path path) {
        String file = path.getFileName().toString();
        int lastDash = file.lastIndexOf('-');
        if (lastDash > 0) {
            int dot = file.indexOf('.', lastDash + 1);
            if (dot > lastDash + 1) {
                try {
                    return Long.parseLong(file.substring(lastDash + 1, dot));
                } catch (NumberFormatException ignored) {
                    return -1;
                }
            }
        }
        int dot = file.indexOf('.');
        if (dot <= 0) {
            return -1;
        }
        try {
            return Long.parseLong(file.substring(0, dot));
        } catch (NumberFormatException ignored) {
            return -1;
        }
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
        } catch (Throwable ignored) {
            // Keep spill path resilient during Burp startup lifecycle transitions.
        }
        return BurpRuntimeMetadata.projectIdOrUnknown();
    }

    private static String sanitizeProjectId(String raw) {
        if (raw == null || raw.isBlank()) {
            return BurpRuntimeMetadata.UNKNOWN_PROJECT_ID;
        }
        StringBuilder sb = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '-' || c == '_') {
                sb.append(Character.toLowerCase(c));
            } else {
                sb.append('-');
            }
        }
        String normalized = sb.toString().replaceAll("-{2,}", "-");
        normalized = normalized.replaceAll("^-+", "").replaceAll("-+$", "");
        return normalized.isBlank() ? BurpRuntimeMetadata.UNKNOWN_PROJECT_ID : normalized;
    }

    private Map<String, Object> buildSpillEnvelope(Map<String, Object> document) {
        Map<String, Object> envelope = new HashMap<>();
        Map<String, Object> meta = new HashMap<>();
        long now = System.currentTimeMillis();
        meta.put("schema_version", SCHEMA_VERSION);
        meta.put("source", SPILL_SOURCE);
        meta.put("project_id", projectId);
        meta.put("enqueued_at_ms", now);
        try {
            meta.put("extension_version", Version.get());
        } catch (IllegalStateException ignored) {
            // Tests may not load from packaged JAR; keep spill metadata optional.
        }
        envelope.put("meta", meta);
        envelope.put("document", document);
        return envelope;
    }

    private Map<String, Object> buildSpillEnvelope(PreparedExportDocument prepared) {
        Map<String, Object> envelope = buildSpillEnvelope(prepared.document());
        Map<String, Object> preparedFields = new HashMap<>();
        preparedFields.put("operation_id", prepared.operationId());
        preparedFields.put("index_name", prepared.indexName());
        preparedFields.put("index_key", prepared.indexKey());
        preparedFields.put("estimated_bulk_bytes", prepared.estimatedBulkBytes());
        preparedFields.put("bulk_ndjson_bytes", prepared.bulkNdjsonBytes());
        envelope.put("prepared", preparedFields);
        return envelope;
    }

    private TrafficQueueEntry extractEntry(byte[] payload) throws IOException {
        JsonNode root = JSON.readTree(payload);
        JsonNode preparedNode = root.get("prepared");
        JsonNode docNode = root.get("document");
        if (preparedNode != null && preparedNode.isObject() && docNode != null && docNode.isObject()) {
            String indexName = textValue(preparedNode.get("index_name"));
            String indexKey = textValue(preparedNode.get("index_key"));
            String operationId = textValue(preparedNode.get("operation_id"));
            JsonNode bytesNode = preparedNode.get("bulk_ndjson_bytes");
            if (indexName != null && indexKey != null && bytesNode != null) {
                byte[] bulkBytes = bytesNode.binaryValue();
                if (bulkBytes != null && bulkBytes.length > 0) {
                    Map<String, Object> document = JSON.convertValue(docNode, DOC_TYPE);
                    if (operationId == null) {
                        // Legacy prepared spills had action metadata without an id. Re-prepare once
                        // so all future retry/re-spill cycles carry one stable operation identity.
                        return TrafficQueueEntry.fromPrepared(
                                ExportDocumentIdentity.prepare(indexName, indexKey, document));
                    }
                    long estimatedBytes = preparedNode.path("estimated_bulk_bytes").asLong(bulkBytes.length);
                    return TrafficQueueEntry.fromPrepared(new PreparedExportDocument(
                            operationId, indexName, indexKey, document, estimatedBytes, bulkBytes));
                }
            }
        }
        return TrafficQueueEntry.from(extractDocument(root));
    }

    private static String textValue(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        String value = node.asText();
        return value == null || value.isBlank() ? null : value;
    }

    private Map<String, Object> extractDocument(byte[] payload) throws IOException {
        return extractDocument(JSON.readTree(payload));
    }

    private Map<String, Object> extractDocument(JsonNode root) {
        JsonNode docNode = root.get("document");
        if (docNode != null && docNode.isObject()) {
            return JSON.convertValue(docNode, DOC_TYPE);
        }
        return JSON.convertValue(root, DOC_TYPE);
    }

    private void pruneExpiredLocked(long nowMs) {
        long cutoffMs = nowMs - maxAgeMs;
        if (cutoffMs <= 0) {
            return;
        }
        long prunedCount = 0;
        Deque<Path> survivors = new ArrayDeque<>(files.size());
        for (Path path : files) {
            if (isExpired(path, cutoffMs)) {
                deleteSpillFile(path);
                prunedCount++;
            } else {
                survivors.addLast(path);
            }
        }
        files.clear();
        files.addAll(survivors);
        if (prunedCount > 0) {
            ExportStats.recordTrafficSpillExpiredPruned(prunedCount);
            ExportStats.recordTrafficDropReason("spill_retention_prune", prunedCount);
        }
    }

    private static boolean isExpired(Path path, long cutoffMs) {
        try {
            return Files.getLastModifiedTime(path).toMillis() < cutoffMs;
        } catch (IOException ignored) {
            return false;
        }
    }

    private void deleteSpillFile(Path path) {
        try {
            long fileBytes = Files.exists(path) ? Files.size(path) : 0;
            if (Files.deleteIfExists(path)) {
                totalBytes = Math.max(0, totalBytes - fileBytes);
            }
        } catch (IOException ignored) {
            // Keep best-effort retention cleanup non-fatal.
        }
    }

    private void cleanupTempFilesLocked() {
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory, "*.tmp")) {
            for (Path tmp : stream) {
                Files.deleteIfExists(tmp);
            }
        } catch (IOException ignored) {
            // Ignore stale temporary files from interrupted writes.
        }
    }

    private boolean isOwnedSpillFile(Path path) {
        String fileName = path.getFileName().toString();
        if (fileName.startsWith(projectId + "-")) {
            return true;
        }
        // Compatibility: load pre-project-id spill files named only by sequence.
        int dot = fileName.indexOf('.');
        if (dot <= 0) {
            return false;
        }
        for (int i = 0; i < dot; i++) {
            if (!Character.isDigit(fileName.charAt(i))) {
                return false;
            }
        }
        return true;
    }
}
