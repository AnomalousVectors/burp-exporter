package ai.anomalousvectors.tools.burp.sinks;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Predicate;

import tools.jackson.databind.JsonNode;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JacksonException;
import tools.jackson.core.ObjectReadContext;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.Version;
import ai.anomalousvectors.tools.burp.utils.ExportAdmissionController;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.ExportPressureLogThrottler;
import ai.anomalousvectors.tools.burp.utils.DiskSpaceGuard;
import ai.anomalousvectors.tools.burp.utils.ManagedDiskPaths;
import ai.anomalousvectors.tools.burp.utils.ManagedStorageQuota;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;
import ai.anomalousvectors.tools.burp.utils.export.SearchDocumentRevision;

/**
 * File-backed FIFO queue used when in-memory traffic queue is full.
 *
 * <p>Each document is written as one JSON file in a dedicated spill directory under the managed
 * exporter temp root. This queue is process-local and best-effort: files are cleaned as they are
 * drained; malformed spill files are skipped with an error log. Thread-safe.</p>
 */
final class TrafficSpillFileQueue {

    private static final JsonMapper JSON = JsonMapper.builderWithJackson2Defaults().build();
    private static final String SCHEMA_VERSION = "1";
    private final ExportPressureLogThrottler failures = new ExportPressureLogThrottler(
            "TrafficSpill", ExportPressureLogThrottler.DEFAULT_INTERVAL_MS,
            System::currentTimeMillis, Logger::logErrorPanelOnly);
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
        REJECTED_STALE,
        FAILED
    }

    record DiscardResult(long filesDeleted, long bytesDeleted, long failures) {
        boolean complete() {
            return failures == 0L;
        }
    }

    private static final String SPILL_SOURCE = "traffic_overflow";
    private static final long DEFAULT_MAX_AGE_MS = TimeUnit.DAYS.toMillis(3);
    private static final TypeReference<Map<String, Object>> DOC_TYPE = new TypeReference<>() { };

    // Release the committed reservation, never a length changed by another filesystem actor.
    private record SpillFile(Path path, long allocatedBytes) { }

    private final Path directory;
    private final String projectId;
    private final long maxFiles;
    private final long maxBytes;
    private final long maxAgeMs;
    private final ReentrantLock lock = new ReentrantLock();
    private final Deque<SpillFile> files = new ArrayDeque<>();
    private long totalBytes = 0;
    private long nextSequence = 1;
    private long startupDiscardedCount = 0;
    private long startupDiscardedBytes = 0;

    /**
     * Creates a queue with default limits under the managed exporter temp root.
     *
     * <p>The default byte cap uses the traffic-spill share of the common exporter-managed disk
     * ceiling. Construction is thread-safe but performs disk initialization immediately.</p>
     */
    TrafficSpillFileQueue() {
        this(
                ManagedDiskPaths.spillDirectory(),
                100_000L,
                DiskSpaceGuard.TRAFFIC_SPILL_MAX_BYTES,
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
     * <p>Visible for tests. Construction initializes on-disk state immediately and discards any
     * compatible spill files abandoned by an earlier process.</p>
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
        return offerDetailed(entry, () -> true);
    }

    OfferResult offerDetailed(TrafficQueueEntry entry, java.util.function.BooleanSupplier ownerActive) {
        if (entry == null || entry.prepared() == null) {
            return OfferResult.FAILED;
        }
        return offerPayload(buildPayload(buildSpillEnvelope(entry.prepared())), ownerActive);
    }

    private OfferResult offerPayload(byte[] payload) {
        return offerPayload(payload, () -> true);
    }

    private OfferResult offerPayload(byte[] payload, java.util.function.BooleanSupplier ownerActive) {
        if (payload == null || payload.length == 0) {
            return OfferResult.FAILED;
        }
        lock.lock();
        try {
            if (!ownerActive.getAsBoolean()) return OfferResult.REJECTED_STALE;
            pruneExpiredLocked(System.currentTimeMillis());
            long effectiveMax = effectiveMaxBytesLocked();
            if (files.size() >= maxFiles || (totalBytes + payload.length) > effectiveMax) {
                return OfferResult.REJECTED_LIMIT;
            }
            ensureDirectoryExists();
            DiskSpaceGuard.ensureWritable(directory, payload.length, "traffic spill");
            if (!ownerActive.getAsBoolean()) return OfferResult.REJECTED_STALE;
            String name = String.format(Locale.ROOT, "%s-%020d.json", projectId, nextSequence++);
            Path target = directory.resolve(name);
            Path temp = directory.resolve(name + ".tmp");
            try (ManagedStorageQuota.Reservation quota = ManagedStorageQuota.reserve(
                    directory,
                    ManagedStorageQuota.Category.TRAFFIC_SPILL,
                    projectId,
                    payload.length,
                    maxBytes)) {
                if (!quota.accepted()) {
                    return OfferResult.REJECTED_LIMIT;
                }
                if (!ownerActive.getAsBoolean()) return OfferResult.REJECTED_STALE;
                try {
                    Files.write(
                            temp,
                            payload,
                            StandardOpenOption.CREATE,
                            StandardOpenOption.TRUNCATE_EXISTING);
                    if (ManagedDiskPaths.isActiveInstancePath(temp)) {
                        ManagedDiskPaths.secureManagedFile(temp);
                    }
                    Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                    if (!ownerActive.getAsBoolean()) {
                        Files.deleteIfExists(target);
                        return OfferResult.REJECTED_STALE;
                    }
                    quota.commit();
                } catch (IOException e) {
                    try {
                        // A failed stale-owner cleanup may leave the committed-name artifact.
                        // Keep its quota charged even though it is never eligible for replay.
                        if (Files.exists(target)) quota.commit();
                        if (Files.exists(temp) && !Files.deleteIfExists(temp)) {
                            quota.commit();
                        }
                    } catch (IOException cleanupFailure) {
                        quota.commit();
                        e.addSuppressed(cleanupFailure);
                    }
                    throw e;
                }
            }
            files.addLast(new SpillFile(target, payload.length));
            totalBytes += payload.length;
            return OfferResult.QUEUED;
        } catch (DiskSpaceGuard.LowDiskSpaceException e) {
            return OfferResult.REJECTED_LOW_DISK;
        } catch (IOException e) {
            logFailure("write_failed", e);
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
        } catch (JacksonException e) {
            logFailure("serialize_failed", e);
            return null;
        }
    }

    // Keep repeated storage failures visible without emitting captured JSON or one log per item.
    private void logFailure(String reason, Exception failure) {
        failures.record(reason, 1, () -> "error=" + failure.getClass().getSimpleName()
                + "; affected traffic could not be retained in spill storage.");
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
                byte[] payload = readAndRemoveSpill(files.removeFirst());
                if (payload == null) {
                    continue;
                }
                try {
                    return extractDocument(payload);
                } catch (IOException | JacksonException e) {
                    recordReadDrop("spill_parse_failed", "parse_failed", e);
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
                byte[] payload = readAndRemoveSpill(files.removeFirst());
                if (payload == null) {
                    continue;
                }
                try {
                    return extractEntry(payload);
                } catch (IOException | JacksonException e) {
                    recordReadDrop("spill_parse_failed", "parse_failed", e);
                }
            }
            return null;
        } finally {
            lock.unlock();
        }
    }

    private byte[] readAndRemoveSpill(SpillFile file) {
        try {
            byte[] payload = Files.readAllBytes(file.path());
            Files.deleteIfExists(file.path());
            releaseAllocation(file);
            return payload;
        } catch (IOException e) {
            // A failed read is not proof of deletion, including a dangling symbolic link.
            if (Files.notExists(file.path(), LinkOption.NOFOLLOW_LINKS)) {
                releaseAllocation(file);
            }
            recordReadDrop("spill_read_failed", "read_delete_failed", e);
            return null;
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

    /** Returns accounted spill bytes, not a fresh measurement of filesystem lengths. */
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
            SpillFile oldest = files.peekFirst();
            if (oldest == null) {
                return 0;
            }
            long lastModified = Files.getLastModifiedTime(oldest.path()).toMillis();
            return Math.max(0, System.currentTimeMillis() - lastModified);
        } catch (IOException ignored) {
            return 0;
        } finally {
            lock.unlock();
        }
    }

    /** Returns abandoned spill file count discarded during initialization. */
    long startupDiscardedCount() {
        lock.lock();
        try {
            return startupDiscardedCount;
        } finally {
            lock.unlock();
        }
    }

    /** Returns abandoned spill byte count discarded during initialization. */
    long startupDiscardedBytes() {
        lock.lock();
        try {
            return startupDiscardedBytes;
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
    DiscardResult clear() {
        lock.lock();
        try {
            long filesDeleted = 0L;
            long bytesDeleted = 0L;
            long allocationReleased = 0L;
            long failures = 0L;
            for (SpillFile file : files) {
                Path path = file.path();
                try {
                    long bytes = Files.exists(path) ? Files.size(path) : 0L;
                    if (Files.deleteIfExists(path)) {
                        filesDeleted++;
                        bytesDeleted += bytes;
                    }
                    allocationReleased += file.allocatedBytes();
                } catch (IOException e) {
                    failures++;
                }
            }
            files.clear();
            totalBytes = 0;
            // Actual deleted lengths describe cleanup; original allocations own the quota.
            releaseQuota(allocationReleased);
            return new DiscardResult(filesDeleted, bytesDeleted, failures);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Removes spilled entries that match {@code predicate}.
     *
     * <p>This is used only for live config deselection, not the hot export path. Malformed or
     * unreadable spill files are removed because they cannot be routed safely.</p>
     */
    int removeIf(Predicate<TrafficQueueEntry> predicate) {
        if (predicate == null) {
            return 0;
        }
        lock.lock();
        try {
            int removed = 0;
            Iterator<SpillFile> iterator = files.iterator();
            while (iterator.hasNext()) {
                SpillFile file = iterator.next();
                TrafficQueueEntry entry = readEntryForPurge(file.path());
                if (entry == null || predicate.test(entry)) {
                    deleteSpillFile(file);
                    iterator.remove();
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
            startupDiscardedCount = 0;
            startupDiscardedBytes = 0;
            if (!Files.isDirectory(directory)) {
                return;
            }
            cleanupTempFilesLocked();
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory, "*.json")) {
                for (Path path : stream) {
                    if (isOwnedSpillFile(path)) {
                        long fileBytes = sizeOf(path);
                        long seq = parseSequence(path);
                        if (seq >= nextSequence) {
                            nextSequence = seq + 1;
                        }
                        try {
                            if (Files.deleteIfExists(path)) {
                                startupDiscardedCount++;
                                startupDiscardedBytes += fileBytes;
                            }
                        } catch (IOException e) {
                            Logger.logWarnPanelOnly(
                                    "[TrafficSpill] Unable to discard abandoned spill file: error="
                                            + e.getClass().getSimpleName() + ".");
                        }
                    }
                }
            }
            if (startupDiscardedCount > 0L) {
                releaseQuota(startupDiscardedBytes);
                Logger.logInfoPanelOnly("[TrafficSpill] Discarded " + startupDiscardedCount
                        + " abandoned spill documents (" + startupDiscardedBytes + " bytes) from "
                        + directoryPath() + ".");
            }
        } catch (IOException e) {
            Logger.logError("[TrafficSpill] Init failed: " + e.getMessage());
        } finally {
            lock.unlock();
        }
    }

    private void ensureDirectoryExists() throws IOException {
        if (ManagedDiskPaths.isManagedPath(directory)) {
            ManagedDiskPaths.ensureManagedDirectory(directory);
        } else {
            Files.createDirectories(directory);
        }
    }

    private TrafficQueueEntry readEntryForPurge(Path file) {
        try {
            return extractEntry(Files.readAllBytes(file));
        } catch (IOException | JacksonException e) {
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
        Path fileName = path.getFileName();
        if (fileName == null) {
            return -1L;
        }
        String file = fileName.toString();
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
        return ManagedDiskPaths.currentProjectId();
    }

    private static String sanitizeProjectId(String raw) {
        return ManagedDiskPaths.sanitizeProjectId(raw);
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
        if (prepared.searchRevision() != null) {
            preparedFields.put("search_document_id", prepared.searchRevision().documentId());
            preparedFields.put("search_version", prepared.searchRevision().version());
        }
        preparedFields.put("index_name", prepared.indexName());
        preparedFields.put("index_key", prepared.indexKey());
        preparedFields.put("estimated_bulk_bytes", prepared.estimatedBulkBytes());
        preparedFields.put("bulk_ndjson_bytes", prepared.bulkNdjsonBytes());
        if (prepared.trafficRouteKey() != null && !prepared.trafficRouteKey().isBlank()) {
            preparedFields.put("traffic_route_key", prepared.trafficRouteKey());
        }
        envelope.put("prepared", preparedFields);
        return envelope;
    }

    private TrafficQueueEntry extractEntry(byte[] payload) throws IOException {
        JsonNode root = readSpillObject(payload);
        JsonNode preparedNode = root.get("prepared");
        JsonNode docNode = root.get("document");
        if (preparedNode != null && preparedNode.isObject() && docNode != null && docNode.isObject()) {
            String indexName = textValue(preparedNode.get("index_name"));
            String indexKey = textValue(preparedNode.get("index_key"));
            String operationId = textValue(preparedNode.get("operation_id"));
            String trafficRouteKey = textValue(preparedNode.get("traffic_route_key"));
            JsonNode bytesNode = preparedNode.get("bulk_ndjson_bytes");
            if (indexName != null && indexKey != null && bytesNode != null) {
                byte[] bulkBytes = bytesNode.binaryValue();
                if (bulkBytes != null && bulkBytes.length > 0) {
                    Map<String, Object> document = JSON.convertValue(docNode, DOC_TYPE);
                    if (operationId == null) {
                        // Legacy prepared spills had action metadata without an id. Re-prepare once
                        // so all future retry/re-spill cycles carry one stable operation identity.
                        return TrafficQueueEntry.fromPrepared(
                                ExportDocumentIdentity.prepareWithTrafficRoute(
                                        indexName, indexKey, document, trafficRouteKey));
                    }
                    long estimatedBytes = preparedNode.path("estimated_bulk_bytes").asLong(bulkBytes.length);
                    var searchRevision = readSearchRevision(preparedNode);
                    return TrafficQueueEntry.fromPrepared(new PreparedExportDocument(
                            operationId,
                            indexName,
                            indexKey,
                            document,
                            estimatedBytes,
                            bulkBytes,
                            trafficRouteKey, searchRevision));
                }
            }
        }
        return TrafficQueueEntry.from(extractDocument(root));
    }

    private static String textValue(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        String value = node.asString();
        return value == null || value.isBlank() ? null : value;
    }

    private static SearchDocumentRevision readSearchRevision(
            JsonNode prepared) throws IOException {
        if (!prepared.has("search_document_id") && !prepared.has("search_version")) return null;
        String id = textValue(prepared.get("search_document_id"));
        JsonNode version = prepared.get("search_version");
        if (id == null || version == null || !version.isIntegralNumber() || !version.canConvertToLong()
                || version.asLong() <= 0L) {
            throw new IOException("Invalid streaming replacement metadata in spill");
        }
        return new SearchDocumentRevision(id, version.asLong());
    }

    private Map<String, Object> extractDocument(byte[] payload) throws IOException {
        return extractDocument(readSpillObject(payload));
    }

    private static JsonNode readSpillObject(byte[] payload) throws IOException {
        JsonFactory factory = JSON.tokenStreamFactory();
        if (payload.length > factory.streamReadConstraints().getMaxStringLength()) {
            // Admitted bodies and prepared NDJSON are Base64 strings that may exceed Jackson's
            // default. Bound this private reader by the already allocated spill payload instead;
            // no decoded JSON string can contain more characters than its enclosing UTF-8 bytes.
            factory = factory.rebuild().streamReadConstraints(factory.streamReadConstraints()
                    .rebuild().maxStringLength(payload.length).build()).build();
        }
        JsonNode root;
        try (JsonParser parser = factory.createParser(ObjectReadContext.empty(), payload)) {
            root = JSON.readTree(parser);
        }
        // Valid non-object JSON must use the same skip-and-continue path as broken JSON syntax.
        if (root == null || !root.isObject()) {
            throw new IOException("Traffic spill must contain a JSON object.");
        }
        return root;
    }

    private void recordReadDrop(String reason, String logReason, Exception failure) {
        ExportStats.recordTrafficSpillDrop(1);
        ExportStats.recordTrafficDropReason(reason, 1);
        logFailure(logReason, failure);
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
        Deque<SpillFile> survivors = new ArrayDeque<>(files.size());
        for (SpillFile file : files) {
            if (isExpired(file.path(), cutoffMs)) {
                deleteSpillFile(file);
                prunedCount++;
            } else {
                survivors.addLast(file);
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

    private void deleteSpillFile(SpillFile file) {
        try {
            Files.deleteIfExists(file.path());
            releaseAllocation(file);
        } catch (IOException ignored) {
            // Keep best-effort retention cleanup non-fatal.
        }
    }

    /** Caller holds the queue lock and has deleted the file or confirmed its absence. */
    private void releaseAllocation(SpillFile file) {
        totalBytes = Math.max(0, totalBytes - file.allocatedBytes());
        releaseQuota(file.allocatedBytes());
    }

    private void cleanupTempFilesLocked() {
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory, "*.tmp")) {
            for (Path tmp : stream) {
                Path fileName = tmp.getFileName();
                if (fileName == null) {
                    continue;
                }
                String name = fileName.toString();
                String targetName = name.substring(0, name.length() - ".tmp".length());
                if (isOwnedSpillFile(tmp.resolveSibling(targetName))) {
                    long bytes = sizeOf(tmp);
                    if (Files.deleteIfExists(tmp)) {
                        releaseQuota(bytes);
                    }
                }
            }
        } catch (IOException ignored) {
            // Ignore stale temporary files from interrupted writes.
        }
    }

    private boolean isOwnedSpillFile(Path path) {
        Path name = path.getFileName();
        if (name == null) {
            return false;
        }
        String fileName = name.toString();
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

    private void releaseQuota(long bytes) {
        try {
            ManagedStorageQuota.release(
                    directory,
                    ManagedStorageQuota.Category.TRAFFIC_SPILL,
                    projectId,
                    bytes);
        } catch (IOException e) {
            Logger.logWarnPanelOnly("[TrafficSpill] Unable to update project quota after deletion: error="
                    + e.getClass().getSimpleName() + ".");
        }
    }
}
