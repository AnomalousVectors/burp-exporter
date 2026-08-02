package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

import ai.anomalousvectors.tools.burp.utils.ExportAdmissionController;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

/**
 * Per-index bounded queues for failed OpenSearch index operations.
 *
 * <p>When a push fails, documents can be offered to the queue; a drain thread later retries them.
 * Capacity is byte-/headroom-aware ({@link ExportAdmissionController}): when full, earliest
 * documents are kept and new enqueue is rejected.</p>
 *
 * <p>Each queued document is wrapped with its enqueue timestamp so callers can observe the age of
 * the oldest retry-pending document per index and drain fairly by age.</p>
 *
 * <p>Thread-safe. Queue and byte-accounting snapshots may become stale immediately after return.
 * Enqueue operations preserve per-index FIFO order.</p>
 */
public final class RetryQueue {

    /**
     * A prepared document waiting to be retried.
     *
     * @param document immutable prepared document
     * @param enqueuedAtMs timestamp supplied by this queue's millisecond clock
     */
    record QueuedDoc(PreparedExportDocument document, long enqueuedAtMs) {}

    private final int maxSizePerIndex;
    private final ConcurrentHashMap<String, BlockingQueue<QueuedDoc>> queues = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicLong> bytesHeld = new ConcurrentHashMap<>();
    private final AtomicLong totalBytesHeld = new AtomicLong();
    private final Object byteAccountingLock = new Object();
    private final LongSupplier currentTimeMillis;

    /**
     * Creates a retry queue using the system epoch-millisecond clock.
     *
     * @param maxSizePerIndex document-count safety rail per index; values below one become one
     */
    public RetryQueue(int maxSizePerIndex) {
        this(maxSizePerIndex, System::currentTimeMillis);
    }

    /**
     * Creates a retry queue with an injectable millisecond clock.
     *
     * <p>The supplier should return epoch milliseconds for production-compatible age reporting.
     * Deterministic tests may use a synthetic clock in the same unit; timestamp accessors then
     * return those supplied values. A {@code null} supplier selects the system clock.</p>
     *
     * @param maxSizePerIndex document-count safety rail per index; values below one become one
     * @param currentTimeMillis millisecond clock, or {@code null} for the system clock
     */
    RetryQueue(int maxSizePerIndex, LongSupplier currentTimeMillis) {
        this.maxSizePerIndex = Math.max(1, maxSizePerIndex);
        this.currentTimeMillis = currentTimeMillis == null
                ? System::currentTimeMillis
                : currentTimeMillis;
    }

    /**
     * Offers a single document to the queue for the given index.
     *
     * @param indexName full index name (e.g. tool-burp-traffic)
     * @param document  document to retry later
     * @return true if accepted, false if queue full
     */
    public boolean offer(String indexName, PreparedExportDocument document) {
        if (document == null || !reserveBytes(indexName, document.estimatedBulkBytes())) {
            return false;
        }
        BlockingQueue<QueuedDoc> q = queueFor(indexName);
        if (q.offer(new QueuedDoc(document, currentTimeMillis.getAsLong()))) {
            return true;
        }
        releaseBytes(indexName, document);
        return false;
    }

    /**
     * Offers multiple documents to the queue for the given index.
     * Stops at first failure (queue full); earlier docs may have been added.
     *
     * @param indexName full index name
     * @param documents documents to retry later
     * @return number of documents actually accepted (0 to documents.size())
     */
    public int offerAll(String indexName, List<PreparedExportDocument> documents) {
        if (documents == null || documents.isEmpty()) {
            return 0;
        }
        BlockingQueue<QueuedDoc> q = queueFor(indexName);
        long now = currentTimeMillis.getAsLong();
        int added = 0;
        for (PreparedExportDocument doc : documents) {
            if (doc == null || !reserveBytes(indexName, doc.estimatedBulkBytes())) {
                return added;
            }
            if (!q.offer(new QueuedDoc(doc, now))) {
                releaseBytes(indexName, doc);
                return added;
            }
            added++;
        }
        return added;
    }

    /**
     * Removes up to maxSize documents from the queue for the given index.
     *
     * @param indexName full index name
     * @param maxSize   maximum number of documents to poll
     * @return list of documents (may be empty, never null)
     */
    public List<PreparedExportDocument> pollBatch(String indexName, int maxSize) {
        return pollBatch(indexName, maxSize, Long.MAX_VALUE);
    }

    /**
     * Removes documents until {@code maxSize} or {@code maxBytes} would be exceeded.
     *
     * <p>Always accepts at least one document when the queue is non-empty, even when that document
     * alone exceeds {@code maxBytes}, so oversized singles can still drain. Uses
     * {@link PreparedExportDocument#resolvedBulkBytes()} so retry bulks stay near the live byte
     * budget instead of packing dozens of large traffic docs into one HTTP body.</p>
     *
     * @param indexName full index name
     * @param maxSize maximum documents to dequeue; values {@code <= 0} yield an empty list
     * @param maxBytes maximum resolved NDJSON bytes for the batch; {@code <= 0} means docs-only
     * @return list of documents (may be empty, never null)
     */
    public List<PreparedExportDocument> pollBatch(String indexName, int maxSize, long maxBytes) {
        BlockingQueue<QueuedDoc> q = queues.get(indexName);
        if (q == null || maxSize <= 0) {
            return List.of();
        }
        List<PreparedExportDocument> batch = new ArrayList<>(Math.min(maxSize, Math.max(1, q.size())));
        long bytes = 0L;
        while (batch.size() < maxSize) {
            QueuedDoc head = q.peek();
            if (head == null) {
                break;
            }
            long docBytes = head.document().resolvedBulkBytes();
            if (!batch.isEmpty() && maxBytes > 0L && bytes + docBytes > maxBytes) {
                break;
            }
            QueuedDoc qd = q.poll();
            if (qd == null) {
                break;
            }
            batch.add(qd.document());
            releaseBytes(indexName, qd.document());
            bytes += docBytes;
        }
        return batch;
    }

    /**
     * Returns the current number of documents queued for the given index.
     *
     * @param indexName full index name
     * @return current non-negative queue depth
     */
    public int size(String indexName) {
        BlockingQueue<QueuedDoc> q = queues.get(indexName);
        return q == null ? 0 : q.size();
    }

    /**
     * Returns the enqueue timestamp (epoch ms) of the oldest queued document for the given index,
     * or {@code -1} when the queue is empty or absent.
     *
     * <p>Uses a non-blocking {@link BlockingQueue#peek()} so reads are cheap and safe from any
     * thread; the returned value is a snapshot and may change immediately after reading.</p>
     *
     * @param indexName full index name
     * @return timestamp supplied at enqueue, or {@code -1} when empty
     */
    public long oldestEnqueuedAtMs(String indexName) {
        BlockingQueue<QueuedDoc> q = queues.get(indexName);
        if (q == null) {
            return -1L;
        }
        QueuedDoc head = q.peek();
        return head == null ? -1L : head.enqueuedAtMs();
    }

    /**
     * Returns true if the queue for the given index is empty or absent.
     *
     * @param indexName full index name
     * @return {@code true} when no documents are currently queued for the index
     */
    public boolean isEmpty(String indexName) {
        return size(indexName) == 0;
    }

    /**
     * Returns the approximate total bytes of documents currently queued for the given index.
     *
     * <p>Maintained incrementally on offer and dequeue. Returns {@code 0} when the queue is empty
     * or absent.</p>
     *
     * @param indexName full index name
     * @return non-negative approximate retained bytes
     */
    public long bytesEstimate(String indexName) {
        AtomicLong held = bytesHeld.get(indexName);
        if (held == null) {
            return 0L;
        }
        return Math.max(0L, held.get());
    }

    /**
     * Returns approximate total bytes held across all indexes.
     *
     * @return non-negative approximate retained bytes
     */
    public long totalBytesEstimate() {
        return Math.max(0L, totalBytesHeld.get());
    }

    /**
     * Recomputes queued bytes by walking the queue. Package-private for unit tests that verify the
     * maintained counter matches a full iteration.
     *
     * @param indexName full index name
     * @return point-in-time estimated bytes from queued documents
     */
    long computeBytesEstimateByWalk(String indexName) {
        BlockingQueue<QueuedDoc> q = queues.get(indexName);
        if (q == null || q.isEmpty()) {
            return 0L;
        }
        long total = 0L;
        for (QueuedDoc qd : q) {
            total += qd.document().estimatedBulkBytes();
        }
        return total;
    }

    /**
     * Polls up to maxSize documents from the oldest non-empty per-index queue.
     *
     * @param maxSize maximum documents to dequeue
     * @return batch with index name and documents, or null when every queue is empty
     */
    public PolledBatch pollNextBatch(int maxSize) {
        return pollNextBatch(maxSize, Long.MAX_VALUE);
    }

    /**
     * Polls the oldest non-empty per-index queue with doc-count and byte caps.
     *
     * @param maxSize maximum documents to dequeue
     * @param maxBytes maximum resolved NDJSON bytes; {@code <= 0} means docs-only
     * @return batch with index name and documents, or null when every queue is empty
     */
    public PolledBatch pollNextBatch(int maxSize, long maxBytes) {
        String oldestIndex = oldestNonEmptyIndexName(false);
        if (oldestIndex == null) {
            return null;
        }
        List<PreparedExportDocument> batch = pollBatch(oldestIndex, maxSize, maxBytes);
        if (batch.isEmpty()) {
            return null;
        }
        return new PolledBatch(oldestIndex, batch);
    }

    /**
     * Returns full index names ordered by oldest enqueue time (oldest first).
     *
     * @param deprioritizeExporter when {@code true}, non-empty {@code exporter} queues are listed last
     * @return ordered list of non-empty index names (may be empty)
     */
    public List<String> nonEmptyIndexesByOldest(boolean deprioritizeExporter) {
        List<String> names = new ArrayList<>();
        for (Map.Entry<String, BlockingQueue<QueuedDoc>> entry : queues.entrySet()) {
            if (entry.getValue() != null && !entry.getValue().isEmpty()) {
                names.add(entry.getKey());
            }
        }
        names.sort(Comparator
                .comparingLong((String name) -> {
                    long age = oldestEnqueuedAtMs(name);
                    return age < 0L ? Long.MAX_VALUE : age;
                })
                .thenComparing(name -> name));
        if (deprioritizeExporter && names.size() > 1) {
            List<String> exporter = new ArrayList<>();
            List<String> others = new ArrayList<>();
            for (String name : names) {
                if (name != null && name.contains("exporter")) {
                    exporter.add(name);
                } else {
                    others.add(name);
                }
            }
            others.addAll(exporter);
            return others;
        }
        return names;
    }

    /**
     * One non-empty poll from {@link #pollNextBatch(int)}.
     *
     * <p>Construction rejects a blank index name or an empty document list.</p>
     *
     * @param indexName full index name
     * @param documents dequeued documents; never null or empty
     */
    public record PolledBatch(String indexName, List<PreparedExportDocument> documents) {
        public PolledBatch {
            if (indexName == null || indexName.isBlank()) {
                throw new IllegalArgumentException("indexName must not be blank");
            }
            if (documents == null || documents.isEmpty()) {
                throw new IllegalArgumentException("documents must not be empty");
            }
            documents = List.copyOf(documents);
        }
    }

    /**
     * Returns true if all known queues are empty.
     *
     * @return {@code true} when no known index currently has queued documents
     */
    public boolean allEmpty() {
        return queues.values().stream().allMatch(queue -> queue.isEmpty());
    }

    /**
     * Returns total number of queued documents across all indexes (for logging).
     *
     * @return current non-negative total queue depth
     */
    public int totalSize() {
        return queues.values().stream().mapToInt(queue -> queue.size()).sum();
    }

    /**
     * Returns a non-destructive snapshot of documents currently queued for {@code indexName}.
     *
     * <p>Used by Stats traffic-source rows to attribute live retry-queue depth without dequeuing.
     * The returned list is a point-in-time copy and may diverge immediately after the call.</p>
     *
     * @param indexName full index name
     * @return immutable list of documents (never {@code null}; empty when absent or empty)
     */
    List<PreparedExportDocument> snapshotDocuments(String indexName) {
        BlockingQueue<QueuedDoc> q = queues.get(indexName);
        if (q == null || q.isEmpty()) {
            return List.of();
        }
        List<PreparedExportDocument> out = new ArrayList<>(q.size());
        for (QueuedDoc qd : q) {
            if (qd != null && qd.document() != null) {
                out.add(qd.document());
            }
        }
        return List.copyOf(out);
    }

    /**
     * Drains every per-index queue and returns the documents keyed by full index name.
     *
     * <p>Used by Stop cleanup so discarded documents can be counted as permanent drops (including
     * per-traffic-source attribution) before the queues are emptied.</p>
     *
     * @return mutable map of drained documents (never {@code null}); empty when nothing was queued
     */
    Map<String, List<PreparedExportDocument>> drainAll() {
        Map<String, List<PreparedExportDocument>> out = new LinkedHashMap<>();
        for (Map.Entry<String, BlockingQueue<QueuedDoc>> entry : queues.entrySet()) {
            BlockingQueue<QueuedDoc> q = entry.getValue();
            if (q == null || q.isEmpty()) {
                continue;
            }
            List<QueuedDoc> wrapped = new ArrayList<>(q.size());
            q.drainTo(wrapped);
            if (wrapped.isEmpty()) {
                continue;
            }
            List<PreparedExportDocument> docs = new ArrayList<>(wrapped.size());
            for (QueuedDoc qd : wrapped) {
                if (qd != null && qd.document() != null) {
                    docs.add(qd.document());
                }
            }
            if (!docs.isEmpty()) {
                out.put(entry.getKey(), docs);
            }
        }
        for (Map.Entry<String, List<PreparedExportDocument>> entry : out.entrySet()) {
            for (PreparedExportDocument document : entry.getValue()) {
                releaseBytes(entry.getKey(), document);
            }
        }
        return out;
    }

    /**
     * Returns a snapshot of non-empty queue sizes keyed by full index name.
     *
     * <p>Used by Stop cleanup to count discarded documents as permanent drops before
     * {@link #clearAll()}.</p>
     *
     * @return mutable snapshot map (never {@code null}); empty when nothing is queued
     */
    Map<String, Integer> snapshotNonEmptySizes() {
        Map<String, Integer> out = new LinkedHashMap<>();
        for (Map.Entry<String, BlockingQueue<QueuedDoc>> entry : queues.entrySet()) {
            int size = entry.getValue().size();
            if (size > 0) {
                out.put(entry.getKey(), size);
            }
        }
        return out;
    }

    /**
     * Peeks the short index key of the head document for {@code indexName}.
     *
     * @param indexName full index name
     * @return index key, or blank when the queue is empty or the head has no key
     */
    String peekIndexKey(String indexName) {
        BlockingQueue<QueuedDoc> q = queues.get(indexName);
        if (q == null) {
            return "";
        }
        QueuedDoc head = q.peek();
        if (head == null || head.document() == null) {
            return "";
        }
        String key = head.document().indexKey();
        return key == null ? "" : key.trim();
    }

    /**
     * Clears all queued retry documents across all indexes.
     *
     * <p>Concurrent offers may add documents while clearing is in progress; the method guarantees
     * only that entries drained by this call are removed and their byte reservations released.</p>
     */
    public void clearAll() {
        for (Map.Entry<String, BlockingQueue<QueuedDoc>> entry : queues.entrySet()) {
            List<QueuedDoc> drained = new ArrayList<>();
            entry.getValue().drainTo(drained);
            for (QueuedDoc queued : drained) {
                if (queued != null) {
                    releaseBytes(entry.getKey(), queued.document());
                }
            }
        }
    }

    private String oldestNonEmptyIndexName(boolean deprioritizeExporter) {
        List<String> ordered = nonEmptyIndexesByOldest(deprioritizeExporter);
        return ordered.isEmpty() ? null : ordered.get(0);
    }

    private boolean reserveBytes(String indexName, long docBytes) {
        long need = Math.max(0L, docBytes);
        synchronized (byteAccountingLock) {
            long perIndexBudget = ExportAdmissionController.retryBudgetBytesPerIndex();
            long totalBudget = ExportAdmissionController.retryBudgetBytes();
            AtomicLong indexBytes = bytesFor(indexName);
            if (indexBytes.get() + need > perIndexBudget
                    || totalBytesHeld.get() + need > totalBudget) {
                return false;
            }
            indexBytes.addAndGet(need);
            totalBytesHeld.addAndGet(need);
            return true;
        }
    }

    private void releaseBytes(String indexName, PreparedExportDocument document) {
        if (document != null) {
            long bytes = Math.max(0L, document.estimatedBulkBytes());
            synchronized (byteAccountingLock) {
                bytesFor(indexName).addAndGet(-bytes);
                totalBytesHeld.addAndGet(-bytes);
            }
        }
    }

    private AtomicLong bytesFor(String indexName) {
        return bytesHeld.computeIfAbsent(indexName, ignored -> new AtomicLong());
    }

    private BlockingQueue<QueuedDoc> queueFor(String indexName) {
        return queues.computeIfAbsent(indexName, k -> new LinkedBlockingQueue<>(maxSizePerIndex));
    }
}
