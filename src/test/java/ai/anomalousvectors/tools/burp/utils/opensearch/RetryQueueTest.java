package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportAdmissionController;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link RetryQueue}: offer, pollBatch, bounded capacity, batch size.
 */
class RetryQueueTest {

    @AfterEach
    void tearDown() {
        ExportAdmissionController.resetForTests();
    }

    @Test
    void bytesEstimate_returnsZeroWhenEmptyOrAbsent() {
        RetryQueue queue = new RetryQueue(10);
        assertThat(queue.bytesEstimate("never-seen")).isZero();
        queue.offer("seen", prepared("seen", Map.of("k", "v")));
        queue.pollBatch("seen", 10);
        assertThat(queue.bytesEstimate("seen")).isZero();
    }

    @Test
    void bytesEstimate_tracksDocumentSize() {
        RetryQueue queue = new RetryQueue(10);
        String indexName = "size-index";
        queue.offer(indexName, prepared(indexName, Map.of("short", "x")));
        long oneDocBytes = queue.bytesEstimate(indexName);
        assertThat(oneDocBytes).isPositive();
        assertThat(oneDocBytes).isEqualTo(queue.computeBytesEstimateByWalk(indexName));
        queue.offer(indexName, prepared(indexName, Map.of("another", "y")));
        long twoDocsBytes = queue.bytesEstimate(indexName);
        assertThat(twoDocsBytes).isGreaterThan(oneDocBytes);
        assertThat(twoDocsBytes).isEqualTo(queue.computeBytesEstimateByWalk(indexName));
    }

    @Test
    void offer_pollBatch_roundTrip() {
        RetryQueue queue = new RetryQueue(100);
        String indexName = "test-index";
        Map<String, Object> doc = Map.of("id", "1");
        PreparedExportDocument prepared = prepared(indexName, doc);
        assertThat(queue.offer(indexName, prepared)).isTrue();
        assertThat(queue.size(indexName)).isEqualTo(1);
        List<PreparedExportDocument> batch = queue.pollBatch(indexName, 10);
        assertThat(batch).containsExactly(prepared);
        assertThat(queue.isEmpty(indexName)).isTrue();
    }

    @Test
    void offerAll_whenFull_dropsExcess() {
        RetryQueue queue = new RetryQueue(2);
        String indexName = "test-index";
        int added = queue.offerAll(indexName, List.of(
                prepared(indexName, Map.of("a", 1)),
                prepared(indexName, Map.of("b", 2)),
                prepared(indexName, Map.of("c", 3))));
        assertThat(added).isEqualTo(2);
        assertThat(queue.size(indexName)).isEqualTo(2);
    }

    @Test
    void offerAll_whenByteBudgetExhausted_keepsAcceptedPrefixAndExactAccounting() {
        RetryQueue queue = new RetryQueue(10);
        String indexName = "batch-byte-budget-index";
        PreparedExportDocument first = prepared(indexName, Map.of("payload", "x".repeat(64)));
        PreparedExportDocument second = prepared(indexName, Map.of("payload", "y".repeat(64)));
        ExportAdmissionController.setRetryBudgetOverrideForTests(first.estimatedBulkBytes() + 1L);

        int added = queue.offerAll(indexName, List.of(first, second));

        assertThat(added).isEqualTo(1);
        assertThat(queue.snapshotDocuments(indexName)).containsExactly(first);
        assertThat(queue.totalBytesEstimate()).isEqualTo(first.estimatedBulkBytes());
        assertThat(queue.computeBytesEstimateByWalk(indexName))
                .isEqualTo(first.estimatedBulkBytes());
    }

    @Test
    void offer_whenByteBudgetExhausted_rejectsNew() {
        ExportAdmissionController.setRetryBudgetOverrideForTests(1L);
        RetryQueue queue = new RetryQueue(100);
        String indexName = "byte-budget-index";
        PreparedExportDocument doc = prepared(indexName, Map.of("payload", "x".repeat(64)));
        assertThat(doc.estimatedBulkBytes()).isGreaterThan(1L);
        assertThat(queue.offer(indexName, doc)).isFalse();
        assertThat(queue.size(indexName)).isZero();
    }

    @Test
    void concurrentOffers_reserveByteBudgetAtomically() throws InterruptedException {
        RetryQueue queue = new RetryQueue(100);
        String indexName = "concurrent-byte-budget-index";
        PreparedExportDocument first = prepared(indexName, Map.of("payload", "x".repeat(512)));
        PreparedExportDocument second = prepared(indexName, Map.of("payload", "y".repeat(512)));
        long oneDocumentBytes = first.estimatedBulkBytes();
        ExportAdmissionController.setRetryBudgetOverrideForTests(oneDocumentBytes + 1L);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger accepted = new AtomicInteger();
        Thread firstProducer = new Thread(() -> offerAfterLatch(queue, indexName, first, start, accepted));
        Thread secondProducer = new Thread(() -> offerAfterLatch(queue, indexName, second, start, accepted));

        firstProducer.start();
        secondProducer.start();
        start.countDown();
        firstProducer.join();
        secondProducer.join();

        assertThat(accepted.get()).isEqualTo(1);
        assertThat(queue.totalBytesEstimate()).isEqualTo(oneDocumentBytes);
        assertThat(queue.computeBytesEstimateByWalk(indexName)).isEqualTo(oneDocumentBytes);
    }

    @Test
    void pollNextBatch_prefersOldestIndex() {
        AtomicLong now = new AtomicLong(2_000L);
        RetryQueue queue = new RetryQueue(100, now::get);
        PreparedExportDocument newer = prepared("tool-burp-alpha", Map.of("t", 1));
        PreparedExportDocument older = ExportDocumentIdentity.prepare(
                "tool-burp-zeta", "findings", Map.of("f", 1));
        queue.offer("tool-burp-zeta", older);
        now.set(3_000L);
        queue.offer("tool-burp-alpha", newer);

        RetryQueue.PolledBatch batch = queue.pollNextBatch(10);

        assertThat(batch).isNotNull();
        assertThat(batch.indexName()).isEqualTo("tool-burp-zeta");
        assertThat(batch.documents()).containsExactly(older);
    }

    @Test
    void pollBatch_respectsMaxSize() {
        RetryQueue queue = new RetryQueue(100);
        String indexName = "test-index";
        queue.offerAll(indexName, List.of(
                prepared(indexName, Map.of("a", 1)),
                prepared(indexName, Map.of("b", 2)),
                prepared(indexName, Map.of("c", 3))));
        List<PreparedExportDocument> batch = queue.pollBatch(indexName, 2);
        assertThat(batch).hasSize(2);
        assertThat(queue.size(indexName)).isEqualTo(1);
    }

    @Test
    void pollBatch_respectsMaxBytes() {
        RetryQueue queue = new RetryQueue(100);
        String indexName = "byte-cap-index";
        PreparedExportDocument first = prepared(indexName, Map.of("payload", "x".repeat(2_000)));
        PreparedExportDocument second = prepared(indexName, Map.of("payload", "y".repeat(2_000)));
        PreparedExportDocument third = prepared(indexName, Map.of("payload", "z".repeat(2_000)));
        queue.offerAll(indexName, List.of(first, second, third));
        long oneDoc = first.resolvedBulkBytes();
        assertThat(oneDoc).isPositive();

        List<PreparedExportDocument> batch = queue.pollBatch(indexName, 10, oneDoc + 1L);
        assertThat(batch).containsExactly(first);
        assertThat(queue.size(indexName)).isEqualTo(2);

        List<PreparedExportDocument> rest = queue.pollBatch(indexName, 10, oneDoc * 3L);
        assertThat(rest).containsExactly(second, third);
        assertThat(queue.isEmpty(indexName)).isTrue();
    }

    @Test
    void pollBatch_emptyIndex_returnsEmptyList() {
        RetryQueue queue = new RetryQueue(100);
        List<PreparedExportDocument> batch = queue.pollBatch("no-such-index", 10);
        assertThat(batch).isEmpty();
    }

    @Test
    void snapshotDocuments_doesNotDequeue() {
        RetryQueue queue = new RetryQueue(10);
        String indexName = "snap-index";
        PreparedExportDocument first = prepared(indexName, Map.of("a", 1));
        PreparedExportDocument second = prepared(indexName, Map.of("b", 2));
        queue.offerAll(indexName, List.of(first, second));

        assertThat(queue.snapshotDocuments(indexName)).containsExactly(first, second);
        assertThat(queue.size(indexName)).isEqualTo(2);
    }

    @Test
    void drainAll_returnsDocumentsAndEmptiesQueues() {
        RetryQueue queue = new RetryQueue(10);
        PreparedExportDocument trafficDoc = prepared("tool-burp-traffic", Map.of("t", 1));
        PreparedExportDocument sitemapDoc = ExportDocumentIdentity.prepare(
                "tool-burp-sitemap", "sitemap", Map.of("s", 1));
        queue.offer("tool-burp-traffic", trafficDoc);
        queue.offer("tool-burp-sitemap", sitemapDoc);

        Map<String, List<PreparedExportDocument>> drained = queue.drainAll();
        assertThat(drained.get("tool-burp-traffic")).containsExactly(trafficDoc);
        assertThat(drained.get("tool-burp-sitemap")).containsExactly(sitemapDoc);
        assertThat(queue.totalSize()).isZero();
        assertThat(queue.totalBytesEstimate()).isZero();
        assertThat(queue.bytesEstimate("tool-burp-traffic")).isZero();
        assertThat(queue.bytesEstimate("tool-burp-sitemap")).isZero();
    }

    @Test
    void oldestEnqueuedAtMs_returnsMinusOneWhenEmpty_andHeadTimestampWhenNonEmpty() throws InterruptedException {
        RetryQueue queue = new RetryQueue(100);
        String indexName = "test-index";
        assertThat(queue.oldestEnqueuedAtMs(indexName)).isEqualTo(-1L);

        long before = System.currentTimeMillis();
        queue.offer(indexName, prepared(indexName, Map.of("a", 1)));
        java.util.concurrent.TimeUnit.MILLISECONDS.sleep(2);
        queue.offer(indexName, prepared(indexName, Map.of("b", 2)));
        long after = System.currentTimeMillis();

        long head = queue.oldestEnqueuedAtMs(indexName);
        assertThat(head).isBetween(before, after);

        queue.pollBatch(indexName, 1);
        long newHead = queue.oldestEnqueuedAtMs(indexName);
        assertThat(newHead).isGreaterThanOrEqualTo(head);

        queue.pollBatch(indexName, 10);
        assertThat(queue.oldestEnqueuedAtMs(indexName)).isEqualTo(-1L);
    }

    private static PreparedExportDocument prepared(String indexName, Map<String, Object> document) {
        return ExportDocumentIdentity.prepare(indexName, "traffic", document);
    }

    private static void offerAfterLatch(
            RetryQueue queue,
            String indexName,
            PreparedExportDocument document,
            CountDownLatch start,
            AtomicInteger accepted) {
        try {
            start.await();
            if (queue.offer(indexName, document)) {
                accepted.incrementAndGet();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
