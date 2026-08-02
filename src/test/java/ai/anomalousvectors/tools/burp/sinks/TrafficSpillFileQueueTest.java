package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Comparator;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.testutils.TestPathSupport;
import ai.anomalousvectors.tools.burp.utils.DiskSpaceGuard;

class TrafficSpillFileQueueTest {

    @Test
    void offerAndPoll_preservesFifoOrder() throws IOException {
        Path dir = TestPathSupport.createDirectory("traffic-spill-test");
        try {
            TrafficSpillFileQueue queue = new TrafficSpillFileQueue(dir, 10, 1024 * 1024);
            assertThat(queue.offer(Map.of("id", 1, "url", "https://a"))).isTrue();
            assertThat(queue.offer(Map.of("id", 2, "url", "https://b"))).isTrue();

            Map<String, Object> first = queue.poll();
            Map<String, Object> second = queue.poll();
            Map<String, Object> empty = queue.poll();

            assertThat(first).isNotNull();
            assertThat(first.get("id")).isEqualTo(1);
            assertThat(second).isNotNull();
            assertThat(second.get("id")).isEqualTo(2);
            assertThat(empty).isNull();
            assertThat(queue.size()).isEqualTo(0);
            assertThat(queue.bytes()).isEqualTo(0);
        } finally {
            deleteRecursively(dir);
        }
    }

    @Test
    void offer_rejectsWhenFileLimitReached() throws IOException {
        Path dir = TestPathSupport.createDirectory("traffic-spill-limit");
        try {
            TrafficSpillFileQueue queue = new TrafficSpillFileQueue(dir, 1, 1024 * 1024);
            assertThat(queue.offer(Map.of("id", 1, "url", "https://a"))).isTrue();
            assertThat(queue.offer(Map.of("id", 2, "url", "https://b"))).isFalse();
            assertThat(queue.size()).isEqualTo(1);
        } finally {
            deleteRecursively(dir);
        }
    }

    @Test
    void offer_rejectsWhenByteLimitReached() throws IOException {
        Path dir = TestPathSupport.createDirectory("traffic-spill-bytes");
        try {
            TrafficSpillFileQueue queue = new TrafficSpillFileQueue(dir, 100, 400);
            assertThat(queue.offer(Map.of("id", 1, "url", "https://a"))).isTrue();
            assertThat(queue.offer(Map.of("id", 2, "payload", "x".repeat(512)))).isFalse();
            assertThat(queue.size()).isEqualTo(1);
        } finally {
            deleteRecursively(dir);
        }
    }

    @Test
    void offer_usesProjectIdPrefixForSpillFileNames() throws IOException {
        Path dir = TestPathSupport.createDirectory("traffic-spill-project-prefix");
        try {
            TrafficSpillFileQueue queue = new TrafficSpillFileQueue(
                    dir, 10, 1024 * 1024, "Burp Project:Alpha", 86_400_000L);
            assertThat(queue.offer(Map.of("id", 7, "url", "https://prefix.example"))).isTrue();

            try (Stream<Path> files = Files.list(dir)) {
                assertThat(files.map(path -> path.getFileName().toString()))
                        .anySatisfy(name -> assertThat(name).startsWith("burp-project-alpha-"));
            }
        } finally {
            deleteRecursively(dir);
        }
    }

    @Test
    void initializeFromDisk_recoversExistingSpillEnvelope() throws IOException {
        Path dir = TestPathSupport.createDirectory("traffic-spill-recover");
        try {
            String payload = "{\"meta\":{\"schema_version\":\"1\"},\"document\":{\"id\":99,\"url\":\"https://r\"}}";
            Files.writeString(
                    dir.resolve("test-project-00000000000000000001.json"),
                    payload,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING);

            TrafficSpillFileQueue queue = new TrafficSpillFileQueue(dir, 10, 1024 * 1024);
            assertThat(queue.recoveredCount()).isEqualTo(1);
            assertThat(queue.recoveredBytes()).isGreaterThan(0);
            assertThat(queue.oldestAgeMs()).isGreaterThanOrEqualTo(0);

            Map<String, Object> doc = queue.poll();
            assertThat(doc).isNotNull();
            assertThat(doc.get("id")).isEqualTo(99);
            assertThat(doc.get("url")).isEqualTo("https://r");
        } finally {
            deleteRecursively(dir);
        }
    }

    @Test
    void initializeFromDisk_legacyPreparedEnvelopeGeneratesStableOperationIdentity()
            throws IOException {
        Path dir = TestPathSupport.createDirectory("traffic-spill-legacy-prepared");
        try {
            String payload = """
                    {
                      "meta":{"schema_version":"1"},
                      "document":{"id":99,"url":"https://legacy.example"},
                      "prepared":{
                        "index_name":"tool-burp-traffic",
                        "index_key":"traffic",
                        "estimated_bulk_bytes":3,
                        "bulk_ndjson_bytes":"e30K"
                      }
                    }
                    """;
            Files.writeString(
                    dir.resolve("test-project-00000000000000000001.json"),
                    payload,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING);

            TrafficSpillFileQueue queue = new TrafficSpillFileQueue(
                    dir, 10, 1024 * 1024);
            TrafficQueueEntry recovered = queue.pollEntry();

            assertThat(recovered).isNotNull();
            assertThat(recovered.prepared().operationId()).isNotBlank();
            assertThat(new String(
                    recovered.prepared().bulkNdjsonBytes(),
                    StandardCharsets.UTF_8))
                    .startsWith("{\"index\":{\"_id\":\""
                            + recovered.prepared().operationId() + "\"}}");
        } finally {
            deleteRecursively(dir);
        }
    }

    @Test
    void offerDetailed_preservesPreparedEntryForRefill() throws IOException {
        Path dir = TestPathSupport.createDirectory("traffic-spill-prepared");
        try {
            TrafficSpillFileQueue queue = new TrafficSpillFileQueue(dir, 10, 1024 * 1024);
            TrafficQueueEntry entry = TrafficQueueEntry.from(Map.of("id", 77, "url", "https://prepared.example"));

            assertThat(queue.offerDetailed(entry)).isEqualTo(TrafficSpillFileQueue.OfferResult.QUEUED);

            TrafficQueueEntry recovered = queue.pollEntry();
            assertThat(recovered).isNotNull();
            assertThat(recovered.prepared().operationId()).isEqualTo(entry.prepared().operationId());
            assertThat(recovered.prepared().bulkNdjsonBytes()).isEqualTo(entry.prepared().bulkNdjsonBytes());
            assertThat(recovered.prepared().estimatedBulkBytes()).isEqualTo(entry.prepared().estimatedBulkBytes());
            assertThat(recovered.document()).isEqualTo(entry.document());
        } finally {
            deleteRecursively(dir);
        }
    }

    @Test
    void constructor_doesNotCreateSpillDirectory_untilFirstWrite() throws IOException {
        Path parent = TestPathSupport.createDirectory("traffic-spill-lazy-parent");
        Path dir = parent.resolve("spill-not-created-yet");
        try {
            assertThat(Files.exists(dir)).isFalse();

            TrafficSpillFileQueue queue = new TrafficSpillFileQueue(dir, 10, 1024 * 1024);

            assertThat(Files.exists(dir)).isFalse();
            assertThat(queue.offer(Map.of("id", 1, "url", "https://lazy.example"))).isTrue();
            assertThat(Files.isDirectory(dir)).isTrue();
        } finally {
            deleteRecursively(parent);
        }
    }

    @Test
    void offerDetailed_rejectsWhenLowDiskThresholdWouldBeBreached() throws IOException {
        Path dir = TestPathSupport.createDirectory("traffic-spill-low-disk");
        try {
            DiskSpaceGuard.resetForTests();
            DiskSpaceGuard.setUsableSpaceOverride(path -> DiskSpaceGuard.MIN_FREE_BYTES - 1);

            TrafficSpillFileQueue queue = new TrafficSpillFileQueue(dir, 10, 1024 * 1024);
            assertThat(queue.offerDetailed(Map.of("id", 1, "url", "https://a")))
                    .isEqualTo(TrafficSpillFileQueue.OfferResult.REJECTED_LOW_DISK);
            assertThat(queue.size()).isEqualTo(0);
        } finally {
            DiskSpaceGuard.resetForTests();
            deleteRecursively(dir);
        }
    }

    private static void deleteRecursively(Path root) throws IOException {
        if (root == null || !Files.exists(root)) {
            return;
        }
        Files.walk(root)
                .sorted(Comparator.reverseOrder())
                .forEach(path -> {
                    try {
                        Files.deleteIfExists(path);
                    } catch (IOException ignored) {
                        // Best-effort cleanup for temp test files.
                    }
                });
    }
}
