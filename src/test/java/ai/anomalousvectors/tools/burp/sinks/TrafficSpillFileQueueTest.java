package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Comparator;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;

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
    @ResourceLock("default-locale")
    void offer_usesAsciiSequenceDigitsUnderNonLatinLocale() throws IOException {
        Path dir = TestPathSupport.createDirectory("traffic-spill-locale");
        Locale original = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("ar-EG"));
            TrafficSpillFileQueue queue = new TrafficSpillFileQueue(
                    dir, 10, 1024 * 1024, "locale-project", 86_400_000L);

            assertThat(queue.offer(Map.of("id", 8, "url", "https://locale.example"))).isTrue();
            try (Stream<Path> files = Files.list(dir)) {
                assertThat(files.map(path -> path.getFileName().toString()))
                        .anySatisfy(name -> assertThat(name)
                                .isEqualTo("locale-project-00000000000000000001.json"));
            }
        } finally {
            Locale.setDefault(original);
            deleteRecursively(dir);
        }
    }

    @Test
    void initializeFromDisk_discardsExistingSpillEnvelope() throws IOException {
        Path dir = TestPathSupport.createDirectory("traffic-spill-discard");
        try {
            String payload = "{\"meta\":{\"schema_version\":\"1\"},\"document\":{\"id\":99,\"url\":\"https://r\"}}";
            Files.writeString(
                    dir.resolve("test-project-00000000000000000001.json"),
                    payload,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING);

            TrafficSpillFileQueue queue = new TrafficSpillFileQueue(dir, 10, 1024 * 1024);
            assertThat(queue.startupDiscardedCount()).isEqualTo(1);
            assertThat(queue.startupDiscardedBytes()).isGreaterThan(0);
            assertThat(queue.size()).isZero();
            assertThat(queue.poll()).isNull();
            assertThat(dir.resolve("test-project-00000000000000000001.json"))
                    .doesNotExist();
        } finally {
            deleteRecursively(dir);
        }
    }

    @Test
    void initializeFromDisk_discardsLegacyPreparedEnvelopeWithoutReplay()
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
            assertThat(queue.startupDiscardedCount()).isEqualTo(1L);
            assertThat(queue.pollEntry()).isNull();
            assertThat(dir.resolve("test-project-00000000000000000001.json"))
                    .doesNotExist();
        } finally {
            deleteRecursively(dir);
        }
    }

    @Test
    void initializeFromDisk_preservesOtherProjectArtifacts() throws IOException {
        Path dir = TestPathSupport.createDirectory("traffic-spill-project-isolation");
        try {
            Path owned = dir.resolve("project-a-00000000000000000001.json");
            Path ownedTemp = dir.resolve("project-a-00000000000000000002.json.tmp");
            Path foreign = dir.resolve("project-b-00000000000000000001.json");
            Files.writeString(owned, "{}");
            Files.writeString(ownedTemp, "partial");
            Files.writeString(foreign, "{}");

            TrafficSpillFileQueue queue = new TrafficSpillFileQueue(
                    dir, 10, 1024 * 1024, "Project A", 86_400_000L);

            assertThat(queue.startupDiscardedCount()).isEqualTo(1L);
            assertThat(owned).doesNotExist();
            assertThat(ownedTemp).doesNotExist();
            assertThat(foreign).exists();
        } finally {
            deleteRecursively(dir);
        }
    }

    @Test
    void offerDetailed_preservesPreparedEntryForRefill() throws IOException {
        Path dir = TestPathSupport.createDirectory("traffic-spill-prepared");
        try {
            TrafficSpillFileQueue queue = new TrafficSpillFileQueue(dir, 10, 1024 * 1024);
            TrafficQueueEntry entry = TrafficQueueEntry.from(
                    Map.of("id", 77, "url", "https://prepared.example"),
                    TrafficRouteBucket.proxyWebSocketHistory());

            assertThat(queue.offerDetailed(entry)).isEqualTo(TrafficSpillFileQueue.OfferResult.QUEUED);

            TrafficQueueEntry recovered = queue.pollEntry();
            assertThat(recovered).isNotNull();
            assertThat(recovered.prepared().operationId()).isEqualTo(entry.prepared().operationId());
            assertThat(recovered.prepared().bulkNdjsonBytes()).isEqualTo(entry.prepared().bulkNdjsonBytes());
            assertThat(recovered.prepared().estimatedBulkBytes()).isEqualTo(entry.prepared().estimatedBulkBytes());
            assertThat(recovered.prepared().trafficRouteKey())
                    .isEqualTo(TrafficRouteBucket.SOURCE_PROXY_WEBSOCKET_HISTORY);
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
