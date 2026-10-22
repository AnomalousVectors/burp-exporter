package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ai.anomalousvectors.tools.burp.utils.ManagedDiskPaths;
import ai.anomalousvectors.tools.burp.utils.ManagedStorageQuota;
import ai.anomalousvectors.tools.burp.utils.export.ExportLineCodec;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

/** Exercises committed spill allocations independently of later filesystem lengths. */
class TrafficSpillAccountingTest {

    private static final long MAX_BYTES = 4096L;
    private static final long OTHER_ALLOCATION = 256L;
    private Path projectDirectory;
    private Path spillDirectory;
    private String projectId;

    private enum Mutation { UNCHANGED, SHRUNK, GROWN, MISSING, UNDELETABLE }

    private enum Removal { POLL, POLL_ENTRY, CLEAR, PURGE, EXPIRE }

    @BeforeEach
    void initializeIsolatedProject() throws IOException {
        projectId = "spill-accounting-" + UUID.randomUUID();
        projectDirectory = ManagedDiskPaths.spillDirectory().getParent().getParent().resolve(projectId);
        // The test JVM's managed instance must never resolve into an operator's temporary tree.
        assertThat(projectDirectory.toAbsolutePath().normalize()
                .startsWith(Path.of("build", "tmp").toAbsolutePath().normalize())).isTrue();
        spillDirectory = ManagedDiskPaths.ensureManagedDirectory(projectDirectory.resolve("spill"));
        try (var reservation = reserve(OTHER_ALLOCATION)) {
            assertThat(reservation.accepted()).isTrue();
            reservation.commit();
        }
    }

    @AfterEach
    void removeIsolatedProject() throws IOException {
        if (projectDirectory != null && Files.exists(projectDirectory)) {
            try (Stream<Path> paths = Files.walk(projectDirectory)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                    Files.delete(path);
                }
            }
            // Only this unique fixture owns the project, and its entire tree is now absent.
            ManagedStorageQuota.release(spillDirectory,
                    ManagedStorageQuota.Category.TRAFFIC_SPILL, projectId, MAX_BYTES);
        }
    }

    @ParameterizedTest(name = "{0}: {1}")
    @MethodSource("accountingCases")
    void removal_releasesOnlyItsOriginalAllocation(Removal removal, Mutation mutation)
            throws IOException {
        TrafficSpillFileQueue queue = new TrafficSpillFileQueue(
                spillDirectory, 10L, MAX_BYTES, projectId, 86_400_000L);
        TrafficQueueEntry first = preparedEntry("first");
        TrafficQueueEntry second = preparedEntry("second");
        assertThat(queue.offerDetailed(first)).isEqualTo(TrafficSpillFileQueue.OfferResult.QUEUED);
        assertThat(queue.offerDetailed(second)).isEqualTo(TrafficSpillFileQueue.OfferResult.QUEUED);
        Path firstFile = spillDirectory.resolve(projectId + "-00000000000000000001.json");
        Path secondFile = spillDirectory.resolve(projectId + "-00000000000000000002.json");
        long firstAllocation = Files.size(firstFile);
        long secondAllocation = Files.size(secondFile);
        mutate(firstFile, mutation);

        boolean retainedSecond = removeFirst(queue, removal, mutation, first, second, firstFile);

        long retainedAllocation = retainedSecond ? secondAllocation : 0L;
        assertThat(queue.size()).isEqualTo(retainedSecond ? 1 : 0);
        if (mutation != Mutation.UNDELETABLE) {
            assertThat(firstFile).doesNotExist();
            assertThat(queue.bytes()).isEqualTo(retainedAllocation);
        } else {
            assertThat(firstFile.resolve("held")).exists();
        }
        long heldAllocation = retainedAllocation
                + (mutation == Mutation.UNDELETABLE ? firstAllocation : 0L);
        assertRemainingQuota(MAX_BYTES - OTHER_ALLOCATION - heldAllocation);
        if (retainedSecond) {
            assertPreparedEntry(queue.pollEntry(), second);
            assertThat(secondFile).doesNotExist();
            assertRemainingQuota(MAX_BYTES - OTHER_ALLOCATION
                    - (mutation == Mutation.UNDELETABLE ? firstAllocation : 0L));
        }
    }

    private static Stream<Arguments> accountingCases() {
        return Arrays.stream(Removal.values()).flatMap(removal ->
                Arrays.stream(Mutation.values()).map(mutation -> Arguments.of(removal, mutation)));
    }

    private static void mutate(Path file, Mutation mutation) throws IOException {
        switch (mutation) {
            case UNCHANGED -> { }
            case SHRUNK -> Files.writeString(file, "null");
            case GROWN -> Files.writeString(file, " ".repeat(Math.toIntExact(MAX_BYTES)),
                    StandardOpenOption.APPEND);
            case MISSING -> Files.delete(file);
            case UNDELETABLE -> {
                Files.delete(file);
                Files.createDirectory(file);
                Files.writeString(file.resolve("held"), "prevents directory deletion");
            }
        }
    }

    private static boolean removeFirst(TrafficSpillFileQueue queue, Removal removal,
            Mutation mutation, TrafficQueueEntry first, TrafficQueueEntry second, Path firstFile)
            throws IOException {
        boolean readableFirst = mutation == Mutation.UNCHANGED || mutation == Mutation.GROWN;
        switch (removal) {
            case POLL -> {
                assertThat(queue.poll()).isEqualTo(readableFirst ? first.document() : second.document());
                return readableFirst;
            }
            case POLL_ENTRY -> {
                assertPreparedEntry(queue.pollEntry(), readableFirst ? first : second);
                return readableFirst;
            }
            case CLEAR -> {
                assertThat(queue.clear().failures()).isEqualTo(mutation == Mutation.UNDELETABLE ? 1L : 0L);
                return false;
            }
            case PURGE -> {
                assertThat(queue.removeIf(entry -> "first".equals(entry.prepared().operationId())))
                        .isEqualTo(1);
                return true;
            }
            case EXPIRE -> {
                if (mutation != Mutation.MISSING) {
                    Files.setLastModifiedTime(firstFile, FileTime.fromMillis(1L));
                }
                queue.canAcceptBytes(1L);
                // A missing file has no timestamp; ordinary draining, not retention, removes it.
                if (mutation == Mutation.MISSING) {
                    assertPreparedEntry(queue.pollEntry(), second);
                    return false;
                }
                return true;
            }
        }
        throw new AssertionError("Unhandled removal: " + removal);
    }

    private void assertRemainingQuota(long remaining) throws IOException {
        try (var exact = reserve(remaining)) {
            assertThat(exact.accepted()).as("remaining quota must not be stranded").isTrue();
        }
        try (var overflow = reserve(remaining + 1L)) {
            assertThat(overflow.accepted()).as("another allocation must stay reserved").isFalse();
        }
    }

    private ManagedStorageQuota.Reservation reserve(long bytes) throws IOException {
        return ManagedStorageQuota.reserve(spillDirectory,
                ManagedStorageQuota.Category.TRAFFIC_SPILL, projectId, bytes, MAX_BYTES);
    }

    private static void assertPreparedEntry(TrafficQueueEntry actual, TrafficQueueEntry expected) {
        assertThat(actual).isNotNull();
        assertThat(actual.prepared()).usingRecursiveComparison().isEqualTo(expected.prepared());
    }

    private static TrafficQueueEntry preparedEntry(String operationId) throws IOException {
        Map<String, Object> document = Map.of("request",
                Map.of("url", Map.of("raw", "https://spill.example/" + operationId)));
        byte[] bytes = ExportLineCodec.bulkNdjsonBytes(operationId, document);
        return TrafficQueueEntry.fromPrepared(new PreparedExportDocument(operationId,
                "tool-burp-traffic", "traffic", document, bytes.length, bytes,
                TrafficRouteBucket.SOURCE_PROXY_WEBSOCKET_HISTORY));
    }
}
