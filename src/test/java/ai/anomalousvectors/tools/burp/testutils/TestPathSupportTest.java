package ai.anomalousvectors.tools.burp.testutils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import org.junit.jupiter.api.Test;

/** Verifies file-test fixtures cannot clean or probe the operator's export directory. */
class TestPathSupportTest {

    @Test
    void isolatedUiFileRoot_isInsideBuildTmpAndPreservesContentsUntilExplicitCleanup() throws Exception {
        Path root = TestPathSupport.isolatedUiFileRoot();
        Path testRoot = Path.of("build", "tmp", "burp-exporter-tests").toAbsolutePath().normalize();
        assertThat(root.getParent()).isEqualTo(testRoot);
        assertThat(root).isNotEqualTo(Path.of("/path/to/directory").toAbsolutePath().normalize());
        Files.writeString(root.resolve("kept.txt"), "existing fixture content");
        try {
            assertThat(TestPathSupport.isolatedUiFileRoot()).isEqualTo(root);
            assertThat(Files.readString(root.resolve("kept.txt"))).isEqualTo("existing fixture content");
        } finally {
            TestPathSupport.cleanupExportArtifacts(root);
        }
        assertThat(root).doesNotExist();
    }

    @Test
    void cleanupUiFixture_removesOnlyItsOwnTree() throws Exception {
        Path root = TestPathSupport.isolatedUiFileRoot();
        Path other = TestPathSupport.createDirectory("unrelated-fixture");
        Path sentinel = Files.writeString(other.resolve("keep.jsonl"), "unrelated");
        Files.writeString(root.resolve("leftover.txt"), "leftover");
        Files.writeString(Files.createDirectory(root.resolve("nested")).resolve("entry.txt"), "nested");

        TestPathSupport.cleanupExportArtifacts(root);

        assertThat(root).doesNotExist();
        assertThat(Files.readString(sentinel)).isEqualTo("unrelated");
        assertThat(TestPathSupport.isolatedUiFileRoot()).isEmptyDirectory();
        TestPathSupport.cleanupExportArtifacts(root);
    }

    @Test
    void operatorDefaultPath_isRejectedWithoutProbingOrDeletingIt() {
        Path operatorRoot = Path.of("/path/to/directory");

        assertThat(TestPathSupport.isWritableDirectory(operatorRoot)).isFalse();
        assertThatThrownBy(() -> TestPathSupport.cleanupExportArtifacts(operatorRoot))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("outside the test-owned directory boundary");
    }

    @Test
    void neighboringDirectoryOutsideTestRoot_isPreserved() throws Exception {
        Path outside = Path.of("build", "tmp", "operator-owned-" + UUID.randomUUID())
                .toAbsolutePath().normalize();
        Files.createDirectories(outside);
        Path sentinel = Files.writeString(outside.resolve("keep.jsonl"), "operator-owned");
        try {
            assertThatThrownBy(() -> TestPathSupport.cleanupExportArtifacts(outside))
                    .isInstanceOf(IOException.class);
            assertThat(TestPathSupport.isWritableDirectory(outside)).isFalse();
            assertThat(Files.readString(sentinel)).isEqualTo("operator-owned");
        } finally {
            Files.delete(sentinel);
            Files.delete(outside);
        }
    }

    @Test
    void cleanup_rejectsTestRootAndNormalizedParentEscape() throws Exception {
        Path owned = TestPathSupport.createDirectory("cleanup-boundary");
        Path testRoot = owned.getParent();
        Path sentinel = Files.writeString(owned.resolve("keep.jsonl"), "keep");

        assertThatThrownBy(() -> TestPathSupport.cleanupExportArtifacts(testRoot))
                .isInstanceOf(IOException.class);
        assertThatThrownBy(() -> TestPathSupport.cleanupExportArtifacts(owned.resolve("../..")))
                .isInstanceOf(IOException.class);
        assertThat(Files.readString(sentinel)).isEqualTo("keep");
    }

    @Test
    void ordinaryFixtureCleanup_removesExportsButRetainsOtherFiles() throws Exception {
        Path root = TestPathSupport.createDirectory("file-artifact-cleanup");
        assertThat(TestPathSupport.isWritableDirectory(root)).isTrue();
        Files.writeString(root.resolve("traffic.jsonl"), "jsonl");
        Files.writeString(root.resolve("traffic.ndjson"), "ndjson");
        Path sentinel = Files.writeString(root.resolve("keep.txt"), "keep");

        TestPathSupport.cleanupExportArtifacts(root);

        assertThat(root.resolve("traffic.jsonl")).doesNotExist();
        assertThat(root.resolve("traffic.ndjson")).doesNotExist();
        assertThat(Files.readString(sentinel)).isEqualTo("keep");
    }
}
