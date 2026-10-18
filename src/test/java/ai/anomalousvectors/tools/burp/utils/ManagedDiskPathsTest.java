package ai.anomalousvectors.tools.burp.utils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.testutils.TestPathSupport;
import ai.anomalousvectors.tools.burp.testutils.Reflect;
import ai.anomalousvectors.tools.burp.Exporter;

/** Tests protected-root validation, permissions, cleanup, and live-instance ownership. */
class ManagedDiskPathsTest {

    private Path testRoot;

    @AfterEach
    void resetManagedRoot() throws IOException {
        ManagedDiskPaths.resetForTests();
        deleteTree(testRoot);
    }

    @Test
    void initialize_restrictsDirectoriesAndRemovesLegacyAbandonedArtifacts() throws Exception {
        testRoot = TestPathSupport.createDirectory("managed-root-parent").resolve("managed");
        Files.createDirectories(testRoot.resolve("spill"));
        Files.writeString(testRoot.resolve("spill").resolve("abandoned.json"), "sensitive");
        ManagedDiskPaths.setManagedRootForTests(testRoot);

        ManagedDiskPaths.CleanupResult cleanup = ManagedDiskPaths.initialize();
        Path spill = ManagedDiskPaths.ensureManagedDirectory(ManagedDiskPaths.spillDirectory());
        Path sensitiveFile = FileUtil.writeTempFile("managed-storage-", ".tmp", "sensitive");

        assertThat(cleanup.entriesDeleted()).isEqualTo(2L);
        assertThat(cleanup.bytesDeleted()).isEqualTo(9L);
        assertThat(testRoot.resolve("spill")).doesNotExist();
        assertThat(spill).isDirectory();
        assertThat(Files.isSymbolicLink(spill)).isFalse();
        assertPrivatePermissions(testRoot);
        assertPrivatePermissions(spill);
        assertPrivateFilePermissions(sensitiveFile);
    }

    @Test
    void initialize_preservesLockedInstanceAndDeletesUnlockedInstance() throws Exception {
        testRoot = TestPathSupport.createDirectory("managed-instance-parent").resolve("managed");
        Path instances = Files.createDirectories(testRoot.resolve("instances"));
        Path active = Files.createDirectories(instances.resolve("active-instance"));
        Path activeOwner = Files.write(active.resolve(".owner.lock"), new byte[] {1});
        Path activeArtifact = Files.write(active.resolve("sensitive.json"), new byte[] {1, 2, 3});
        Path abandoned = Files.createDirectories(instances.resolve("abandoned-instance"));
        Files.write(abandoned.resolve(".owner.lock"), new byte[] {1});
        Files.write(abandoned.resolve("sensitive.json"), new byte[] {4, 5, 6});
        Files.write(abandoned.resolve("fresh.json.tmp"), new byte[] {7});
        Files.write(abandoned.resolve("stale.json"), new byte[] {8});
        Files.write(abandoned.resolve("corrupt.json.corrupt"), new byte[] {9});
        Files.write(abandoned.resolve("sent.json.delivered"), new byte[] {10});

        try (FileChannel channel = FileChannel.open(
                activeOwner, StandardOpenOption.READ, StandardOpenOption.WRITE);
                FileLock lock = channel.lock()) {
            assertThat(lock.isValid()).isTrue();
            ManagedDiskPaths.setManagedRootForTests(testRoot);
            ManagedDiskPaths.CleanupResult cleanup = ManagedDiskPaths.initialize();

            assertThat(activeArtifact).exists();
            assertThat(abandoned).doesNotExist();
            assertThat(cleanup.activeInstancesSkipped()).isEqualTo(1L);
            assertThat(cleanup.complete()).isTrue();
        }
    }

    @Test
    void closeInstance_removesOwnedTreeAndReinitializeFindsNoAbandonedEntries() throws Exception {
        testRoot = TestPathSupport.createDirectory("managed-close-parent").resolve("managed");
        ManagedDiskPaths.setManagedRootForTests(testRoot);
        ManagedDiskPaths.initialize();
        Path spill = ManagedDiskPaths.ensureManagedDirectory(ManagedDiskPaths.spillDirectory());
        ManagedDiskPaths.ensureManagedDirectory(ManagedDiskPaths.proxyCorrelationDirectory());
        Path temporaryFile = FileUtil.writeTempFile("managed-close-", ".tmp", "sensitive");
        Path instance = spill.getParent().getParent().getParent();

        ManagedDiskPaths.CleanupResult cleanup = ManagedDiskPaths.closeInstance();

        assertThat(cleanup.complete()).isTrue();
        assertThat(cleanup.entriesDeleted()).isEqualTo(8L);
        assertThat(cleanup.bytesDeleted()).isEqualTo(9L);
        assertThat(instance).doesNotExist();
        assertThat(temporaryFile).doesNotExist();
        ManagedDiskPaths.CleanupResult nextLoad = ManagedDiskPaths.initialize();
        assertThat(nextLoad.entriesDeleted()).isZero();
        assertThat(nextLoad.bytesDeleted()).isZero();
        assertThat(nextLoad.complete()).isTrue();
        assertThat(ManagedDiskPaths.closeInstance().complete()).isTrue();
        assertThat(ManagedDiskPaths.closeInstance().entriesDeleted()).isZero();
    }

    @Test
    void startupCleanup_reportsEmptyStructureAtDebugWithoutClaimingDiscardedData() throws Exception {
        testRoot = TestPathSupport.createDirectory("managed-empty-parent").resolve("managed");
        Path abandoned = Files.createDirectories(testRoot.resolve("instances/abandoned/empty"));
        Files.write(abandoned.getParent().resolve(".owner.lock"), new byte[0]);
        ManagedDiskPaths.setManagedRootForTests(testRoot);
        var messages = new CopyOnWriteArrayList<String>();
        Logger.LogListener listener = (level, message) -> messages.add(level + " " + message);
        Logger.registerListener(listener);
        try {
            Reflect.callStatic(Exporter.class, "initializeManagedStorage");
            assertThat(messages).contains(
                    "DEBUG [ManagedStorage] Removed 3 empty temporary filesystem entries "
                            + "(directories/zero-byte files); no file-content bytes were discarded.");
            assertThat(messages).noneMatch(message -> message.startsWith("INFO [ManagedStorage]"));
        } finally {
            Logger.unregisterListener(listener);
        }
        assertThat(abandoned.getParent()).doesNotExist();
    }

    @Test
    void startupCleanup_keepsDiscardedFileContentsVisibleAtInfo() throws Exception {
        testRoot = TestPathSupport.createDirectory("managed-data-parent").resolve("managed");
        Path abandoned = Files.createDirectories(testRoot.resolve("instances/abandoned"));
        Files.write(abandoned.resolve(".owner.lock"), new byte[0]);
        Files.writeString(abandoned.resolve("pending.json"), "sensitive");
        ManagedDiskPaths.setManagedRootForTests(testRoot);
        var messages = new CopyOnWriteArrayList<String>();
        Logger.LogListener listener = (level, message) -> messages.add(level + " " + message);
        Logger.registerListener(listener);
        try {
            Reflect.callStatic(Exporter.class, "initializeManagedStorage");
            assertThat(messages).contains(
                    "INFO [ManagedStorage] Discarded abandoned temporary file contents: 9 bytes; "
                            + "removed 3 filesystem entries (including directories and lock files). "
                            + "Unfinished export state is not replayed.");
        } finally {
            Logger.unregisterListener(listener);
        }
        assertThat(abandoned).doesNotExist();
    }

    @Test
    void initialize_rejectsPrecreatedNonDirectoryOrSymlinkRoot() throws Exception {
        Path parent = TestPathSupport.createDirectory("managed-unsafe-parent");
        Path target = Files.createDirectory(parent.resolve("target"));
        testRoot = parent.resolve("managed");
        boolean symbolicLinkCreated = false;
        try {
            Files.createSymbolicLink(testRoot, target.getFileName());
            symbolicLinkCreated = true;
        } catch (IOException | UnsupportedOperationException | SecurityException e) {
            Files.writeString(testRoot, "not-a-directory");
        }
        ManagedDiskPaths.setManagedRootForTests(testRoot);

        assertThatThrownBy(ManagedDiskPaths::initialize)
                .isInstanceOf(IOException.class)
                .hasMessageContaining("not a real directory");
        if (symbolicLinkCreated) {
            assertThat(testRoot).isSymbolicLink();
        } else {
            assertThat(testRoot).isRegularFile();
        }
    }

    private static void assertPrivatePermissions(Path path) throws IOException {
        PosixFileAttributeView posix = Files.getFileAttributeView(
                path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (posix != null) {
            assertThat(posix.readAttributes().permissions()).isEqualTo(EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE));
            return;
        }
        AclFileAttributeView acl = Files.getFileAttributeView(
                path, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        assertThat(acl).isNotNull();
        UserPrincipal owner = Files.getOwner(path, LinkOption.NOFOLLOW_LINKS);
        assertThat(acl.getAcl())
                .anySatisfy(entry -> {
                    assertThat(entry.type()).isEqualTo(AclEntryType.ALLOW);
                    assertThat(entry.principal()).isEqualTo(owner);
                })
                .allSatisfy(entry -> {
                    if (entry.type() == AclEntryType.ALLOW) {
                        assertThat(entry.principal()).isEqualTo(owner);
                    }
                });
    }

    private static void assertPrivateFilePermissions(Path path) throws IOException {
        PosixFileAttributeView posix = Files.getFileAttributeView(
                path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (posix != null) {
            assertThat(posix.readAttributes().permissions()).isEqualTo(EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE));
            return;
        }
        AclFileAttributeView acl = Files.getFileAttributeView(
                path, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        assertThat(acl).isNotNull();
        UserPrincipal owner = Files.getOwner(path, LinkOption.NOFOLLOW_LINKS);
        assertThat(acl.getAcl())
                .anySatisfy(entry -> {
                    assertThat(entry.type()).isEqualTo(AclEntryType.ALLOW);
                    assertThat(entry.principal()).isEqualTo(owner);
                })
                .allSatisfy(entry -> {
                    if (entry.type() == AclEntryType.ALLOW) {
                        assertThat(entry.principal()).isEqualTo(owner);
                    }
                });
    }

    private static void deleteTree(Path root) throws IOException {
        if (root == null || !Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        try (var paths = Files.walk(root)) {
            for (Path path : paths.sorted((left, right) -> right.compareTo(left)).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }
}
