package ai.anomalousvectors.tools.burp.utils;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

/**
 * Owns and resolves the exporter's protected temporary-storage tree.
 *
 * <p>Each loaded extension instance holds an operating-system lock in a unique child directory.
 * Sensitive spill files are written only below that directory. Startup removes unlocked instance
 * trees left by crashes but never traverses an instance whose owner lock is still held. The shared
 * root and every managed child are validated as real, non-symlink directories owned by the same
 * principal as the running process.</p>
 *
 * <p>Initialization performs filesystem I/O and may block briefly on another instance's cleanup
 * lock. Public path accessors initialize lazily so process-local reporters created during class
 * loading cannot bypass root validation.</p>
 */
public final class ManagedDiskPaths {

    private static final String ROOT_DIR_NAME = "burp-exporter";
    private static final String INSTANCES_SUBDIR = "instances";
    private static final String PROJECTS_SUBDIR = "projects";
    private static final String SPILL_SUBDIR = "spill";
    private static final String PROXY_CORRELATION_SUBDIR = "proxy-correlation";
    private static final String TEMPORARY_FILES_SUBDIR = "temporary-files";
    private static final String OWNER_LOCK_NAME = ".owner.lock";
    private static final String CLEANUP_LOCK_NAME = ".cleanup.lock";
    private static final String INSTANCE_ID = UUID.randomUUID().toString();
    private static final Object LIFECYCLE_LOCK = new Object();
    private static final long CLEANUP_LOCK_TIMEOUT_NANOS = TimeUnit.SECONDS.toNanos(5L);
    private static final long CLEANUP_LOCK_RETRY_NANOS = TimeUnit.MILLISECONDS.toNanos(5L);
    private static final Set<PosixFilePermission> PRIVATE_DIRECTORY_PERMISSIONS =
            EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE);
    private static final Set<PosixFilePermission> PRIVATE_FILE_PERMISSIONS =
            EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

    private static Path rootOverrideForTests;
    private static InstanceLease instanceLease;

    private ManagedDiskPaths() { }

    /**
     * Initializes the protected managed root and acquires this extension instance's owner lock.
     *
     * <p>Repeated calls in one classloader are harmless. Cleanup failures are returned to the
     * caller but do not make abandoned data eligible for replay.</p>
     *
     * @return startup cleanup result
     * @throws IOException when the root cannot be proven safe for sensitive writes
     */
    public static CleanupResult initialize() throws IOException {
        synchronized (LIFECYCLE_LOCK) {
            if (instanceLease != null) {
                return CleanupResult.empty();
            }
            Path requestedRoot = configuredRootDirectory();
            Path root = prepareManagedRoot(requestedRoot);
            Path instances = preparePrivateDirectory(root, root.resolve(INSTANCES_SUBDIR));
            String instanceId = INSTANCE_ID;
            Path instance = preparePrivateDirectory(root, instances.resolve(instanceId));
            Path ownerLockPath = instance.resolve(OWNER_LOCK_NAME);
            FileChannel ownerChannel = null;
            FileLock ownerLock = null;
            try {
                ownerChannel = openPrivateLockFile(ownerLockPath);
                ownerLock = ownerChannel.tryLock();
                if (ownerLock == null) {
                    throw new IOException("Unable to acquire managed-storage instance ownership.");
                }
                InstanceLease lease = new InstanceLease(
                        root, instances, instanceId, instance, ownerLockPath, ownerChannel, ownerLock);
                instanceLease = lease;
                return cleanupAbandonedStorageLocked(lease);
            } catch (IOException | RuntimeException e) {
                releaseQuietly(ownerLock);
                closeQuietly(ownerChannel);
                instanceLease = null;
                deleteTreeBestEffort(root, instance);
                throw e;
            }
        }
    }

    /**
     * Releases this instance's owner lock and removes its now-disposable tree.
     *
     * @return cleanup result for the current instance tree
     */
    public static CleanupResult closeInstance() {
        synchronized (LIFECYCLE_LOCK) {
            InstanceLease lease = instanceLease;
            instanceLease = null;
            if (lease == null) {
                return CleanupResult.empty();
            }
            releaseQuietly(lease.ownerLock());
            closeQuietly(lease.ownerChannel());
            return deleteTreeBestEffort(lease.root(), lease.instanceDirectory());
        }
    }

    /** Returns the configured managed root without creating it. */
    public static Path managedRootDirectory() {
        return configuredRootDirectory();
    }

    /** Returns this instance's protected traffic-spill directory for the current Burp project. */
    public static Path spillDirectory() {
        return projectDirectory().resolve(SPILL_SUBDIR);
    }

    /** Returns this instance's protected Proxy-correlation directory for the current Burp project. */
    public static Path proxyCorrelationDirectory() {
        return projectDirectory().resolve(PROXY_CORRELATION_SUBDIR);
    }

    /** Returns this instance's protected general-purpose temporary-file directory. */
    public static Path temporaryFilesDirectory() {
        InstanceLease lease = requireLeaseUnchecked();
        Path directory = lease.instanceDirectory().resolve(TEMPORARY_FILES_SUBDIR);
        try {
            return preparePrivateDirectory(lease.root(), directory);
        } catch (IOException e) {
            throw new IllegalStateException("Managed temporary storage is unavailable: "
                    + e.getMessage(), e);
        }
    }

    /**
     * Creates and validates a managed directory before a sensitive write.
     *
     * @param directory directory returned by this utility
     * @return real validated directory
     * @throws IOException when the path escapes the active instance or is not privately owned
     */
    public static Path ensureManagedDirectory(Path directory) throws IOException {
        InstanceLease lease = requireLease();
        Path normalized = directory.toAbsolutePath().normalize();
        if (!normalized.startsWith(lease.instanceDirectory())) {
            throw new IOException("Managed-storage path is not owned by the active instance.");
        }
        return preparePrivateDirectory(lease.root(), directory);
    }

    /** Returns whether {@code path} is inside the configured managed root. */
    public static boolean isManagedPath(Path path) {
        return path != null
                && path.toAbsolutePath().normalize().startsWith(configuredRootDirectory());
    }

    /** Returns whether {@code path} belongs to the active instance's protected tree. */
    public static boolean isActiveInstancePath(Path path) {
        if (path == null) {
            return false;
        }
        synchronized (LIFECYCLE_LOCK) {
            return instanceLease != null
                    && path.toAbsolutePath().normalize()
                            .startsWith(instanceLease.instanceDirectory());
        }
    }

    /** Returns a filesystem-safe, locale-independent project identifier. */
    public static String currentProjectId() {
        try {
            var api = MontoyaApiProvider.get();
            if (api != null && api.project() != null) {
                String projectId = api.project().id();
                if (projectId != null && !projectId.isBlank()) {
                    return sanitizeProjectId(projectId);
                }
            }
        } catch (RuntimeException ignored) {
            // Runtime metadata remains available through normal startup and unload transitions.
        }
        return sanitizeProjectId(BurpRuntimeMetadata.projectIdOrUnknown());
    }

    /** Returns a filesystem-safe, locale-independent project identifier. */
    public static String sanitizeProjectId(String raw) {
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

    static void setManagedRootForTests(Path root) {
        synchronized (LIFECYCLE_LOCK) {
            closeInstance();
            rootOverrideForTests = root == null ? null : root.toAbsolutePath().normalize();
        }
    }

    static void resetForTests() {
        synchronized (LIFECYCLE_LOCK) {
            closeInstance();
            rootOverrideForTests = null;
        }
    }

    static Path ensureSharedDirectory(Path directory) throws IOException {
        InstanceLease lease = requireLease();
        return preparePrivateDirectory(lease.root(), directory);
    }

    /**
     * Validates and applies owner-restricted permissions to a managed file.
     *
     * @param file file below the protected managed root
     * @throws IOException when the file escapes the root, is a symlink, has another owner, or
     *     cannot be restricted
     */
    public static void secureManagedFile(Path file) throws IOException {
        InstanceLease lease = requireLease();
        Path normalized = file.toAbsolutePath().normalize();
        if (!normalized.startsWith(lease.root()) || Files.isSymbolicLink(normalized)) {
            throw new IOException("Managed-storage file escaped its protected root.");
        }
        validateSameOwner(lease.root(), normalized);
        restrictPermissions(normalized, false);
    }

    static Path instancesDirectoryPath() {
        return requireLeaseUnchecked().instancesDirectory();
    }

    private static Path projectDirectory() {
        InstanceLease lease = requireLeaseUnchecked();
        Path projects = lease.instanceDirectory().resolve(PROJECTS_SUBDIR);
        Path project = projects.resolve(currentProjectId());
        try {
            preparePrivateDirectory(lease.root(), projects);
            return preparePrivateDirectory(lease.root(), project);
        } catch (IOException e) {
            throw new IllegalStateException("Managed temporary storage is unavailable: "
                    + e.getMessage(), e);
        }
    }

    private static InstanceLease requireLeaseUnchecked() {
        synchronized (LIFECYCLE_LOCK) {
            if (instanceLease == null) {
                try {
                    initialize();
                } catch (IOException e) {
                    throw new IllegalStateException("Managed temporary storage is unavailable: "
                            + e.getMessage(), e);
                }
            }
            return instanceLease;
        }
    }

    private static InstanceLease requireLease() throws IOException {
        synchronized (LIFECYCLE_LOCK) {
            if (instanceLease == null) {
                initialize();
            }
            if (instanceLease == null) {
                throw new IOException("Managed temporary storage has no active owner.");
            }
            return instanceLease;
        }
    }

    private static Path configuredRootDirectory() {
        synchronized (LIFECYCLE_LOCK) {
            if (rootOverrideForTests != null) {
                return rootOverrideForTests;
            }
        }
        return Path.of(System.getProperty("java.io.tmpdir"), ROOT_DIR_NAME)
                .toAbsolutePath()
                .normalize();
    }

    private static Path prepareManagedRoot(Path requestedRoot) throws IOException {
        Path root = requestedRoot.toAbsolutePath().normalize();
        Path parent = root.getParent();
        if (parent == null || !Files.isDirectory(parent)) {
            throw new IOException("Managed-storage parent directory is unavailable.");
        }
        if (Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
            requireRealDirectory(root);
        } else {
            createPrivateDirectory(root);
        }
        validateCurrentOwner(root);
        restrictPermissions(root, true);
        return root.toRealPath(LinkOption.NOFOLLOW_LINKS);
    }

    private static Path preparePrivateDirectory(Path root, Path requested) throws IOException {
        Path normalizedRoot = root.toAbsolutePath().normalize();
        Path target = requested.toAbsolutePath().normalize();
        if (!target.startsWith(normalizedRoot)) {
            throw new IOException("Managed-storage path escaped its protected root.");
        }
        Path relative = normalizedRoot.relativize(target);
        Path current = normalizedRoot;
        for (Path segment : relative) {
            current = current.resolve(segment);
            if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
                requireRealDirectory(current);
            } else {
                try {
                    createPrivateDirectory(current);
                } catch (FileAlreadyExistsException e) {
                    requireRealDirectory(current);
                }
            }
            validateSameOwner(normalizedRoot, current);
            restrictPermissions(current, true);
        }
        return target;
    }

    private static void createPrivateDirectory(Path directory) throws IOException {
        PosixFileAttributeView posix = Files.getFileAttributeView(
                directory.getParent(), PosixFileAttributeView.class);
        if (posix != null) {
            FileAttribute<Set<PosixFilePermission>> permissions =
                    PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY_PERMISSIONS);
            Files.createDirectory(directory, permissions);
        } else {
            Files.createDirectory(directory);
        }
        requireRealDirectory(directory);
        restrictPermissions(directory, true);
    }

    private static FileChannel openPrivateLockFile(Path path) throws IOException {
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS) && Files.isSymbolicLink(path)) {
            throw new IOException("Managed-storage lock path is a symbolic link.");
        }
        FileChannel channel = FileChannel.open(
                path,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.READ,
                StandardOpenOption.WRITE);
        try {
            restrictPermissions(path, false);
            return channel;
        } catch (IOException e) {
            closeQuietly(channel);
            Files.deleteIfExists(path);
            throw e;
        }
    }

    private static CleanupResult cleanupAbandonedStorageLocked(InstanceLease lease) throws IOException {
        Path cleanupLockPath = lease.root().resolve(CLEANUP_LOCK_NAME);
        FileChannel cleanupChannel = openSharedLockFile(cleanupLockPath);
        try (cleanupChannel; FileLock ignored = acquireCleanupLock(cleanupChannel)) {
            CleanupResult result = cleanupLegacyLayout(lease.root());
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(lease.instancesDirectory())) {
                for (Path candidate : stream) {
                    if (candidate.equals(lease.instanceDirectory())) {
                        continue;
                    }
                    result = result.plus(cleanAbandonedInstance(lease.root(), candidate));
                }
            }
            ManagedStorageQuota.reconcileAll();
            return result;
        }
    }

    private static CleanupResult cleanupLegacyLayout(Path root) {
        CleanupResult result = CleanupResult.empty();
        result = result.plus(deleteTreeBestEffort(root, root.resolve(SPILL_SUBDIR)));
        result = result.plus(deleteTreeBestEffort(root, root.resolve(PROXY_CORRELATION_SUBDIR)));
        return result;
    }

    private static CleanupResult cleanAbandonedInstance(Path root, Path candidate) {
        if (Files.isSymbolicLink(candidate) || !Files.isDirectory(candidate, LinkOption.NOFOLLOW_LINKS)) {
            return deleteTreeBestEffort(root, candidate);
        }
        Path ownerPath = candidate.resolve(OWNER_LOCK_NAME);
        if (!Files.isRegularFile(ownerPath, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(ownerPath)) {
            return deleteTreeBestEffort(root, candidate);
        }
        try (FileChannel channel = FileChannel.open(
                ownerPath, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            FileLock lock;
            try {
                lock = channel.tryLock();
            } catch (OverlappingFileLockException e) {
                return CleanupResult.activeSkipped();
            }
            if (lock == null) {
                return CleanupResult.activeSkipped();
            }
            try (lock) {
                return deleteTreeBestEffort(root, candidate);
            }
        } catch (IOException | RuntimeException e) {
            return CleanupResult.failure();
        }
    }

    private static FileLock acquireCleanupLock(FileChannel channel) throws IOException {
        long deadline = System.nanoTime() + CLEANUP_LOCK_TIMEOUT_NANOS;
        while (true) {
            try {
                FileLock lock = channel.tryLock();
                if (lock != null) {
                    return lock;
                }
            } catch (OverlappingFileLockException ignored) {
                // Another classloader in this Burp process is completing startup cleanup.
            }
            if (System.nanoTime() >= deadline) {
                throw new IOException("Timed out waiting for managed-storage cleanup ownership.");
            }
            if (Thread.currentThread().isInterrupted()) {
                throw new IOException("Interrupted while waiting for managed-storage cleanup ownership.");
            }
            LockSupport.parkNanos(CLEANUP_LOCK_RETRY_NANOS);
        }
    }

    private static FileChannel openSharedLockFile(Path path) throws IOException {
        try {
            return openPrivateLockFile(path);
        } catch (FileAlreadyExistsException e) {
            if (Files.isSymbolicLink(path)
                    || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("Managed-storage cleanup lock is not a regular file.", e);
            }
            FileChannel channel = FileChannel.open(
                    path, StandardOpenOption.READ, StandardOpenOption.WRITE);
            try {
                restrictPermissions(path, false);
                return channel;
            } catch (IOException failure) {
                closeQuietly(channel);
                throw failure;
            }
        }
    }

    private static CleanupResult deleteTreeBestEffort(Path root, Path target) {
        if (target == null || !Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            return CleanupResult.empty();
        }
        Path normalizedRoot = root.toAbsolutePath().normalize();
        Path normalizedTarget = target.toAbsolutePath().normalize();
        if (normalizedTarget.equals(normalizedRoot) || !normalizedTarget.startsWith(normalizedRoot)) {
            return CleanupResult.failure();
        }
        MutableCleanup cleanup = new MutableCleanup();
        try {
            Files.walkFileTree(normalizedTarget, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) {
                    cleanup.recordDelete(file, attributes.size());
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException failure) {
                    cleanup.failures++;
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path directory, IOException failure) {
                    if (failure != null) {
                        cleanup.failures++;
                    }
                    cleanup.recordDelete(directory, 0L);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException | RuntimeException e) {
            cleanup.failures++;
        }
        return cleanup.result();
    }

    private static void requireRealDirectory(Path directory) throws IOException {
        if (Files.isSymbolicLink(directory)
                || !Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Managed-storage path is not a real directory: " + directory);
        }
    }

    private static void validateCurrentOwner(Path root) throws IOException {
        Path probe = null;
        try {
            probe = Files.createTempFile(root, ".owner-probe-", ".tmp");
            restrictPermissions(probe, false);
            UserPrincipal directoryOwner = Files.getOwner(root, LinkOption.NOFOLLOW_LINKS);
            UserPrincipal processOwner = Files.getOwner(probe, LinkOption.NOFOLLOW_LINKS);
            if (!directoryOwner.equals(processOwner)) {
                throw new IOException("Managed-storage root is owned by another principal.");
            }
        } finally {
            if (probe != null) {
                Files.deleteIfExists(probe);
            }
        }
    }

    private static void validateSameOwner(Path root, Path child) throws IOException {
        UserPrincipal rootOwner = Files.getOwner(root, LinkOption.NOFOLLOW_LINKS);
        UserPrincipal childOwner = Files.getOwner(child, LinkOption.NOFOLLOW_LINKS);
        if (!rootOwner.equals(childOwner)) {
            throw new IOException("Managed-storage child is owned by another principal: " + child);
        }
    }

    private static void restrictPermissions(Path path, boolean directory) throws IOException {
        PosixFileAttributeView posix = Files.getFileAttributeView(
                path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (posix != null) {
            Set<PosixFilePermission> expected = directory
                    ? PRIVATE_DIRECTORY_PERMISSIONS
                    : PRIVATE_FILE_PERMISSIONS;
            posix.setPermissions(expected);
            if (!posix.readAttributes().permissions().equals(expected)) {
                throw new IOException("Managed-storage POSIX permissions are not owner-only.");
            }
            return;
        }
        AclFileAttributeView acl = Files.getFileAttributeView(
                path, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (acl == null) {
            throw new IOException("Filesystem does not expose owner-restrictable permissions.");
        }
        UserPrincipal owner = Files.getOwner(path, LinkOption.NOFOLLOW_LINKS);
        AclEntry.Builder builder = AclEntry.newBuilder()
                .setType(AclEntryType.ALLOW)
                .setPrincipal(owner)
                .setPermissions(EnumSet.allOf(AclEntryPermission.class));
        if (directory) {
            builder.setFlags(AclEntryFlag.DIRECTORY_INHERIT, AclEntryFlag.FILE_INHERIT);
        }
        acl.setAcl(List.of(builder.build()));
        List<AclEntry> effective = acl.getAcl();
        boolean unsafeAllow = effective.stream()
                .anyMatch(entry -> entry.type() == AclEntryType.ALLOW
                        && !entry.principal().equals(owner));
        boolean ownerAllowed = effective.stream()
                .anyMatch(entry -> entry.type() == AclEntryType.ALLOW
                        && entry.principal().equals(owner));
        if (unsafeAllow || !ownerAllowed) {
            throw new IOException("Managed-storage ACL is not owner-restricted.");
        }
    }

    private static void releaseQuietly(FileLock lock) {
        if (lock == null) {
            return;
        }
        try {
            lock.release();
        } catch (IOException ignored) {
            // Best-effort release during failed initialization or unload.
        }
    }

    private static void closeQuietly(FileChannel channel) {
        if (channel == null) {
            return;
        }
        try {
            channel.close();
        } catch (IOException ignored) {
            // Best-effort close during failed initialization or unload.
        }
    }

    /** Startup or unload cleanup accounting. */
    public record CleanupResult(
            long filesDeleted,
            long bytesDeleted,
            long failures,
            long activeInstancesSkipped) {

        static CleanupResult empty() {
            return new CleanupResult(0L, 0L, 0L, 0L);
        }

        static CleanupResult failure() {
            return new CleanupResult(0L, 0L, 1L, 0L);
        }

        static CleanupResult activeSkipped() {
            return new CleanupResult(0L, 0L, 0L, 1L);
        }

        CleanupResult plus(CleanupResult other) {
            return new CleanupResult(
                    filesDeleted + other.filesDeleted,
                    bytesDeleted + other.bytesDeleted,
                    failures + other.failures,
                    activeInstancesSkipped + other.activeInstancesSkipped);
        }

        /** Returns whether every selected abandoned artifact was removed. */
        public boolean complete() {
            return failures == 0L;
        }
    }

    private record InstanceLease(
            Path root,
            Path instancesDirectory,
            String instanceId,
            Path instanceDirectory,
            Path ownerLockPath,
            FileChannel ownerChannel,
            FileLock ownerLock) { }

    private static final class MutableCleanup {
        private long filesDeleted;
        private long bytesDeleted;
        private long failures;

        private void recordDelete(Path path, long bytes) {
            try {
                if (Files.deleteIfExists(path)) {
                    filesDeleted++;
                    bytesDeleted += Math.max(0L, bytes);
                }
            } catch (IOException | RuntimeException e) {
                failures++;
            }
        }

        private CleanupResult result() {
            return new CleanupResult(filesDeleted, bytesDeleted, failures, 0L);
        }
    }
}
