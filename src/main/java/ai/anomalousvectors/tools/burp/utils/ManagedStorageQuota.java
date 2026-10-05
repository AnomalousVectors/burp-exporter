package ai.anomalousvectors.tools.burp.utils;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

/** Cross-process per-project accounting for exporter-managed temporary storage. */
public final class ManagedStorageQuota {

    private static final String QUOTAS_SUBDIR = "quotas";
    private static final String PROJECTS_SUBDIR = "projects";
    private static final long LOCK_TIMEOUT_NANOS = TimeUnit.SECONDS.toNanos(5L);
    private static final long LOCK_RETRY_NANOS = TimeUnit.MILLISECONDS.toNanos(5L);

    /** Independently capped temporary-storage shares within each Burp project. */
    public enum Category {
        TRAFFIC_SPILL("traffic-spill"),
        PROXY_CORRELATION("proxy-correlation");

        private final String quotaName;

        Category(String quotaName) {
            this.quotaName = quotaName;
        }
    }

    private ManagedStorageQuota() { }

    /**
     * Atomically reserves project-scoped bytes before a managed write.
     *
     * <p>Directories outside the managed root retain their constructor-local test limits and
     * receive a no-op accepted reservation.</p>
     *
     * @param directory target managed directory
     * @param category quota share
     * @param projectId Burp project identifier
     * @param bytes requested bytes
     * @param maximumBytes project-scoped cap for this category
     * @return reservation that must be committed after a successful write or closed to roll back
     * @throws IOException when accounting cannot be read or updated safely
     */
    public static Reservation reserve(
            Path directory,
            Category category,
            String projectId,
            long bytes,
            long maximumBytes) throws IOException {
        long requested = Math.max(0L, bytes);
        if (!ManagedDiskPaths.isActiveInstancePath(directory) || requested == 0L) {
            return Reservation.noop();
        }
        String safeProjectId = ManagedDiskPaths.sanitizeProjectId(projectId);
        validateProjectDirectory(directory, safeProjectId);
        Path quota = quotaPath(category, safeProjectId);
        FileChannel channel = openQuotaFile(quota);
        FileLock lock = null;
        try {
            lock = acquireQuotaLock(channel);
            long current = readUsage(channel);
            long next;
            try {
                next = Math.addExact(current, requested);
            } catch (ArithmeticException e) {
                throw new IOException("Managed-storage quota overflow.", e);
            }
            if (next > Math.max(1L, maximumBytes)) {
                releaseLockAndChannel(lock, channel);
                return Reservation.rejected();
            }
            writeUsage(channel, next);
            return new Reservation(requested, true, false, channel, lock);
        } catch (IOException | RuntimeException e) {
            releaseLockAndChannelQuietly(lock, channel);
            throw e;
        }
    }

    /** Releases project-scoped bytes after a managed artifact is deleted. */
    public static void release(
            Path directory,
            Category category,
            String projectId,
            long bytes) throws IOException {
        long released = Math.max(0L, bytes);
        if (!ManagedDiskPaths.isActiveInstancePath(directory) || released == 0L) {
            return;
        }
        String safeProjectId = ManagedDiskPaths.sanitizeProjectId(projectId);
        validateProjectDirectory(directory, safeProjectId);
        adjust(category, safeProjectId, -released, Long.MAX_VALUE);
    }

    /**
     * Reconciles quota files against every currently retained instance tree.
     *
     * <p>Call while holding startup cleanup ownership and after abandoned-instance cleanup. Quotas
     * are reset only for projects absent from every retained instance tree. Active or incompletely
     * cleaned projects retain conservative accounting until a later startup can prove that no
     * instance owns them.</p>
     *
     * @return number of project/category quota files rewritten
     * @throws IOException when the protected tree cannot be scanned safely
     */
    public static long reconcileAll() throws IOException {
        Path quotas = quotaDirectory();
        Set<String> projects = discoverQuotaProjects(quotas);
        Set<String> retainedProjects = discoverRetainedProjects();
        long reconciled = 0L;
        for (String project : projects) {
            if (retainedProjects.contains(project)) {
                continue;
            }
            for (Category category : Category.values()) {
                reset(project, category);
                reconciled++;
            }
        }
        return reconciled;
    }

    private static boolean adjust(
            Category category,
            String projectId,
            long delta,
            long maximumBytes) throws IOException {
        Path quota = quotaPath(category, projectId);
        try (FileChannel channel = openQuotaFile(quota); FileLock ignored = acquireQuotaLock(channel)) {
            long current = readUsage(channel);
            long next;
            try {
                next = Math.addExact(current, delta);
            } catch (ArithmeticException e) {
                throw new IOException("Managed-storage quota overflow.", e);
            }
            next = Math.max(0L, next);
            if (delta > 0L && next > maximumBytes) {
                return false;
            }
            writeUsage(channel, next);
            return true;
        }
    }

    private static void reset(String projectId, Category category) throws IOException {
        Path quota = quotaPath(category, projectId);
        try (FileChannel channel = openQuotaFile(quota); FileLock ignored = acquireQuotaLock(channel)) {
            writeUsage(channel, 0L);
        }
    }

    private static Set<String> discoverQuotaProjects(Path quotas) throws IOException {
        Set<String> projects = new LinkedHashSet<>();
        if (Files.isDirectory(quotas, LinkOption.NOFOLLOW_LINKS)) {
            try (DirectoryStream<Path> quotaFiles = Files.newDirectoryStream(quotas, "*.quota")) {
                for (Path quota : quotaFiles) {
                    String name = quota.getFileName().toString();
                    for (Category category : Category.values()) {
                        String suffix = "." + category.quotaName + ".quota";
                        if (name.endsWith(suffix)) {
                            projects.add(name.substring(0, name.length() - suffix.length()));
                        }
                    }
                }
            }
        }
        return projects;
    }

    private static Set<String> discoverRetainedProjects() throws IOException {
        Set<String> projects = new LinkedHashSet<>();
        Path instances = ManagedDiskPaths.instancesDirectoryPath();
        try (DirectoryStream<Path> instanceStream = Files.newDirectoryStream(instances)) {
            for (Path instance : instanceStream) {
                Path projectRoot = instance.resolve(PROJECTS_SUBDIR);
                if (!Files.isDirectory(projectRoot, LinkOption.NOFOLLOW_LINKS)
                        || Files.isSymbolicLink(projectRoot)) {
                    continue;
                }
                try (DirectoryStream<Path> projectStream = Files.newDirectoryStream(projectRoot)) {
                    for (Path project : projectStream) {
                        if (Files.isDirectory(project, LinkOption.NOFOLLOW_LINKS)
                                && !Files.isSymbolicLink(project)) {
                            projects.add(ManagedDiskPaths.sanitizeProjectId(
                                    project.getFileName().toString()));
                        }
                    }
                }
            }
        }
        return projects;
    }

    private static void validateProjectDirectory(Path directory, String projectId) throws IOException {
        Path projectDirectory = directory.toAbsolutePath().normalize().getParent();
        if (projectDirectory == null
                || !projectId.equals(projectDirectory.getFileName().toString())) {
            throw new IOException("Managed-storage directory does not match its Burp project.");
        }
    }

    private static Path quotaDirectory() throws IOException {
        Path directory = ManagedDiskPaths.managedRootDirectory().resolve(QUOTAS_SUBDIR);
        return ManagedDiskPaths.ensureSharedDirectory(directory);
    }

    private static Path quotaPath(Category category, String projectId) throws IOException {
        return quotaDirectory().resolve(projectId + "." + category.quotaName + ".quota");
    }

    private static FileChannel openQuotaFile(Path quota) throws IOException {
        boolean existed = Files.exists(quota, LinkOption.NOFOLLOW_LINKS);
        if (existed && (Files.isSymbolicLink(quota)
                || !Files.isRegularFile(quota, LinkOption.NOFOLLOW_LINKS))) {
            throw new IOException("Managed-storage quota path is not a regular file.");
        }
        FileChannel channel = FileChannel.open(
                quota,
                StandardOpenOption.CREATE,
                StandardOpenOption.READ,
                StandardOpenOption.WRITE);
        try {
            ManagedDiskPaths.secureManagedFile(quota);
            return channel;
        } catch (IOException e) {
            channel.close();
            if (!existed) {
                Files.deleteIfExists(quota);
            }
            throw e;
        }
    }

    private static long readUsage(FileChannel channel) throws IOException {
        long size = channel.size();
        if (size == 0L) {
            return 0L;
        }
        if (size != Long.BYTES) {
            throw new IOException("Managed-storage quota file has an invalid length.");
        }
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        channel.position(0L);
        while (buffer.hasRemaining()) {
            if (channel.read(buffer) < 0) {
                throw new IOException("Managed-storage quota file ended unexpectedly.");
            }
        }
        buffer.flip();
        long value = buffer.getLong();
        if (value < 0L) {
            throw new IOException("Managed-storage quota file contains a negative value.");
        }
        return value;
    }

    private static FileLock acquireQuotaLock(FileChannel channel) throws IOException {
        long deadline = System.nanoTime() + LOCK_TIMEOUT_NANOS;
        while (true) {
            try {
                FileLock lock = channel.tryLock();
                if (lock != null) {
                    return lock;
                }
            } catch (OverlappingFileLockException ignored) {
                // Another classloader in this Burp process owns the same project quota briefly.
            }
            if (System.nanoTime() >= deadline) {
                throw new IOException("Timed out waiting for managed-storage project quota.");
            }
            if (Thread.currentThread().isInterrupted()) {
                throw new IOException("Interrupted while waiting for managed-storage project quota.");
            }
            LockSupport.parkNanos(LOCK_RETRY_NANOS);
        }
    }

    private static void writeUsage(FileChannel channel, long value) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES).putLong(Math.max(0L, value));
        buffer.flip();
        channel.truncate(0L);
        channel.position(0L);
        while (buffer.hasRemaining()) {
            channel.write(buffer);
        }
    }

    private static void releaseLockAndChannel(FileLock lock, FileChannel channel) throws IOException {
        IOException failure = null;
        if (lock != null) {
            try {
                lock.release();
            } catch (IOException e) {
                failure = e;
            }
        }
        try {
            channel.close();
        } catch (IOException e) {
            if (failure == null) {
                failure = e;
            } else {
                failure.addSuppressed(e);
            }
        }
        if (failure != null) {
            throw failure;
        }
    }

    private static void releaseLockAndChannelQuietly(FileLock lock, FileChannel channel) {
        try {
            releaseLockAndChannel(lock, channel);
        } catch (IOException ignored) {
            // Preserve the primary reservation or accounting failure.
        }
    }

    /** One reversible quota reservation. */
    public static final class Reservation implements AutoCloseable {
        private final long bytes;
        private final boolean accepted;
        private final boolean noop;
        private final FileChannel channel;
        private final FileLock lock;
        private boolean committed;
        private boolean closed;

        private Reservation(
                long bytes,
                boolean accepted,
                boolean noop,
                FileChannel channel,
                FileLock lock) {
            this.bytes = bytes;
            this.accepted = accepted;
            this.noop = noop;
            this.channel = channel;
            this.lock = lock;
        }

        private static Reservation noop() {
            return new Reservation(0L, true, true, null, null);
        }

        private static Reservation rejected() {
            return new Reservation(0L, false, true, null, null);
        }

        /** Returns whether the project-scoped cap admitted the reservation. */
        public boolean accepted() {
            return accepted;
        }

        /** Keeps an accepted reservation after its filesystem write succeeds. */
        public void commit() {
            if (!accepted || noop || committed || closed) {
                return;
            }
            committed = true;
            closed = true;
            releaseLockAndChannelQuietly(lock, channel);
        }

        @Override
        public void close() throws IOException {
            if (closed) {
                return;
            }
            closed = true;
            if (accepted && !committed && !noop && bytes > 0L) {
                IOException failure = null;
                try {
                    long current = readUsage(channel);
                    writeUsage(channel, Math.max(0L, current - bytes));
                } catch (IOException e) {
                    failure = e;
                }
                try {
                    releaseLockAndChannel(lock, channel);
                } catch (IOException e) {
                    if (failure == null) {
                        failure = e;
                    } else {
                        failure.addSuppressed(e);
                    }
                }
                if (failure != null) {
                    throw failure;
                }
            }
        }
    }
}
