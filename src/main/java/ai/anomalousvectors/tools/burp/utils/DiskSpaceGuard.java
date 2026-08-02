package ai.anomalousvectors.tools.burp.utils;

import java.io.IOException;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import ai.anomalousvectors.tools.burp.sinks.ExportReporterLifecycle;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

/**
 * Enforces exporter disk-space safety rules.
 *
 * <p>The exporter should stop writing before the destination disk becomes critically full. This
 * guard preserves a 1 GiB safety reserve on the target volume and centralizes the status/log
 * behavior for low-disk write refusals.</p>
 *
 * <p>When the disk/file sink is the only active sink, low disk stops export entirely via
 * {@link ExportReporterLifecycle#stopAndClearPendingExportWork()}. When database export remains
 * enabled, this guard refuses only the local disk write and leaves database export running.</p>
 *
 * <p>Thread-safe. Write checks perform filesystem I/O and should run off the EDT. The cached public
 * probe supports frequent UI refreshes, although a cache miss can still query the filesystem.</p>
 */
public final class DiskSpaceGuard {

    /** Maximum managed-disk usage for spill and other exporter-owned storage. */
    public static final long MAX_MANAGED_BYTES = 1024L * 1024L * 1024L;
    /** Minimum free bytes that must remain on the destination volume after a write. */
    public static final long MIN_FREE_BYTES = 1024L * 1024L * 1024L;
    private static final long LOW_DISK_LOG_THROTTLE_MS = 30_000L;
    /**
     * TTL for {@link #usableSpacePublic(Path)} FileStore probes used by spill budgeting and
     * Overview status. Write checks via {@link #ensureWritable} always query fresh usable space.
     */
    private static final long USABLE_SPACE_PUBLIC_CACHE_TTL_MS = 2_000L;

    private static final Map<String, Long> LAST_LOW_DISK_NOTIFICATION_MS = new ConcurrentHashMap<>();
    private static volatile Function<Path, Long> usableSpaceOverride;
    private static final Object USABLE_SPACE_PUBLIC_CACHE_LOCK = new Object();
    private static Path usableSpacePublicCacheDirectory;
    private static long usableSpacePublicCacheBytes;
    private static long usableSpacePublicCacheAtMs;

    private DiskSpaceGuard() { }

    /**
     * Exception used when a disk write is refused due to low available space.
     *
     * <p>The message is intended for diagnostics; {@link #userMessage()} is the user-facing
     * summary that callers should prefer for UI status text.</p>
     */
    public static final class LowDiskSpaceException extends IOException {
        private final String userMessage;

        /**
         * Creates a new low-disk exception.
         *
         * @param message diagnostic detail for logs and stack traces
         * @param userMessage concise user-facing summary
         */
        public LowDiskSpaceException(String message, String userMessage) {
            super(message);
            this.userMessage = userMessage;
        }

        /** Returns the user-facing summary for status surfaces. */
        public String userMessage() {
            return userMessage;
        }
    }

    /**
     * Ensures the destination volume has enough free space for a write.
     *
     * <p>The check preserves a 1 GiB reserve after the write completes. On failure this method
     * logs the event, posts the appropriate control status, and may stop export when the current
     * sink selection means disk is the only active sink. Caller may invoke from any thread.</p>
     *
     * <p>A null target uses the exporter-managed root. A non-null target whose final path segment
     * contains a dot is treated as a file and resolved to its parent; other targets are treated as
     * directories.</p>
     *
     * @param target path being written, its containing directory, or {@code null} for the managed
     *               root
     * @param bytesToWrite estimated write size in bytes
     * @param context short context for logs and user-facing status; {@code null} is rendered as
     *                literal diagnostic text
     * @throws IOException when the disk cannot be checked or the write should be refused
     * @throws RuntimeException if a test override fails while serving a write check
     */
    public static void ensureWritable(Path target, long bytesToWrite, String context) throws IOException {
        Path directory = resolveDirectory(target);
        long requiredBytes = Math.max(0L, bytesToWrite);
        long usableBytes = usableSpace(directory);
        if (usableBytes - requiredBytes >= MIN_FREE_BYTES) {
            return;
        }

        String userMessage = userMessageForLowDisk();
        String detail = "Low disk space: refusing " + context
                + " write under " + directory.toAbsolutePath()
                + " (usable=" + formatBytes(usableBytes)
                + ", requested=" + formatBytes(requiredBytes)
                + ", reserve=" + formatBytes(MIN_FREE_BYTES) + ")";
        notifyLowDisk(directory, detail, userMessage);
        throw new LowDiskSpaceException(detail, userMessage);
    }

    /**
     * Returns usable free bytes on the volume for {@code target}, or {@code -1} when unknown.
     *
     * <p>Used by spill headroom budgeting and Overview Traffic Spill Status. Results are cached
     * briefly so frequent Stats/admission probes do not repeatedly hit {@link FileStore} on the
     * EDT or hot paths. Does not enforce the write reserve; callers that write must still call
     * {@link #ensureWritable(Path, long, String)}, which always reads fresh usable space.</p>
     *
     * <p>A null target uses the exporter-managed root. A non-null target whose final path segment
     * contains a dot is treated as a file and resolved to its parent; other targets are treated as
     * directories. Probe and override failures are converted to {@code -1}.</p>
     *
     * @param target path or directory on the target volume, or {@code null} for the managed root
     * @return usable bytes, or {@code -1} when the volume cannot be queried
     */
    public static long usableSpacePublic(Path target) {
        Path directory = resolveDirectory(target);
        Function<Path, Long> override = usableSpaceOverride;
        if (override != null) {
            try {
                Long forced = override.apply(directory);
                return forced == null ? -1L : forced;
            } catch (RuntimeException e) {
                return -1L;
            }
        }
        long now = System.currentTimeMillis();
        synchronized (USABLE_SPACE_PUBLIC_CACHE_LOCK) {
            if (directory.equals(usableSpacePublicCacheDirectory)
                    && now - usableSpacePublicCacheAtMs < USABLE_SPACE_PUBLIC_CACHE_TTL_MS) {
                return usableSpacePublicCacheBytes;
            }
        }
        long usable;
        try {
            usable = usableSpace(directory);
        } catch (IOException | RuntimeException e) {
            return -1L;
        }
        synchronized (USABLE_SPACE_PUBLIC_CACHE_LOCK) {
            usableSpacePublicCacheDirectory = directory;
            usableSpacePublicCacheBytes = usable;
            usableSpacePublicCacheAtMs = now;
        }
        return usable;
    }

    /**
     * Visible-for-tests override for usable space calculation.
     *
     * <p>Tests may force low-disk scenarios without filling the real disk. Production code should
     * leave this unset. Installing or clearing an override also invalidates the public probe
     * cache. The replacement may be invoked from any thread.</p>
     *
     * @param override replacement usable-space resolver, or {@code null} to clear
     */
    public static void setUsableSpaceOverride(Function<Path, Long> override) {
        usableSpaceOverride = override;
        clearUsableSpacePublicCache();
    }

    /**
     * Clears low-disk throttling state and test overrides.
     *
     * <p>Intended for test teardown so one scenario does not leak notification state into the
     * next test.</p>
     */
    public static void resetForTests() {
        usableSpaceOverride = null;
        LAST_LOW_DISK_NOTIFICATION_MS.clear();
        clearUsableSpacePublicCache();
    }

    private static void clearUsableSpacePublicCache() {
        synchronized (USABLE_SPACE_PUBLIC_CACHE_LOCK) {
            usableSpacePublicCacheDirectory = null;
            usableSpacePublicCacheBytes = 0L;
            usableSpacePublicCacheAtMs = 0L;
        }
    }

    private static void notifyLowDisk(Path directory, String detail, String userMessage) {
        String key = directory.toAbsolutePath().toString();
        long now = System.currentTimeMillis();
        long last = LAST_LOW_DISK_NOTIFICATION_MS.getOrDefault(key, 0L);
        if (now - last < LOW_DISK_LOG_THROTTLE_MS) {
            return;
        }
        LAST_LOW_DISK_NOTIFICATION_MS.put(key, now);
        Logger.logError(detail);

        if (RuntimeConfig.isExportRunning() && shouldStopAllExportForLowDisk()) {
            ExportReporterLifecycle.stopAndClearPendingExportWork();
            ControlStatusBridge.post("Stopped due to low disk space");
            Logger.logInfoPanelOnly("[Export] Forced stop due to low disk space; syncing Start/Stop controls.");
            ExportControlBridge.notifyForcedStopped();
            return;
        }

        ControlStatusBridge.post(userMessage);
    }

    private static boolean shouldStopAllExportForLowDisk() {
        ConfigState.State state = RuntimeConfig.getState();
        if (state == null || state.sinks() == null) {
            return false;
        }
        ConfigState.Sinks sinks = state.sinks();
        return sinks.filesEnabled() && !sinks.databaseEnabled();
    }

    private static String userMessageForLowDisk() {
        if (!RuntimeConfig.isExportRunning()) {
            return "Write cancelled due to low disk space";
        }
        if (shouldStopAllExportForLowDisk()) {
            return "Stopped due to low disk space";
        }
        ConfigState.State state = RuntimeConfig.getState();
        boolean databaseEnabled = state != null && state.sinks() != null && state.sinks().databaseEnabled();
        if (databaseEnabled) {
            return "Local disk writes stopped due to low disk space; "
                    + RuntimeConfig.searchDestinationDisplayName() + " export continues.";
        }
        return "Write cancelled due to low disk space";
    }

    private static Path resolveDirectory(Path target) {
        if (target == null) {
            return ManagedDiskPaths.managedRootDirectory();
        }
        Path normalized = target.toAbsolutePath().normalize();
        String fileName = normalized.getFileName() == null ? "" : normalized.getFileName().toString();
        return fileName.contains(".") ? normalized.getParent() : normalized;
    }

    private static long usableSpace(Path directory) throws IOException {
        Function<Path, Long> override = usableSpaceOverride;
        if (override != null) {
            return override.apply(directory);
        }
        Path existing = directory;
        while (existing != null && !Files.exists(existing)) {
            existing = existing.getParent();
        }
        if (existing == null) {
            existing = directory;
        }
        FileStore store = Files.getFileStore(existing);
        return store.getUsableSpace();
    }

    private static String formatBytes(long bytes) {
        double value = Math.max(0L, bytes);
        String unit = "B";
        if (value >= 1024d * 1024d * 1024d) {
            value /= 1024d * 1024d * 1024d;
            unit = "GB";
        } else if (value >= 1024d * 1024d) {
            value /= 1024d * 1024d;
            unit = "MB";
        } else if (value >= 1024d) {
            value /= 1024d;
            unit = "KB";
        }
        if ("B".equals(unit)) {
            return String.format(java.util.Locale.ROOT, "%d %s", (long) value, unit);
        }
        return String.format(java.util.Locale.ROOT, "%.1f %s", value, unit);
    }
}
