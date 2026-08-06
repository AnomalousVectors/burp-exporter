package ai.anomalousvectors.tools.burp.utils;

import java.nio.file.Path;

/**
 * Resolves exporter-managed disk locations.
 *
 * <p>All automatic, non-user-chosen disk writes should live under one clearly named root so the
 * extension does not scatter spill or temporary content across unrelated temp directories. Caller
 * code may still write to explicit user-selected destinations, but helper paths owned by the
 * exporter should resolve through this utility.</p>
 */
public final class ManagedDiskPaths {

    private static final String ROOT_DIR_NAME = "burp-exporter";
    private static final String SPILL_SUBDIR = "spill";
    private static final String PROXY_CORRELATION_SUBDIR = "proxy-correlation";

    private ManagedDiskPaths() { }

    /**
     * Returns the managed root directory under the platform temp location.
     *
     * <p>This method is thread-safe and side-effect free. Callers are responsible for creating the
     * directory when they need it to exist on disk.</p>
     *
     * @return canonical exporter-managed temp root
     */
    public static Path managedRootDirectory() {
        return Path.of(System.getProperty("java.io.tmpdir"), ROOT_DIR_NAME);
    }

    /**
     * Returns the spill directory under the managed root.
     *
     * <p>Traffic spill files should use this location so runtime overflow storage stays grouped
     * under the same exporter-managed parent directory.</p>
     *
     * @return canonical spill directory path
     */
    public static Path spillDirectory() {
        return managedRootDirectory().resolve(SPILL_SUBDIR);
    }

    /**
     * Returns the durable unresolved Proxy-correlation directory under the managed root.
     *
     * <p>Entries here have not yet been admitted to the traffic export queue. They remain separate
     * from overflow spill files so Stop and restart can resume exact Proxy History binding.</p>
     *
     * @return canonical unresolved Proxy-correlation directory path
     */
    public static Path proxyCorrelationDirectory() {
        return managedRootDirectory().resolve(PROXY_CORRELATION_SUBDIR);
    }
}
