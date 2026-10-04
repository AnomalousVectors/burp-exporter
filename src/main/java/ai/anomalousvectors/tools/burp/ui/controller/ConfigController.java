package ai.anomalousvectors.tools.burp.ui.controller;

import java.nio.file.Path;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.SwingUtilities;

import ai.anomalousvectors.tools.burp.utils.DiskSpaceGuard;
import ai.anomalousvectors.tools.burp.utils.FileUtil;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.WholeFileSave;
import ai.anomalousvectors.tools.burp.utils.config.ConfigJsonMapper;
import ai.anomalousvectors.tools.burp.utils.config.ConfigParseResult;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.search.SearchConnectionStatus;
import ai.anomalousvectors.tools.burp.utils.search.SearchConnectionTester;

/**
 * Coordinates owned background operations for the Config UI.
 *
 * <p>Import, export, and connection work runs on a controller-owned daemon executor. Import and
 * Test Connection use latest-request-wins cancellation and generation fencing. Export operations
 * may finish independently, but only the newest control operation may update control status.
 * {@link #close()} cancels queued/running work and prevents later UI or log callbacks.</p>
 */
public final class ConfigController implements AutoCloseable {

    /** UI callback surface implemented by ConfigPanel. */
    public interface Ui {
        /** Displays file-destination status on the EDT. */
        void onFileStatus(String message);

        /** Displays database-destination status on the EDT. */
        void onDatabaseStatus(String message);

        /** Displays import/export/control status on the EDT. */
        void onControlStatus(String message);

        /**
         * Applies the newest successfully imported state on the EDT.
         *
         * @param state imported configuration
         */
        default void onImportResult(ConfigState.State state) {
            // Most test and alternate UI implementations do not consume imported state.
        }
    }

    @FunctionalInterface
    interface ConfigImporter {
        ConfigParseResult importConfig(Path path) throws Exception;
    }

    @FunctionalInterface
    interface ConfigExporter {
        void exportConfig(Path path, String json, WholeFileSave.Replacement replacement) throws Exception;
    }

    @FunctionalInterface
    interface ConnectionProbe {
        SearchConnectionStatus test(ConfigState.SearchDestination destination, String url) throws Exception;
    }

    private static final int WORKER_COUNT = 3;

    private final Ui ui;
    private final ExecutorService executor;
    private final ConfigImporter importer;
    private final ConfigExporter exporter;
    private final ConnectionProbe connectionProbe;
    private final Object lifecycleLock = new Object();
    private long connectionGeneration;
    private long controlGeneration;
    private boolean closed;
    private Future<?> activeConnection;
    private Future<?> activeImport;

    /**
     * Creates a controller with an owned daemon executor and production I/O operations.
     *
     * @param ui destination for EDT callbacks
     */
    public ConfigController(Ui ui) {
        this(
                ui,
                newExecutor(),
                path -> ConfigJsonMapper.parse(FileUtil.readString(path)),
                WholeFileSave::writeUtf8,
                SearchConnectionTester::safeTestConnection);
    }

    ConfigController(
            Ui ui,
            ExecutorService executor,
            ConfigImporter importer,
            ConfigExporter exporter,
            ConnectionProbe connectionProbe) {
        this.ui = Objects.requireNonNull(ui, "ui");
        this.executor = Objects.requireNonNull(executor, "executor");
        this.importer = Objects.requireNonNull(importer, "importer");
        this.exporter = Objects.requireNonNull(exporter, "exporter");
        this.connectionProbe = Objects.requireNonNull(connectionProbe, "connectionProbe");
    }

    private static ExecutorService newExecutor() {
        AtomicInteger sequence = new AtomicInteger();
        return Executors.newFixedThreadPool(WORKER_COUNT, runnable -> {
            Thread thread = new Thread(
                    runnable,
                    "burp-exporter-config-" + sequence.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        });
    }

    /**
     * Writes the provided config JSON transactionally on an owned background thread.
     *
     * <p>Every completed export may log its result. Only the newest import/export action may
     * update control status, and no callback is published after {@link #close()}.</p>
     *
     * @param out destination path after extension normalization and overwrite confirmation
     * @param json serialized configuration payload
     * @param replacement confirmed replacement policy
     */
    public void exportConfigAsync(Path out, String json, WholeFileSave.Replacement replacement) {
        Objects.requireNonNull(out, "out");
        Objects.requireNonNull(replacement, "replacement");
        long generation;
        synchronized (lifecycleLock) {
            if (closed) {
                return;
            }
            generation = ++controlGeneration;
            postIfCurrentControl(generation, () -> ui.onControlStatus("Exporting configuration ..."));
            executor.execute(() -> runExport(generation, out, json, replacement));
        }
        Logger.logDebug("[Config] Export requested: " + out);
        Logger.logInfoPanelOnly("[Config] Exporting configuration to " + out + ".");
    }

    private void runExport(
            long generation,
            Path out,
            String json,
            WholeFileSave.Replacement replacement) {
        String status;
        boolean success;
        try {
            exporter.exportConfig(out, json, replacement);
            status = "Exported configuration to: " + out;
            success = true;
        } catch (Exception e) {
            status = "Export failed: " + userFacingMessage(e);
            success = false;
        }
        String completedStatus = status;
        boolean completedSuccessfully = success;
        postExportCompletion(generation, () -> {
            if (completedSuccessfully) {
                Logger.logInfoPanelOnly("[Config] " + completedStatus);
            } else {
                Logger.logErrorPanelOnly("[Config] " + completedStatus);
            }
        }, () -> ui.onControlStatus(completedStatus));
    }

    /**
     * Reads and parses a configuration file on an owned background thread.
     *
     * <p>A newer import cancels and fences the prior import. Only the newest successful result may
     * apply state or publish status/log output.</p>
     *
     * @param in config file to load
     */
    public void importConfigAsync(Path in) {
        Objects.requireNonNull(in, "in");
        long generation;
        synchronized (lifecycleLock) {
            if (closed) {
                return;
            }
            generation = ++controlGeneration;
            if (activeImport != null) {
                activeImport.cancel(true);
            }
            postIfCurrentControl(generation, () -> ui.onControlStatus("Importing configuration ..."));
            activeImport = executor.submit(() -> runImport(generation, in));
        }
        Logger.logDebug("[Config] Import requested: " + in);
    }

    private void runImport(long generation, Path in) {
        try {
            Logger.logInfoPanelOnly("[Config] Importing configuration from " + in + ".");
            ConfigParseResult result = importer.importConfig(in);
            postIfCurrentControl(generation, () -> publishImportResult(in, result));
        } catch (Exception e) {
            String status = formatImportFailureStatus(e);
            postIfCurrentControl(generation, () -> {
                ui.onControlStatus(status);
                Logger.logErrorPanelOnly("[Config] " + status);
            });
        }
    }

    private void publishImportResult(Path in, ConfigParseResult result) {
        ConfigState.State state = result.state();
        String status = result.report().formatControlStatusSummary(in);
        ui.onControlStatus(status);
        for (String line : result.report().formatLogLines(20)) {
            Logger.logInfoPanelOnly(line);
        }
        if (result.report().isEmpty()) {
            Logger.logInfoPanelOnly("[Config] Imported configuration from " + in + ".");
        }
        ui.onImportResult(state);
    }

    /**
     * Tests connectivity to an OpenSearch cluster asynchronously.
     *
     * @param url base URL of the OpenSearch cluster
     */
    public void testConnectionAsync(String url) {
        testConnectionAsync(ConfigState.SearchDestination.OPEN_SEARCH, url);
    }

    /**
     * Tests connectivity to the selected database destination on an owned background thread.
     *
     * <p>A newer request cancels and fences the prior request. The probe has its own bounded
     * transport timeout; a transport that ignores interruption may finish, but its stale result is
     * discarded.</p>
     *
     * @param destination selected database destination; {@code null} selects OpenSearch
     * @param url base URL of the selected destination
     */
    public void testConnectionAsync(ConfigState.SearchDestination destination, String url) {
        ConfigState.SearchDestination selected = destination == null
                ? ConfigState.SearchDestination.OPEN_SEARCH
                : destination;
        long generation;
        synchronized (lifecycleLock) {
            if (closed) {
                return;
            }
            generation = ++connectionGeneration;
            if (activeConnection != null) {
                activeConnection.cancel(true);
            }
            activeConnection = executor.submit(() -> runConnectionTest(generation, selected, url));
        }
        Logger.logDebug("[Config] " + selected.displayName() + " test connection requested.");
    }

    private void runConnectionTest(
            long generation,
            ConfigState.SearchDestination destination,
            String url) {
        String status;
        try {
            SearchConnectionStatus result = connectionProbe.test(destination, url);
            status = result.formattedStatus();
        } catch (Exception e) {
            status = failedConnectionStatus(destination, rootMessage(e));
        }
        String completedStatus = status;
        postIfCurrentConnection(generation, () -> {
            ui.onDatabaseStatus(completedStatus);
            if (completedStatus.startsWith("Connection: Success")) {
                Logger.logInfoPanelOnly("[" + destination.displayName()
                        + "] Test connection result\n" + completedStatus);
            } else {
                Logger.logWarnPanelOnly("[" + destination.displayName()
                        + "] Test connection result\n" + completedStatus);
            }
        });
    }

    private static String failedConnectionStatus(
            ConfigState.SearchDestination destination,
            String detail) {
        return "Connection: Failed\nAuthentication: Not tested\nTrust: Not tested\n"
                + destination.displayName() + " version: unknown\nDetails: " + detail;
    }

    private void postExportCompletion(long generation, Runnable logCallback, Runnable statusCallback) {
        SwingUtilities.invokeLater(() -> {
            boolean publishStatus;
            synchronized (lifecycleLock) {
                if (closed) {
                    return;
                }
                publishStatus = generation == controlGeneration;
            }
            logCallback.run();
            if (publishStatus) {
                statusCallback.run();
            }
        });
    }

    private void postIfCurrentControl(long generation, Runnable callback) {
        runOnEdt(() -> {
            synchronized (lifecycleLock) {
                if (closed || generation != controlGeneration) {
                    return;
                }
            }
            callback.run();
        });
    }

    private void postIfCurrentConnection(long generation, Runnable callback) {
        runOnEdt(() -> {
            synchronized (lifecycleLock) {
                if (closed || generation != connectionGeneration) {
                    return;
                }
            }
            callback.run();
        });
    }

    private static void runOnEdt(Runnable action) {
        if (SwingUtilities.isEventDispatchThread()) {
            action.run();
        } else {
            SwingUtilities.invokeLater(action);
        }
    }

    /**
     * Cancels owned work and permanently fences this controller's callbacks.
     *
     * <p>Thread-safe and idempotent. The executor uses daemon threads and is interrupted without
     * waiting so panel removal and extension unload do not block the EDT.</p>
     */
    @Override
    public void close() {
        synchronized (lifecycleLock) {
            if (closed) {
                return;
            }
            closed = true;
            connectionGeneration++;
            controlGeneration++;
            if (activeConnection != null) {
                activeConnection.cancel(true);
                activeConnection = null;
            }
            if (activeImport != null) {
                activeImport.cancel(true);
                activeImport = null;
            }
            executor.shutdownNow();
        }
    }

    private static String rootMessage(Throwable throwable) {
        Throwable current = throwable;
        while (current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
        }
        String message = current.getMessage();
        return message == null || message.isBlank()
                ? current.getClass().getSimpleName()
                : message;
    }

    private static String userFacingMessage(Throwable throwable) {
        Throwable current = throwable;
        while (current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
        }
        if (current instanceof DiskSpaceGuard.LowDiskSpaceException lowDisk) {
            return lowDisk.userMessage();
        }
        String message = current.getMessage();
        return message == null || message.isBlank()
                ? current.getClass().getSimpleName()
                : message;
    }

    private static String formatImportFailureStatus(Throwable throwable) {
        String detail = userFacingMessage(throwable);
        if (detail.contains("sinks.files") || detail.contains("sinks.database")) {
            return "Import failed: Sink settings must use nested 'sinks.files' and 'sinks.database' objects "
                    + "(for example 'sinks.database.openSearch.url'). Details: " + detail;
        }
        return "Import failed: " + detail;
    }
}
