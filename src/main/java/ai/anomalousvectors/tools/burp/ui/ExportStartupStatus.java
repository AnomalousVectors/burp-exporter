package ai.anomalousvectors.tools.burp.ui;

import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

/**
 * User-visible control-status text for export startup.
 *
 * <p>Messages reflect actual bootstrap phases: file preflight and file creation, search database
 * connection test, index creation, then background reporter startup.</p>
 */
public final class ExportStartupStatus {

    private static final String PREFIX = "Starting: ";

    private ExportStartupStatus() {}

    /**
     * Selected destinations at Start time.
     *
     * @param filesSelected Files sink checkbox selected
     * @param databaseSelected database sink checkbox selected
     */
    public record Snapshot(boolean filesSelected, boolean databaseSelected) {}

    /**
     * Captures sink selection from runtime configuration.
     *
     * <p>This method does not access Swing state and may be invoked from any thread.</p>
     *
     * @return point-in-time destination-selection snapshot
     */
    public static Snapshot capture() {
        ConfigState.State state = RuntimeConfig.getState();
        boolean files = false;
        boolean database = false;
        if (state != null) {
            ConfigState.Sinks sinks = state.sinks();
            if (sinks != null) {
                files = sinks.filesEnabled();
                database = sinks.databaseEnabled();
            }
        }
        return new Snapshot(files, database);
    }

    /**
     * Returns the initial status line shown immediately when Start is clicked.
     *
     * @param snapshot non-null destination-selection snapshot
     * @return initial starting message
     * @throws NullPointerException if {@code snapshot} is {@code null}
     */
    public static String initialStartingMessage(Snapshot snapshot) {
        return PREFIX + "preparing " + destinationLabel(snapshot) + " export …";
    }

    /**
     * Returns status while the file export root and per-source files are prepared.
     *
     * @return file-initialization message
     */
    public static String initializingFilesMessage() {
        return PREFIX + "initializing file export …";
    }

    /**
     * Returns status while search database connectivity is verified.
     *
     * @return connection-test message
     */
    public static String testingSearchConnectionMessage() {
        return PREFIX + "testing search database connection …";
    }

    /**
     * Returns the compatibility alias for search database connection status.
     *
     * @return connection-test message
     */
    public static String testingOpenSearchConnectionMessage() {
        return testingSearchConnectionMessage();
    }

    /**
     * Returns status while selected search database indexes are created or updated.
     *
     * @return index-creation message
     */
    public static String creatingSearchIndexesMessage() {
        return PREFIX + "creating search database indexes …";
    }

    /**
     * Returns the compatibility alias for search database index-creation status.
     *
     * @return index-creation message
     */
    public static String creatingOpenSearchIndexesMessage() {
        return creatingSearchIndexesMessage();
    }

    /**
     * Returns status while recurring reporters and traffic handlers are started.
     *
     * @return background-reporter startup message
     */
    public static String startingBackgroundReportersMessage() {
        return PREFIX + "starting background reporters …";
    }

    private static String destinationLabel(Snapshot snapshot) {
        String databaseName = RuntimeConfig.searchDestinationDisplayName();
        if (snapshot.filesSelected() && snapshot.databaseSelected()) {
            return "Files and " + databaseName;
        }
        if (snapshot.filesSelected()) {
            return "Files";
        }
        if (snapshot.databaseSelected()) {
            return databaseName;
        }
        return "export";
    }
}
