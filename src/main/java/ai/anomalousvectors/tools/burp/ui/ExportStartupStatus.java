package ai.anomalousvectors.tools.burp.ui;

import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

/**
 * User-visible control-status text for export startup.
 *
 * <p>Messages reflect actual bootstrap phases: file preflight and file creation, OpenSearch
 * connection test, index creation, then background reporter startup.</p>
 */
public final class ExportStartupStatus {

    private static final String PREFIX = "Starting: ";

    private ExportStartupStatus() {}

    /**
     * Selected destinations at Start time.
     *
     * @param filesSelected Files sink checkbox selected
     * @param openSearchSelected OpenSearch sink checkbox selected
     */
    public record Snapshot(boolean filesSelected, boolean openSearchSelected) {}

    /** Captures sink selection from runtime config. Caller may invoke on the EDT when Start is clicked. */
    public static Snapshot capture() {
        ConfigState.State state = RuntimeConfig.getState();
        boolean files = false;
        boolean openSearch = false;
        if (state != null) {
            ConfigState.Sinks sinks = state.sinks();
            if (sinks != null) {
                files = sinks.filesEnabled();
                openSearch = sinks.osEnabled();
            }
        }
        return new Snapshot(files, openSearch);
    }

    /** Initial status line shown immediately when Start is clicked. */
    public static String initialStartingMessage(Snapshot snapshot) {
        return PREFIX + "preparing " + destinationLabel(snapshot) + " export …";
    }

    /** Status while file export root and per-source files are prepared. */
    public static String initializingFilesMessage() {
        return PREFIX + "initializing file export …";
    }

    /** Status while OpenSearch connectivity is verified. */
    public static String testingOpenSearchConnectionMessage() {
        return PREFIX + "testing OpenSearch connection …";
    }

    /** Status while selected OpenSearch indexes are created or updated. */
    public static String creatingOpenSearchIndexesMessage() {
        return PREFIX + "creating OpenSearch indexes …";
    }

    /** Status while recurring index reporters and traffic handlers are started. */
    public static String startingBackgroundReportersMessage() {
        return PREFIX + "starting background reporters …";
    }

    private static String destinationLabel(Snapshot snapshot) {
        String databaseName = RuntimeConfig.searchDestinationDisplayName();
        if (snapshot.filesSelected() && snapshot.openSearchSelected()) {
            return "Files and " + databaseName;
        }
        if (snapshot.filesSelected()) {
            return "Files";
        }
        if (snapshot.openSearchSelected()) {
            return databaseName;
        }
        return "export";
    }
}
