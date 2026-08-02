package ai.anomalousvectors.tools.burp.utils;

import java.util.concurrent.atomic.AtomicReference;

/**
 * Bridges forced export-stop events to the Config Start/Stop control UI.
 *
 * <p>Background paths such as persistent destination failure and low-disk shutdown can stop export
 * without a Start/Stop button click. The control panel registers a listener so the indicator and
 * button can sync to the stopped state. The most recently registered listener wins. Process-local
 * and thread-safe.</p>
 */
public final class ExportControlBridge {

    private static final AtomicReference<Runnable> FORCED_STOPPED_LISTENER = new AtomicReference<>();

    private ExportControlBridge() {
    }

    /**
     * Registers the handler that syncs Start/Stop controls after a forced export stop.
     *
     * <p>Callers typically register from the EDT via {@code ConfigControlPanel}. Any previously
     * registered listener is replaced.</p>
     *
     * @param listener runs when export was stopped outside the Start/Stop click path; may be
     *                 {@code null} to clear
     */
    public static void registerForcedStopped(Runnable listener) {
        FORCED_STOPPED_LISTENER.set(listener);
    }

    /**
     * Clears the registered forced-stop listener.
     *
     * <p>Used by test reset paths and teardown that should stop UI sync delivery.</p>
     */
    public static void clear() {
        FORCED_STOPPED_LISTENER.set(null);
    }

    /**
     * Notifies the registered listener that export was forced to stop.
     *
     * <p>No-op when no listener is registered. Does not enforce EDT delivery; the listener is
     * responsible for marshaling to the EDT when mutating Swing controls. Listener runtime
     * exceptions propagate to the notifying caller.</p>
     */
    public static void notifyForcedStopped() {
        Runnable listener = FORCED_STOPPED_LISTENER.get();
        if (listener != null) {
            listener.run();
        }
    }
}
