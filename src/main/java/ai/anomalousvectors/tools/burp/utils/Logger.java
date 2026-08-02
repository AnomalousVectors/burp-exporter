package ai.anomalousvectors.tools.burp.utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.WeakHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import burp.api.montoya.logging.Logging;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.core.AppenderBase;
import org.slf4j.LoggerFactory;

/**
 * Centralizes extension logging for SLF4J, Burp, and Swing listeners.
 *
 * <p>This helper writes to SLF4J and exposes a listener bus used by the Log panel and tests. Only
 * explicit extension-lifecycle methods mirror messages to Burp's logging APIs.</p>
 *
 * <p>A bounded replay buffer lets newly registered listeners reconstruct recent history after UI
 * removal or recreation. Listener callbacks are always delivered on the EDT.</p>
 *
 * <p>Use a stable {@code [Component]} prefix on every message so support can search the Log tab
 * and log files. Choose destinations as follows:</p>
 * <ul>
 *   <li>{@link #logInfoPanelOnly}, {@link #logWarnPanelOnly}, and
 *       {@link #logErrorPanelOnly}: SLF4J and Log tab only, for operator runtime messages.</li>
 *   <li>{@link #logInfoPanelAndBurp}: SLF4J, Log tab, and Burp Output, for extension
 *       load/unload lifecycle only.</li>
 *   <li>{@link #logErrorPanelAndBurp}: SLF4J, Log tab, and Burp Error, for extension
 *       initialization failures only.</li>
 *   <li>{@link #logDebug} and {@link #logTrace}: SLF4J and Log tab only, for detailed or
 *       high-volume diagnostics.</li>
 *   <li>{@link #logInfo}, {@link #logWarn}, and {@link #logError}: SLF4J and Log tab only, for
 *       general runtime messages.</li>
 *   <li>{@link #internalDebug} and {@link #internalTrace}: SLF4J only, for Log panel internals
 *       that must not feed back into the listener bus.</li>
 * </ul>
 * <p>Do not use {@link #logError} for recoverable per-document OpenSearch failures; record stats and
 * emit {@link #logWarnPanelOnly} at the reporter plus {@link #logDebug} in
 * {@link ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClientWrapper}. User-initiated
 * Stop treats in-flight push failures as cancellation ({@link #logTrace}, not WARN/ERROR) via
 * {@link ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchPushCancellation}.</p>
 */
public final class Logger {

    /**
     * Receives log events emitted through {@link Logger}.
     *
     * <p>Callbacks are invoked on the EDT, even when the originating log call comes from a worker
     * thread.</p>
     */
    public interface LogListener {
        /**
         * Receives one normalized log event on the EDT.
         *
         * <p>Runtime exceptions are isolated and logged at internal DEBUG level.</p>
         *
         * @param level log level label
         * @param message non-null message text
         */
        void onLog(String level, String message);
    }

    private static final String INTERNAL_LOGGER_NAME = "ai.anomalousvectors.tools.burp";
    private static final int REPLAY_BUFFER_SIZE = 500;

    private static final org.slf4j.Logger LOG =
            LoggerFactory.getLogger(INTERNAL_LOGGER_NAME);

    private static final List<LogListener> LISTENERS = new CopyOnWriteArrayList<>();
    private static final AtomicReference<Logging> BURP_LOGGER = new AtomicReference<>();

    /** Bounded replay buffer for new listeners. Guarded by REPLAY_BUFFER_LOCK. */
    private static final Object REPLAY_BUFFER_LOCK = new Object();
    private static final List<ReplayEvent> REPLAY_BUFFER = new ArrayList<>(REPLAY_BUFFER_SIZE);
    private static final AtomicLong REPLAY_SEQ = new AtomicLong(0);
    private static final Map<LogListener, Long> LAST_SEEN =
            Collections.synchronizedMap(new WeakHashMap<>());

    /**
     * Utility holder; not instantiable.
     */
    private Logger() {}

    /**
     * Wires Burp's logging sink.
     *
     * @param montoyaLogging Burp logging handle, or {@code null} to clear the sink
     */
    public static void initialize(Logging montoyaLogging) { BURP_LOGGER.set(montoyaLogging); }

    /**
     * Registers a UI/log listener. If the listener is a {@link ReplayableLogListener},
     * recent buffered messages are replayed so the panel shows full history (e.g. after
     * switching back to the extension tab when Burp had removed the panel).
     * Replay runs immediately on the EDT or is queued asynchronously when registration occurs on
     * another thread. Listener exceptions are isolated from the caller.
     *
     * @param listener listener to add (nullable ignored)
     */
    public static void registerListener(LogListener listener) {
        if (listener == null) return;
        if (LISTENERS.contains(listener)) return;
        LISTENERS.add(listener);
        if (listener instanceof ReplayableLogListener) {
            replayTo(listener);
        }
    }

    /**
     * Marker for listeners that should receive a replay of recent messages when registered
     * (e.g. LogPanel so the tab shows full history after a tab switch).
     */
    public interface ReplayableLogListener extends LogListener {}

    /**
     * Unregisters a UI/log listener.
     *
     * @param listener listener to remove (nullable ignored)
     */
    public static void unregisterListener(LogListener listener) { LISTENERS.remove(listener); }

    /**
     * Clears listener registrations, replay state, and the Montoya logging sink.
     *
     * <p>Intended for extension unload and test isolation so stale listeners do not
     * survive a reload or leak state across tests.</p>
     */
    public static void resetState() {
        LISTENERS.clear();
        BURP_LOGGER.set(null);
        LAST_SEEN.clear();
        synchronized (REPLAY_BUFFER_LOCK) {
            REPLAY_BUFFER.clear();
        }
        REPLAY_SEQ.set(0);
    }

    // -------- Public API (mirrored to UI listener bus) --------

    /**
     * Logs at INFO to SLF4J and UI listeners without writing to Burp's console.
     *
     * @param msg message to log
     */
    public static void logInfo(String msg)  {
        final String m = safe(msg);
        LOG.info(m);
        notifyListeners("INFO",  m);
    }

    /**
     * Logs at INFO to SLF4J and UI listeners only; does not send to Burp extension Output.
     * Use for high-signal messages that should appear in the extension's Log tab but not in
     * Burp's Extensions → Output console (e.g. "Creating index for: X", "Result for X: CREATED").
     *
     * @param msg message to log
     */
    public static void logInfoPanelOnly(String msg) {
        final String m = safe(msg);
        LOG.info(m);
        notifyListeners("INFO", m);
    }

    /**
     * Logs at INFO with separate text for the Log tab and Burp Extensions Output.
     *
     * <p>SLF4J and the Log tab receive {@code panelMessage}; Burp's Output console receives
     * {@code burpMessage} only. Use when the Extensions tab should show a clean operator-facing
     * line while the Log tab keeps a {@code [Component]} prefix for grep support.</p>
     *
     * @param panelMessage message for SLF4J and Log tab listeners
     * @param burpMessage message for Burp Extensions Output only
     */
    public static void logInfoPanelAndBurp(String panelMessage, String burpMessage) {
        final String panel = safe(panelMessage);
        final String burp = safe(burpMessage);
        LOG.info(panel);
        toBurpOut(burp);
        notifyListeners("INFO", panel);
    }

    /**
     * Logs an extension lifecycle failure with separate panel and Burp error-console text.
     *
     * <p>This is reserved for extension initialization failures. Runtime export errors belong in
     * the extension Log tab and must use {@link #logError} or {@link #logErrorPanelOnly}.</p>
     *
     * @param panelMessage message for SLF4J and Log tab listeners
     * @param burpMessage concise extension-lifecycle message for Burp's error console
     * @param failure initialization failure; may be {@code null}
     */
    public static void logErrorPanelAndBurp(
            String panelMessage, String burpMessage, Throwable failure) {
        final String panel = safe(panelMessage);
        final String burp = safe(burpMessage);
        final String detail = failure != null
                ? " :: " + failure.getClass().getSimpleName() + ": " + safe(failure.getMessage())
                : "";
        LOG.error(panel, failure);
        toBurpErr(burp + detail);
        notifyListeners("ERROR", panel + detail);
    }

    /**
     * Logs at WARN to SLF4J and UI listeners only; does not send to Burp's output/error consoles.
     *
     * <p>Use for recoverable degradation or operator-visible warning conditions that should be easy
     * to spot in the extension Log tab without adding noise to Burp's global console.</p>
     *
     * @param msg message to log
     */
    public static void logWarnPanelOnly(String msg) {
        final String m = safe(msg);
        LOG.warn(m);
        notifyListeners("WARN", m);
    }

    /**
     * Logs at ERROR to SLF4J and UI listeners only; does not send to Burp's error console.
     *
     * @param msg message to log
     */
    public static void logErrorPanelOnly(String msg) {
        final String m = safe(msg);
        LOG.error(m);
        notifyListeners("ERROR", m);
    }

    /**
     * Logs at WARN to SLF4J and UI listeners without writing to Burp's console.
     *
     * @param msg message to log
     */
    public static void logWarn(String msg)  {
        final String m = safe(msg);
        LOG.warn(m);
        notifyListeners("WARN",  m);
    }

    /**
     * Logs at DEBUG (when enabled) and mirrors to UI listeners only (not Burp console).
     *
     * @param msg message to log
     */
    public static void logDebug(String msg) {
        final String m = safe(msg);
        if (LOG.isDebugEnabled()) LOG.debug(m);
        notifyListeners("DEBUG", m);
    }

    /**
     * Logs at TRACE (when enabled) and mirrors to UI listeners only (not Burp console).
     *
     * @param msg message to log
     */
    public static void logTrace(String msg) {
        final String m = safe(msg);
        if (LOG.isTraceEnabled()) LOG.trace(m);
        notifyListeners("TRACE", m);
    }

    /**
     * Logs at ERROR to SLF4J and UI listeners without writing to Burp's console.
     *
     * @param msg message to log
     */
    public static void logError(String msg) {
        final String m = safe(msg);
        LOG.error(m);
        notifyListeners("ERROR", m);
    }

    /**
     * Logs at ERROR with throwable and sends a concise summary to UI listeners only.
     *
     * @param msg message to log
     * @param t   throwable (nullable)
     */
    public static void logError(String msg, Throwable t) {
        final String base = safe(msg);
        final String detail = (t != null ? " :: " + t.getClass().getSimpleName() + ": " + safe(t.getMessage()) : "");
        final String uiMessage = base + detail;
        LOG.error(base, t);                    // stack trace handled by backend
        notifyListeners("ERROR", uiMessage);
    }

    /**
     * Allows logging backends to forward events into the UI listener bus.
     *
     * @param level   level string
     * @param message message to emit
     */
    public static void emitToListeners(String level, String message) {
        notifyListeners(level, safe(message));
    }

    // -------- Internal-only API (NO UI mirroring) --------
    // Use these inside components like LogPanel to avoid self-feeding the UI listener bus.

    /** Logs at INFO without notifying UI listeners. */
    public static void internalInfo(String msg)  { if (LOG.isInfoEnabled())  LOG.info(safe(msg)); }
    /** Logs at WARN without notifying UI listeners. */
    public static void internalWarn(String msg)  { if (LOG.isWarnEnabled())  LOG.warn(safe(msg)); }
    /** Logs at DEBUG without notifying UI listeners. */
    public static void internalDebug(String msg) { if (LOG.isDebugEnabled()) LOG.debug(safe(msg)); }
    /** Logs at TRACE without notifying UI listeners. */
    public static void internalTrace(String msg) { if (LOG.isTraceEnabled()) LOG.trace(safe(msg)); }

    /**
     * Returns whether DEBUG-level internal logging is enabled. Hot paths can use this to skip
     * message-string concatenation entirely when the level is disabled.
     */
    public static boolean isInternalDebugEnabled() { return LOG.isDebugEnabled(); }

    /**
     * Returns whether TRACE-level internal logging is enabled. Hot paths can use this to skip
     * message-string concatenation entirely when the level is disabled.
     */
    public static boolean isInternalTraceEnabled() { return LOG.isTraceEnabled(); }

    // -------- Internals --------

    /**
     * Sends a message to Burp's standard output log if available.
     *
     * @param m message to log
     */
    private static void toBurpOut(String m) {
        final Logging l = BURP_LOGGER.get();
        if (l != null) {
            try { l.logToOutput(m); }
            catch (RuntimeException ex) {
                if (LOG.isDebugEnabled()) LOG.debug("logToOutput failed: {}", ex.toString());
            }
        }
    }

    /**
     * Sends a message to Burp's error log if available.
     *
     * @param m message to log
     */
    private static void toBurpErr(String m) {
        final Logging l = BURP_LOGGER.get();
        if (l != null) {
            try { l.logToError(m); }
            catch (RuntimeException ex) {
                if (LOG.isDebugEnabled()) LOG.debug("logToError failed: {}", ex.toString());
            }
        }
    }

    /**
     * Dispatches a message to registered UI listeners.
     * Always runs listener callbacks on the EDT so the Log panel (and any Swing
     * listener) updates correctly when log calls come from worker threads.
     *
     * @param level level string
     * @param m     message text
     */
    private static void notifyListeners(String level, String m) {
        long seq = appendToReplayBuffer(level, m);
        if (LISTENERS.isEmpty()) {
            return;
        }
        if (SwingUtilities.isEventDispatchThread()) {
            doNotifyListeners(seq, level, m);
        } else {
            SwingUtilities.invokeLater(() -> doNotifyListeners(seq, level, m));
        }
    }

    private static long appendToReplayBuffer(String level, String m) {
        long seq = REPLAY_SEQ.incrementAndGet();
        synchronized (REPLAY_BUFFER_LOCK) {
            REPLAY_BUFFER.add(new ReplayEvent(seq, level, m));
            while (REPLAY_BUFFER.size() > REPLAY_BUFFER_SIZE) {
                REPLAY_BUFFER.remove(0);
            }
        }
        return seq;
    }

    /**
     * Replays buffered messages to a single listener on the EDT so the panel shows full history.
     */
    private static void replayTo(LogListener listener) {
        long lastSeen = LAST_SEEN.getOrDefault(listener, 0L);
        List<ReplayEvent> snapshot;
        synchronized (REPLAY_BUFFER_LOCK) {
            snapshot = new ArrayList<>(REPLAY_BUFFER);
        }
        if (snapshot.isEmpty()) return;
        List<ReplayEvent> toReplay = new ArrayList<>();
        for (ReplayEvent ev : snapshot) {
            if (ev.seq() > lastSeen) {
                toReplay.add(ev);
            }
        }
        if (toReplay.isEmpty()) return;
        Runnable replay = () -> {
            long latest = lastSeen;
            for (ReplayEvent entry : toReplay) {
                try {
                    listener.onLog(entry.level(), entry.message());
                    latest = entry.seq();
                } catch (RuntimeException ex) {
                    if (LOG.isDebugEnabled()) LOG.debug("replay listener threw: {}", ex.toString());
                }
            }
            if (latest > lastSeen) {
                LAST_SEEN.put(listener, latest);
            }
        };
        if (SwingUtilities.isEventDispatchThread()) {
            replay.run();
        } else {
            SwingUtilities.invokeLater(replay);
        }
    }

    private static void doNotifyListeners(long seq, String level, String m) {
        for (LogListener l : LISTENERS) {
            try {
                l.onLog(level, m);
                if (l instanceof ReplayableLogListener) {
                    LAST_SEEN.put(l, seq);
                }
            } catch (RuntimeException ex) {
                if (LOG.isDebugEnabled()) LOG.debug("listener threw: {}", ex.toString());
            }
        }
    }

    private record ReplayEvent(long seq, String level, String message) {}

    /**
     * Null-safe string conversion.
     *
     * @param s input string
     * @return non-null string
     */
    private static String safe(String s) { return Objects.toString(s, ""); }

    // --------------------------------------------
    // Logback appender that feeds the listener bus
    // --------------------------------------------

    /**
     * Logback appender that forwards non-internal events to the UI listener bus.
     */
    public static final class UiAppender extends AppenderBase<ILoggingEvent> {
        /**
         * Forwards the event to UI listeners, skipping internal logger entries.
         *
         * @param event logback event; {@code null} is ignored
         */
        @Override
        protected void append(ILoggingEvent event) {
            if (event == null) return;

            // Skip messages from our internal logger; those already notify the UI directly.
            if (INTERNAL_LOGGER_NAME.equals(event.getLoggerName())) return;

            // Only forward our package to the UI. Third-party (e.g. org.apache.hc) would flood the panel and cause cap-rebuild loops.
            if (!event.getLoggerName().startsWith("ai.anomalousvectors.tools.burp")) return;

            String level = (event.getLevel() != null) ? event.getLevel().toString() : "INFO";
            String message = event.getFormattedMessage();
            if (message == null) message = "";

            IThrowableProxy tp = event.getThrowableProxy();
            if (tp != null) {
                String exClass = tp.getClassName();
                String exMsg = tp.getMessage();
                message = message + " :: " + (exClass != null ? exClass : "Exception")
                        + (exMsg != null ? (": " + exMsg) : "");
            }

            Logger.emitToListeners(level, message);
        }
    }
}
