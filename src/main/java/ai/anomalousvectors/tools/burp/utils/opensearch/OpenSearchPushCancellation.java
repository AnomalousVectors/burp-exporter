package ai.anomalousvectors.tools.burp.utils.opensearch;

import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.concurrent.ExportRunContext;

/**
 * Classifies OpenSearch push outcomes that are expected when the user stops export or pooled
 * clients are torn down, so they are not surfaced as destination failures.
 *
 * <p>Stateless and safe for concurrent callers.</p>
 */
public final class OpenSearchPushCancellation {

    private OpenSearchPushCancellation() {}

    /**
     * Returns {@code true} when export is no longer running (user Stop or lifecycle reset).
     *
     * @return {@code true} when the active run has stopped or the caller's run context is stale
     */
    public static boolean isUserStopInProgress() {
        return !RuntimeConfig.isExportRunning() || ExportRunContext.isStale();
    }

    /**
     * Returns {@code true} when a push failure should not increment stats, set last-error text,
     * or emit panel warnings — typically because Stop was clicked or connectors are shutting down.
     *
     * <p>Stats accounting still suppresses while export is stopped so Stop-drain retries do not
     * double-count failures already recorded when the documents were first queued. Logging uses
     * {@link #shouldSuppressPushFailure(Throwable)} separately so real HTTP/transport causes are
     * not rewritten as {@code export stopped}.</p>
     *
     * @return {@code true} when failure accounting belongs to a stopped or stale run
     */
    public static boolean shouldSuppressFailureAccounting() {
        return isUserStopInProgress();
    }

    /**
     * Returns {@code true} when {@code throwable} matches common Stop/teardown interruption causes.
     *
     * @param throwable failure from an in-flight push; {@code null} is never treated as benign
     * @return {@code true} for interrupted I/O or connector shutdown messages
     */
    public static boolean isBenignShutdownCause(Throwable throwable) {
        if (throwable == null) {
            return false;
        }
        for (Throwable current = throwable; current != null; current = current.getCause()) {
            if (current instanceof InterruptedException) {
                return true;
            }
            String message = current.getMessage();
            if (message != null && matchesBenignShutdownMessage(message)) {
                return true;
            }
        }
        return Thread.currentThread().isInterrupted() && isUserStopInProgress();
    }

    /**
     * Returns {@code true} when a push exception should be logged quietly (TRACE) because the
     * failure itself is a benign connector teardown cause.
     *
     * <p>Does <b>not</b> suppress merely because {@link #isUserStopInProgress()} is true. Stop
     * drain and late HTTP errors (429, 502, failed-to-respond) must keep their real causes in the
     * log so operators can diagnose without guessing.</p>
     *
     * @param throwable push failure; may be {@code null}
     * @return {@code true} to log at TRACE and skip failure-style WARN lines
     */
    public static boolean shouldSuppressPushFailure(Throwable throwable) {
        return isBenignShutdownCause(throwable);
    }

    /**
     * Returns a short description for TRACE logs when a bulk/document push was cancelled during Stop.
     *
     * <p>Exception messages are returned verbatim and are not secret-redacted. Callers must use the
     * result only when the transport exception cannot contain credentials or request bodies.</p>
     *
     * @param throwable push failure; may be {@code null}
     * @return human-readable suffix (never {@code null})
     */
    public static String cancelledPushLogSuffix(Throwable throwable) {
        String message = rootMessage(throwable);
        if (!message.isBlank()) {
            return message;
        }
        if (isUserStopInProgress()) {
            return "export stopped";
        }
        return "connector shut down";
    }

    private static String rootMessage(Throwable throwable) {
        if (throwable == null) {
            return "";
        }
        Throwable root = throwable;
        while (root.getCause() != null) {
            root = root.getCause();
        }
        String message = root.getMessage();
        return message == null ? root.getClass().getSimpleName() : message;
    }

    private static boolean matchesBenignShutdownMessage(String message) {
        String lower = message.toLowerCase(java.util.Locale.ROOT);
        return lower.contains("interrupted")
                || lower.contains("i/o reactor has been shut down")
                || lower.contains("connection is closed")
                || lower.contains("connection pool shut down")
                || lower.contains("pool shut down")
                || lower.contains("socket closed");
    }
}
