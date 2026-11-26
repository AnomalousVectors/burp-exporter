package ai.anomalousvectors.tools.burp.utils.concurrent;

import java.util.function.Supplier;

import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;

/**
 * Propagates export-run ownership through queued logs, reporters, and snapshot I/O.
 *
 * <p>Unscoped live and shutdown paths remain allowed. Snapshot flush tasks install their captured
 * token so downstream accounting can reject a late outcome after Stop or a subsequent Start.</p>
 *
 * <p>The context is thread-local and is not inherited by child threads. Its methods are safe to
 * call concurrently because each thread owns its own context value.</p>
 */
public final class ExportRunContext {

    private static final ThreadLocal<ExportRunToken> TOKEN = new ThreadLocal<>();

    private ExportRunContext() {}

    /**
     * Returns the originating context token, or captures the active run for an unscoped caller.
     *
     * <p>A stale installed token is preserved, never rebound to a newer active run.</p>
     *
     * @return originating token, possibly invalid when export is stopped
     */
    public static ExportRunToken captureToken() {
        ExportRunToken token = TOKEN.get();
        return token == null ? RuntimeConfig.currentExportRunToken() : token;
    }

    /**
     * Runs work in its originating context only when that run remains active at entry.
     *
     * <p>Exceptions propagate and the previous context is restored. Downstream I/O and mutable
     * reporter state must still reject stale ownership after a blocking operation returns.</p>
     *
     * @param token token captured before queueing or source acquisition
     * @param work synchronous work to execute; must not be null
     */
    public static void run(ExportRunToken token, Runnable work) {
        if (RuntimeConfig.isExportRunActive(token)) {
            call(token, () -> { work.run(); return null; });
        }
    }

    /**
     * Runs work with {@code token} installed on the current thread.
     *
     * <p>A null token creates an unscoped context. Nested calls restore the previous token in a
     * {@code finally} block. Exceptions from {@code work} propagate unchanged after restoration.</p>
     *
     * @param token captured export-run token
     * @param work work to execute; must not be {@code null}
     * @param <T> result type
     * @return result from {@code work}
     * @throws NullPointerException if {@code work} is {@code null}
     */
    public static <T> T call(ExportRunToken token, Supplier<T> work) {
        ExportRunToken previous = TOKEN.get();
        TOKEN.set(token);
        try {
            return work.get();
        } finally {
            if (previous == null) {
                TOKEN.remove();
            } else {
                TOKEN.set(previous);
            }
        }
    }

    /**
     * Returns whether mutations are allowed for the current asynchronous context.
     *
     * @return {@code true} for unscoped work or a still-active captured run
     */
    public static boolean allowsRunMutation() {
        ExportRunToken token = TOKEN.get();
        return token == null || RuntimeConfig.isExportRunActive(token);
    }

    /**
     * Returns the token installed on the current thread.
     *
     * @return scoped token, or {@code null} for ordinary live/shutdown work
     */
    public static ExportRunToken currentToken() {
        return TOKEN.get();
    }

    /**
     * Returns whether the current thread carries a stale export-run token.
     *
     * @return {@code true} when scoped snapshot work belongs to an invalidated run
     */
    public static boolean isStale() {
        ExportRunToken token = TOKEN.get();
        return token != null && !RuntimeConfig.isExportRunActive(token);
    }
}
