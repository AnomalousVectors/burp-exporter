package ai.anomalousvectors.tools.burp.utils.concurrent;

import java.util.function.Supplier;

import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;

/**
 * Propagates an export-run token through asynchronous snapshot I/O.
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
