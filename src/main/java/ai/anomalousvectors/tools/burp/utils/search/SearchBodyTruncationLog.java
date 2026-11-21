package ai.anomalousvectors.tools.burp.utils.search;

import java.util.concurrent.TimeUnit;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

/** Aggregates search-only body-fitting notices without generating one event per document. */
public final class SearchBodyTruncationLog {
    private static final Counter COUNTER = new Counter();

    private SearchBodyTruncationLog() { }

    /** Records newly truncated documents; callers must first fence their exact export run. */
    public static void record(int count, long budgetBytes) {
        COUNTER.record(count, budgetBytes, TimeUnit.NANOSECONDS.toMillis(System.nanoTime()));
    }

    /** Emits outstanding counts and clears the window after run producers/drains are retired. */
    public static void flushAndClear() { COUNTER.flushAndClear(); }

    static final class Counter {
        private long pending;
        private long budget;
        private long next;
        private boolean started;

        synchronized void record(int count, long budgetBytes, long now) {
            if (count <= 0) return;
            pending += count;
            budget = budgetBytes;
            if (!started || now >= next) {
                emit();
                started = true;
                next = now + 30_000L;
            }
        }

        synchronized void flushAndClear() { emit(); next = 0L; started = false; }

        private void emit() {
            if (pending == 0L) return;
            Logger.logInfoPanelOnly(RuntimeConfig.searchDestinationLogPrefix() + " Prefix-truncated "
                    + pending + " document(s); latest live budget=" + budget
                    + " bytes (search path only; files sink unchanged).");
            pending = 0L;
        }
    }
}
