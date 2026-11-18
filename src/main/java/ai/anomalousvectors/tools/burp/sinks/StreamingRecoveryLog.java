package ai.anomalousvectors.tools.burp.sinks;

import java.util.EnumMap;
import java.util.Map;
import java.util.function.LongSupplier;

import ai.anomalousvectors.tools.burp.utils.Logger;

/** Run-owned, payload-free streaming diagnostics with independent warning throttles. */
final class StreamingRecoveryLog {
    enum Reason { INITIALIZATION, HISTORY, OBSERVATION, CAPACITY }

    private static final long INTERVAL_MS = 30_000L;
    private final LongSupplier clock;
    private final Map<Reason, Warning> warnings = new EnumMap<>(Reason.class);
    private long nextActivity;
    private long candidates;
    private long attempts;
    private long admitted;
    private long unchanged;
    private boolean capacity;

    StreamingRecoveryLog(LongSupplier clock) {
        this.clock = clock;
        nextActivity = clock.getAsLong() + INTERVAL_MS;
    }

    synchronized void candidate() { candidates++; }
    synchronized void snapshot(boolean accepted) { attempts++; if (accepted) admitted++; }
    synchronized void unchanged() { unchanged++; }

    synchronized void warn(Reason reason, String message) {
        long now = clock.getAsLong();
        Warning previous = warnings.get(reason);
        if (previous != null && now - previous.last < INTERVAL_MS) {
            previous.suppressed++;
            return;
        }
        long suppressed = previous == null ? 0L : previous.suppressed;
        Logger.logWarnPanelOnly("[StreamingRecovery] " + message + ". repeated_events=" + suppressed + ".");
        warnings.put(reason, new Warning(now));
    }

    synchronized void capacity(boolean pressured) {
        if (pressured) {
            warn(Reason.CAPACITY, "Tracking capacity reached; some exchanges may not be observed");
        } else if (capacity) {
            Warning previous = warnings.remove(Reason.CAPACITY);
            Logger.logInfoPanelOnly("[StreamingRecovery] Tracking capacity pressure cleared; "
                    + "repeated_events=" + (previous == null ? 0L : previous.suppressed) + ".");
        }
        capacity = pressured;
    }

    synchronized void flush(boolean last) {
        long now = clock.getAsLong();
        if (!last && now < nextActivity) return;
        if (candidates + attempts + unchanged > 0L) {
            Logger.logDebug("[StreamingRecovery] Activity: candidates=" + candidates + ", attempts="
                    + attempts + ", admitted=" + admitted + ", unchanged=" + unchanged
                    + ", per_item_events_suppressed=" + (candidates + attempts + unchanged) + ".");
        }
        candidates = 0L;
        attempts = 0L;
        admitted = 0L;
        unchanged = 0L;
        nextActivity = now + INTERVAL_MS;
        if (last) {
            warnings.forEach((reason, warning) -> {
                if (warning.suppressed > 0L) Logger.logWarnPanelOnly(
                        "[StreamingRecovery] Repeated " + reason.name().toLowerCase(java.util.Locale.ROOT)
                                + " events suppressed=" + warning.suppressed + ".");
            });
            warnings.clear();
        }
    }

    private static final class Warning {
        private final long last;
        private long suppressed;
        private Warning(long last) { this.last = last; }
    }
}
