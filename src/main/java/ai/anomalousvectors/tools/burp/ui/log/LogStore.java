package ai.anomalousvectors.tools.burp.ui.log;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Log model: entries, duplicate compaction, memory cap, and filtered aggregation.
 *
 * <p>Not thread-safe. Caller must invoke on the EDT when the model is used by the Log panel.</p>
 */
public final class LogStore {

    /**
     * Levels from most verbose to most severe: {@code TRACE < DEBUG < INFO < WARN < ERROR}.
     */
    public enum Level { TRACE, DEBUG, INFO, WARN, ERROR;
        /**
         * Parses a case-insensitive level name.
         *
         * @param s level name; null or unrecognized values use {@link #INFO}
         * @return recognized level, or {@link #INFO}
         */
        public static Level fromString(String s) {
            if (s == null) return INFO;
            try { return Level.valueOf(s.trim().toUpperCase(Locale.ROOT)); }
            catch (IllegalArgumentException ex) { return INFO; }
        }
    }

    /** Minimal event; repeats track consecutive duplicates. */
    public static final class Entry implements Serializable {
        @Serial private static final long serialVersionUID = 1L;
        public final LocalDateTime ts;
        public final Level level;
        public final String message;
        private int repeats; // >= 1

        /**
         * Creates a log entry with an initial repeat count of 1.
         *
         * @param ts      timestamp of the event (required)
         * @param level   log level (required)
         * @param message log message (nullable)
         */
        public Entry(LocalDateTime ts, Level level, String message) {
            this.ts = ts;
            this.level = level;
            this.message = message;
            this.repeats = 1;
        }

        /** Number of consecutive duplicates represented by this entry (>= 1). */
        public int repeats() { return repeats; }
    }

    /** Visibility predicate derived from the UI. */
    @FunctionalInterface
    public interface VisibilityFilter {
        /**
         * Tests whether an entry belongs in the rendered view without changing the stored model.
         *
         * @param level entry severity
         * @param message entry text; may be {@code null}
         * @return {@code true} when the entry should be visible
         */
        boolean test(Level level, String message);
    }

    /**
     * Renderer decision for incremental updates.
     *
     * @param kind required rendering action
     * @param entry entry snapshot for append/replace; {@code null} for no change
     */
    public record Decision(Kind kind, Entry entry) {
        /** Incremental rendering actions for one ingested event. */
        public enum Kind { APPEND, REPLACE, NONE }
        /** Returns a decision that leaves the rendered document unchanged. */
        public static Decision none()           { return new Decision(Kind.NONE, null); }
        /**
         * Returns a decision to append an entry snapshot.
         *
         * @param e snapshot to render
         * @return append decision
         */
        public static Decision append(Entry e)  { return new Decision(Kind.APPEND, e); }
        /**
         * Returns a decision to replace the last rendered aggregate.
         *
         * @param e replacement snapshot including its repeat count
         * @return replacement decision
         */
        public static Decision replace(Entry e) { return new Decision(Kind.REPLACE, e); }
    }

    /**
     * Aggregated line for full rebuilds.
     *
     * @param ts timestamp associated with the aggregate
     * @param level shared severity of the aggregated entries
     * @param message shared text; may be {@code null}
     * @param count total occurrences represented by the line
     */
    public record Aggregate(LocalDateTime ts, Level level, String message, int count) {}

    /**
     * Result of a single {@link #trimIfNeeded()} call.
     *
     * <p>{@code removedEntries} is the count of entries removed from the head of the unfiltered
     * model. {@code removedVisible} is the subset of those entries that would have rendered
     * under the current visibility filter. Callers performing incremental view updates need
     * {@code removedVisible} to know whether the visible window changed; the boolean answer
     * loses that information.</p>
     *
     * @param removedEntries number of unfiltered model entries removed
     * @param removedVisible number of rendered aggregates affected by the removed prefix
     */
    public record TrimResult(int removedEntries, int removedVisible) {
        public static final TrimResult NONE = new TrimResult(0, 0);
        /** Returns whether any unfiltered entries were removed. */
        public boolean trimmed() { return removedEntries > 0; }
    }

    private final List<Entry> entries = new ArrayList<>();
    private final int maxEntries;
    private VisibilityFilter filter;

    /**
     * Constructs a bounded log model with a visibility filter.
     *
     * @param maxEntries maximum entries to retain before trimming (> 0)
     * @param filter     predicate used for visibility decisions during renders
     * @throws IllegalArgumentException if {@code maxEntries} is not positive
     * @throws NullPointerException if {@code filter} is {@code null}
     */
    public LogStore(int maxEntries, VisibilityFilter filter) {
        if (maxEntries <= 0) throw new IllegalArgumentException("maxEntries must be > 0");
        this.maxEntries = maxEntries;
        this.filter = Objects.requireNonNull(filter, "filter");
    }

    /**
     * Updates the visibility predicate used during render decisions.
     *
     * @param filter new predicate (required)
     */
    public void setFilter(VisibilityFilter filter) { this.filter = Objects.requireNonNull(filter, "filter"); }

    /**
     * Clears all stored entries.
     */
    public void clear() { entries.clear(); }

    /**
     * Returns the number of stored (unfiltered) entries.
     *
     * @return entry count
     */
    public int size() { return entries.size(); }

    /**
     * Ingests an event and returns an incremental render decision.
     *
     * <p>Consecutive duplicates share one stored entry. The stored model is unfiltered;
     * visibility affects only the returned decision. Call {@link #trimIfNeeded()} separately
     * to enforce the entry cap.</p>
     *
     * @param level event severity
     * @param message event text; may be {@code null}
     * @param now timestamp used for the event or replacement render snapshot
     * @return append, replacement, or no-change decision
     */
    public Decision ingest(Level level, String message, LocalDateTime now) {
        if (!entries.isEmpty()) {
            Entry last = entries.getLast();
            if (last.level == level && Objects.equals(last.message, message)) {
                last.repeats++;
                if (filter.test(level, message)) {
                    Entry snapshot = new Entry(now, level, message);
                    snapshot.repeats = last.repeats;
                    return Decision.replace(snapshot);
                }
                return Decision.none();
            }
        }
        Entry e = new Entry(now, level, message);
        entries.add(e);
        if (filter.test(level, message)) {
            return Decision.append(new Entry(e.ts, e.level, e.message));
        }
        return Decision.none();
    }

    /**
     * Enforces the entry cap.
     *
     * <p>Returns {@link TrimResult#NONE} when no trim was required. Otherwise returns the
     * count of removed (unfiltered) entries and the count of those that would have been
     * visible under the current filter. The visible count lets callers decide whether the
     * rendered document needs to change at all (filter-rejected entries can be trimmed
     * silently with no document edit).</p>
     *
     * @return removed model and visible aggregate counts
     */
    public TrimResult trimIfNeeded() {
        int over = entries.size() - maxEntries;
        if (over <= 0) return TrimResult.NONE;

        int removedVisible = 0;
        // Count visible entries within the to-be-removed prefix; aggregate across consecutive
        // duplicates so the count matches one document line per logical aggregate.
        Level prevLvl = null;
        String prevMsg = null;
        for (int i = 0; i < over; i++) {
            Entry e = entries.get(i);
            if (!filter.test(e.level, e.message)) continue;
            boolean continuation = (e.level == prevLvl && Objects.equals(e.message, prevMsg));
            if (!continuation) {
                removedVisible++;
                prevLvl = e.level;
                prevMsg = e.message;
            }
        }
        entries.subList(0, over).clear();
        return new TrimResult(over, removedVisible);
    }

    /**
     * Builds filtered, aggregated lines for a full repaint.
     *
     * @return newly allocated visible aggregates in model order
     */
    public List<Aggregate> buildVisibleAggregated() {
        List<Aggregate> out = new ArrayList<>();
        LocalDateTime aggTs = null;
        Level aggLvl = null;
        String aggMsg = null;
        int aggCount = 0;

        for (Entry e : entries) {
            if (!filter.test(e.level, e.message)) continue;
            boolean same = (aggLvl == e.level && Objects.equals(aggMsg, e.message));
            if (same) {
                aggCount += e.repeats;
                aggTs = e.ts;
            } else {
                if (aggLvl != null) out.add(new Aggregate(aggTs, aggLvl, aggMsg, aggCount));
                aggTs = e.ts;
                aggLvl = e.level;
                aggMsg = e.message;
                aggCount = e.repeats;
            }
        }
        if (aggLvl != null) out.add(new Aggregate(aggTs, aggLvl, aggMsg, aggCount));
        return out;
    }
}
