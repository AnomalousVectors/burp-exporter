package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.Logger;

/** Verifies bounded event generation rather than only display filtering. */
class StreamingRecoveryLogTest {
    @Test
    void activityIsAggregatedAndDistinctWarningsCannotSuppressEachOther() {
        List<String> events = new ArrayList<>();
        Logger.LogListener listener = (level, message) -> events.add(level + ":" + message);
        Logger.registerListener(listener);
        try {
            AtomicLong now = new AtomicLong(1_000L);
            StreamingRecoveryLog log = new StreamingRecoveryLog(now::get);
            for (int i=0; i<10_000; i++) { log.candidate(); log.snapshot(true); log.unchanged(); }
            log.flush(false);
            assertThat(events).isEmpty();
            log.warn(StreamingRecoveryLog.Reason.HISTORY, "history read failed");
            log.warn(StreamingRecoveryLog.Reason.OBSERVATION, "body read failed");
            log.warn(StreamingRecoveryLog.Reason.HISTORY, "history read failed");
            assertThat(events).hasSize(2);
            now.addAndGet(30_000L);
            log.flush(false);
            assertThat(events).hasSize(3);
            assertThat(events.getLast()).contains("admitted=10000", "per_item_events_suppressed=30000");
            log.capacity(true);
            log.capacity(true);
            log.capacity(false);
            int count = events.size();
            now.addAndGet(30_000L);
            log.capacity(false);
            assertThat(events).hasSize(count);
            assertThat(events.getLast()).contains("pressure cleared", "repeated_events=1");
            log.flush(true);
            assertThat(events.getLast()).contains("history events suppressed=1");
        } finally { Logger.unregisterListener(listener); }
    }
}
