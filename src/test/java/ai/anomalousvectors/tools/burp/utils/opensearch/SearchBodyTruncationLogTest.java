package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.Logger;

/** Checks fitting-event aggregation, final counts and clean reuse between runs. */
class SearchBodyTruncationLogTest {
    @Test
    void frequentFittingHasBoundedEventsAndFlushRetainsEveryCount() {
        List<String> events = new ArrayList<>();
        Logger.LogListener listener = (level, message) -> events.add(message);
        Logger.registerListener(listener);
        try {
            SearchBodyTruncationLog.Counter counter = new SearchBodyTruncationLog.Counter();
            for (int i=0; i<1_000; i++) counter.record(1, 1_048_576L, 1_000L);
            assertThat(events).hasSize(1);
            counter.flushAndClear();
            assertThat(events).hasSize(2);
            assertThat(events.getLast()).contains("999 document(s)", "files sink unchanged");
            counter.flushAndClear();
            assertThat(events).hasSize(2);
            counter.record(2, 2_000L, 1_001L);
            assertThat(events.getLast()).contains("2 document(s)");
        } finally { Logger.unregisterListener(listener); }
    }
}
