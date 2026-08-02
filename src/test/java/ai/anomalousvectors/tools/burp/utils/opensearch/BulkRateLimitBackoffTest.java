package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportStats;

/**
 * Unit tests for {@link BulkRateLimitBackoff}.
 *
 * <p>Cooldown reset is invoked explicitly from each {@code @Test} method (no
 * {@code @BeforeEach}/{@code @AfterEach} and no test-class constructor hooks) so IDE
 * "never used" hints on JUnit lifecycle entry points do not fire.</p>
 */
class BulkRateLimitBackoffTest {

    private static void resetCooldown() {
        BulkRateLimitBackoff.clear();
        ExportStats.resetForTests();
    }

    @Test
    void isRateLimited_covers429_502_503_and504() {
        resetCooldown();
        assertThat(BulkRateLimitBackoff.isRateLimited(429)).isTrue();
        assertThat(BulkRateLimitBackoff.isRateLimited(502)).isTrue();
        assertThat(BulkRateLimitBackoff.isRateLimited(503)).isTrue();
        assertThat(BulkRateLimitBackoff.isRateLimited(504)).isTrue();
        assertThat(BulkRateLimitBackoff.isRateLimited(500)).isFalse();
        assertThat(BulkRateLimitBackoff.isRateLimited(401)).isFalse();
        assertThat(BulkRateLimitBackoff.isRateLimited(200)).isFalse();
    }

    @Test
    void resolveBackoffMs_defaultsWhenRetryAfterMissing() {
        resetCooldown();
        assertThat(BulkRateLimitBackoff.resolveBackoffMs(null))
                .isEqualTo(BulkRateLimitBackoff.DEFAULT_BACKOFF_MS);
        HttpResponse response = mock(HttpResponse.class);
        when(response.getFirstHeader("Retry-After")).thenReturn(null);
        assertThat(BulkRateLimitBackoff.resolveBackoffMs(response))
                .isEqualTo(BulkRateLimitBackoff.DEFAULT_BACKOFF_MS);
    }

    @Test
    void resolveBackoffMs_honorsRetryAfterSecondsWithinBounds() {
        resetCooldown();
        HttpResponse response = mock(HttpResponse.class);
        when(response.getFirstHeader("Retry-After")).thenReturn(new BasicHeader("Retry-After", "12"));
        assertThat(BulkRateLimitBackoff.resolveBackoffMs(response)).isEqualTo(12_000L);

        when(response.getFirstHeader("Retry-After")).thenReturn(new BasicHeader("Retry-After", "1"));
        assertThat(BulkRateLimitBackoff.resolveBackoffMs(response)).isEqualTo(1_000L);

        when(response.getFirstHeader("Retry-After")).thenReturn(new BasicHeader("Retry-After", "120"));
        assertThat(BulkRateLimitBackoff.resolveBackoffMs(response))
                .isEqualTo(BulkRateLimitBackoff.MAX_BACKOFF_MS);
    }

    @Test
    void resolveBackoffMs_ignoresInvalidRetryAfter() {
        resetCooldown();
        HttpResponse response = mock(HttpResponse.class);
        Header header = new BasicHeader("Retry-After", "not-a-delay");
        when(response.getFirstHeader("Retry-After")).thenReturn(header);
        assertThat(BulkRateLimitBackoff.resolveBackoffMs(response))
                .isEqualTo(BulkRateLimitBackoff.DEFAULT_BACKOFF_MS);
    }

    @Test
    void noteRateLimited_setsSharedCooldownWithoutSleepingInCaller() {
        resetCooldown();
        try {
            HttpResponse response = mock(HttpResponse.class);
            when(response.getFirstHeader("Retry-After")).thenReturn(new BasicHeader("Retry-After", "30"));
            assertThat(BulkRateLimitBackoff.isCoolingDown()).isFalse();

            long started = System.nanoTime();
            BulkRateLimitBackoff.noteRateLimited(429, response, "tool-burp-traffic", "Prepared bulk");
            long elapsedMs = (System.nanoTime() - started) / 1_000_000L;

            assertThat(elapsedMs).isLessThan(1_000L);
            assertThat(BulkRateLimitBackoff.isCoolingDown()).isTrue();
            assertThat(BulkRateLimitBackoff.pressureStreak()).isEqualTo(1L);
            assertThat(BulkRateLimitBackoff.remainingCooldownMs()).isGreaterThan(20_000L);
            assertThat(ExportStats.getCapacityPressureEvents()).isEqualTo(1L);
        } finally {
            resetCooldown();
        }
    }

    @Test
    void noteRateLimited_escalatesCooldownOnRepeatedPressure() {
        resetCooldown();
        try {
            BulkRateLimitBackoff.noteRateLimited(504, null, "tool-burp-traffic", "Prepared bulk");
            assertThat(BulkRateLimitBackoff.pressureStreak()).isEqualTo(1L);

            BulkRateLimitBackoff.noteRateLimited(504, null, "tool-burp-traffic", "Prepared bulk");
            assertThat(BulkRateLimitBackoff.pressureStreak()).isEqualTo(2L);
            assertThat(BulkRateLimitBackoff.isCoolingDown()).isTrue();

            // One success cannot erase an active hard-pressure epoch.
            assertThat(BulkRateLimitBackoff.pressureStreak()).isEqualTo(2L);

            BulkRateLimitBackoff.noteStablePayloadRecovery();
            assertThat(BulkRateLimitBackoff.pressureStreak()).isEqualTo(0L);
        } finally {
            resetCooldown();
        }
    }

    @Test
    void nextEscalatedBackoffMs_followsLadder() {
        resetCooldown();
        try {
            assertThat(BulkRateLimitBackoff.nextEscalatedBackoffMs(null))
                    .isEqualTo(BulkRateLimitBackoff.ESCALATION_MS[0]);
            assertThat(BulkRateLimitBackoff.nextEscalatedBackoffMs(null))
                    .isEqualTo(BulkRateLimitBackoff.ESCALATION_MS[1]);
            assertThat(BulkRateLimitBackoff.nextEscalatedBackoffMs(null))
                    .isEqualTo(BulkRateLimitBackoff.ESCALATION_MS[2]);
            assertThat(BulkRateLimitBackoff.nextEscalatedBackoffMs(null))
                    .isEqualTo(BulkRateLimitBackoff.ESCALATION_MS[3]);
            assertThat(BulkRateLimitBackoff.nextEscalatedBackoffMs(null))
                    .isEqualTo(BulkRateLimitBackoff.ESCALATION_MS[3]);
        } finally {
            resetCooldown();
        }
    }

    @Test
    void noteRateLimited_ignoresNonRateLimitStatus() {
        resetCooldown();
        try {
            BulkRateLimitBackoff.noteRateLimited(500, null, "tool-burp-traffic", "Prepared bulk");
            assertThat(BulkRateLimitBackoff.isCoolingDown()).isFalse();
        } finally {
            resetCooldown();
        }
    }

    @Test
    void noteTransportPressure_setsCooldownForFailedToRespond() {
        resetCooldown();
        try {
            assertThat(BulkRateLimitBackoff.isCoolingDown()).isFalse();
            BulkRateLimitBackoff.noteTransportPressure(
                    "NoHttpResponseException: host failed to respond",
                    "tool-burp-traffic",
                    "Prepared bulk");
            assertThat(BulkRateLimitBackoff.isCoolingDown()).isTrue();
        } finally {
            resetCooldown();
        }
    }

    @Test
    void noteTransportPressure_ignoresUnrelatedFailures() {
        resetCooldown();
        try {
            BulkRateLimitBackoff.noteTransportPressure(
                    "mapper_parsing_exception",
                    "tool-burp-traffic",
                    "Prepared bulk");
            assertThat(BulkRateLimitBackoff.isCoolingDown()).isFalse();
        } finally {
            resetCooldown();
        }
    }

    @Test
    void isItemCapacityPressure_detectsCircuitBreakerAndThrottleReasons() {
        resetCooldown();
        assertThat(BulkRateLimitBackoff.isItemCapacityPressure(
                "circuit_breaking_exception",
                "rejected execution of primary operation [throttled]")).isTrue();
        assertThat(BulkRateLimitBackoff.isItemCapacityPressure(
                "es_rejected_execution_exception", "busy")).isTrue();
        assertThat(BulkRateLimitBackoff.isItemCapacityPressure(
                "mapper_parsing_exception", "failed to parse")).isFalse();
    }

    @Test
    void noteItemCapacityPressure_setsPerIndexCooldownWithoutHardClusterCooldown() {
        resetCooldown();
        try {
            assertThat(BulkRateLimitBackoff.isCoolingDown()).isFalse();
            BulkRateLimitBackoff.noteItemCapacityPressure(
                    "tool-burp-traffic",
                    "Bulk item",
                    "circuit_breaking_exception: rejected execution [throttled]");
            // Mild item pressure must not climb the hard gateway streak or park other indexes.
            assertThat(BulkRateLimitBackoff.isCoolingDown()).isFalse();
            assertThat(BulkRateLimitBackoff.isCoolingDown("tool-burp-traffic")).isTrue();
            assertThat(BulkRateLimitBackoff.isCoolingDown("tool-burp-findings")).isFalse();
            assertThat(BulkRateLimitBackoff.pressureStreak()).isZero();
            assertThat(ExportStats.getCapacityPressureEvents()).isEqualTo(1L);
            assertThat(BulkRateLimitBackoff.remainingCooldownMs("tool-burp-traffic"))
                    .isLessThanOrEqualTo(BulkRateLimitBackoff.MAX_MILD_BACKOFF_MS);
        } finally {
            resetCooldown();
        }
    }

    @Test
    void awaitIfNeeded_respectsStopDrainCap() {
        resetCooldown();
        try {
            BulkRateLimitBackoff.noteRateLimited(429, null, "tool-burp-traffic", "Prepared bulk");
            assertThat(BulkRateLimitBackoff.remainingCooldownMs()).isGreaterThan(2_000L);

            long started = System.nanoTime();
            BulkRateLimitBackoff.awaitIfNeeded(
                    "tool-burp-traffic",
                    BulkRateLimitBackoff.STOP_DRAIN_MAX_COOLDOWN_WAIT_MS);
            long elapsedMs = java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);

            assertThat(elapsedMs)
                    .isGreaterThanOrEqualTo(1_500L)
                    .isLessThan(10_000L);
            assertThat(ExportStats.getPeakCooldownWaitMs())
                    .isLessThanOrEqualTo(BulkRateLimitBackoff.STOP_DRAIN_MAX_COOLDOWN_WAIT_MS);
            assertThat(BulkRateLimitBackoff.isCoolingDown()).isTrue();
        } finally {
            resetCooldown();
        }
    }
}
