package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

/** Deterministic tests for aggregate search bulk offered-load control. */
class OfferedLoadGovernorTest {

    @Test
    void reservationsBoundRequestStartsAndBytesOverMonotonicTime() {
        Fixture fixture = new Fixture();
        OfferedLoadGovernor governor = fixture.governor();

        try (OfferedLoadGovernor.Permit ignored =
                governor.acquirePermit(OfferedLoadGovernor.INITIAL_BYTES_PER_SECOND)) {
            assertThat(fixture.now.get()).isZero();
        }
        try (OfferedLoadGovernor.Permit ignored = governor.acquirePermit(64L * 1024L)) {
            assertThat(fixture.now.get()).isEqualTo(TimeUnit.SECONDS.toNanos(1L));
        }
    }

    @Test
    void hardPressureMultiplicativelyReducesRateAndSerializes() {
        Fixture fixture = new Fixture();
        OfferedLoadGovernor governor = fixture.governor();

        governor.observeFullPayloadSuccess(true, false);
        fixture.advance(OfferedLoadGovernor.STABLE_GROWTH_WINDOW_NANOS);
        governor.observeFullPayloadSuccess(true, false);
        assertThat(governor.bytesPerSecondValue())
                .isGreaterThan(OfferedLoadGovernor.INITIAL_BYTES_PER_SECOND);

        long before = governor.bytesPerSecondValue();
        governor.observeHardPressure();

        assertThat(governor.bytesPerSecondValue())
                .isEqualTo(Math.max(OfferedLoadGovernor.MIN_BYTES_PER_SECOND, before / 2L));
        assertThat(governor.maxInFlightValue()).isEqualTo(1);
        assertThat(governor.recoveryStreakValue()).isZero();
    }

    @Test
    void recoveryRequiresEightSpacedFullPayloadSuccessesThenWindowedGrowth() {
        Fixture fixture = new Fixture();
        OfferedLoadGovernor governor = fixture.governor();
        governor.observeHardPressure();
        long pressuredRate = governor.bytesPerSecondValue();

        for (int i = 1; i < OfferedLoadGovernor.RECOVERY_SUCCESS_STREAK; i++) {
            fixture.advance(OfferedLoadGovernor.MIN_SUCCESS_SPACING_NANOS);
            assertThat(governor.observeFullPayloadSuccess(true, true).recoveryQualified())
                    .isFalse();
        }
        fixture.advance(OfferedLoadGovernor.MIN_SUCCESS_SPACING_NANOS);
        assertThat(governor.observeFullPayloadSuccess(true, true).recoveryQualified()).isTrue();
        assertThat(governor.bytesPerSecondValue()).isEqualTo(pressuredRate);

        governor.completeStableRecovery();
        fixture.advance(OfferedLoadGovernor.STABLE_GROWTH_WINDOW_NANOS);
        governor.observeFullPayloadSuccess(true, false);
        assertThat(governor.bytesPerSecondValue()).isGreaterThan(pressuredRate);
        assertThat(governor.growthGenerationForTests()).isEqualTo(1L);
    }

    @Test
    void probeOrExporterSuccessCannotClearRecoveryState() {
        Fixture fixture = new Fixture();
        OfferedLoadGovernor governor = fixture.governor();
        governor.observeHardPressure();

        for (int i = 0; i < OfferedLoadGovernor.RECOVERY_SUCCESS_STREAK * 2; i++) {
            fixture.advance(OfferedLoadGovernor.MIN_SUCCESS_SPACING_NANOS);
            assertThat(governor.observeFullPayloadSuccess(false, true).recoveryQualified())
                    .isFalse();
        }

        assertThat(governor.recoveryStreakValue()).isZero();
    }

    @Test
    void rateDoesNotGrowWhileOutageOrCooldownIsActive() {
        Fixture fixture = new Fixture();
        OfferedLoadGovernor governor = fixture.governor();
        long initial = governor.bytesPerSecondValue();

        for (int i = 0; i < 4; i++) {
            fixture.advance(OfferedLoadGovernor.STABLE_GROWTH_WINDOW_NANOS);
            governor.observeFullPayloadSuccess(true, true);
        }
        assertThat(governor.bytesPerSecondValue()).isEqualTo(initial);

        fixture.cooldown.set(TimeUnit.SECONDS.toNanos(5L));
        fixture.advance(OfferedLoadGovernor.STABLE_GROWTH_WINDOW_NANOS);
        governor.observeFullPayloadSuccess(true, false);
        assertThat(governor.bytesPerSecondValue()).isEqualTo(initial);
    }

    @Test
    void partialSuccessResetsRecoveryStreak() {
        Fixture fixture = new Fixture();
        OfferedLoadGovernor governor = fixture.governor();
        for (int i = 0; i < 4; i++) {
            fixture.advance(OfferedLoadGovernor.MIN_SUCCESS_SPACING_NANOS);
            governor.observeFullPayloadSuccess(true, true);
        }

        governor.observePartialOrFailure();

        assertThat(governor.recoveryStreakValue()).isZero();
    }

    @Test
    void resetForStartRestoresConservativeDefaults() {
        Fixture fixture = new Fixture();
        OfferedLoadGovernor governor = fixture.governor();
        governor.observeHardPressure();
        governor.observeHardPressure();

        governor.resetState(fixture.now.get());

        assertThat(governor.bytesPerSecondValue())
                .isEqualTo(OfferedLoadGovernor.INITIAL_BYTES_PER_SECOND);
        assertThat(governor.maxInFlightValue()).isEqualTo(1);
        assertThat(governor.recoveryStreakValue()).isZero();
        assertThat(governor.growthGenerationForTests()).isZero();
    }

    @Test
    void stopBypassesRateAndInFlightWaitsPromptly() {
        Fixture fixture = new Fixture();
        OfferedLoadGovernor governor = fixture.governor();
        OfferedLoadGovernor.Permit first =
                governor.acquirePermit(OfferedLoadGovernor.INITIAL_BYTES_PER_SECOND);
        fixture.stop.set(true);
        long before = fixture.now.get();

        try (OfferedLoadGovernor.Permit ignored =
                governor.acquirePermit(OfferedLoadGovernor.INITIAL_BYTES_PER_SECOND)) {
            assertThat(fixture.now.get()).isEqualTo(before);
            assertThat(fixture.parkCalls.get()).isZero();
        } finally {
            first.close();
        }
    }

    @Test
    void permitFromPriorStartCannotReleaseNextStartInFlightReservation() {
        Fixture fixture = new Fixture();
        OfferedLoadGovernor governor = fixture.governor();
        OfferedLoadGovernor.Permit oldPermit = governor.acquirePermit(1L);
        governor.resetState(fixture.now.get());
        OfferedLoadGovernor.Permit newPermit = governor.acquirePermit(1L);

        oldPermit.close();

        assertThat(governor.inFlightValueForTests()).isEqualTo(1);
        newPermit.close();
        assertThat(governor.inFlightValueForTests()).isZero();
    }

    private static final class Fixture {
        private final AtomicLong now = new AtomicLong();
        private final AtomicLong cooldown = new AtomicLong();
        private final AtomicBoolean stop = new AtomicBoolean();
        private final AtomicLong parkCalls = new AtomicLong();

        private OfferedLoadGovernor governor() {
            return OfferedLoadGovernor.createForTests(
                    now::get,
                    nanos -> {
                        parkCalls.incrementAndGet();
                        now.addAndGet(nanos);
                    },
                    stop::get,
                    cooldown::get);
        }

        private void advance(long nanos) {
            now.addAndGet(nanos);
        }
    }
}
