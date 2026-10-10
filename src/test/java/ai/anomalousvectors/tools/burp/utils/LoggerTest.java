package ai.anomalousvectors.tools.burp.utils;

import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

import ai.anomalousvectors.tools.burp.testutils.Reflect;
import burp.api.montoya.logging.Logging;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class LoggerTest {

    @Test
    void registerListener_receivesInfoAndErrorLogs() throws Exception {
        try {
            List<String> seen = new ArrayList<>();
            Logger.LogListener listener = (level, msg) -> seen.add(level + ":" + msg);

            Logger.registerListener(listener);

            // Direct listeners run synchronously on the originating thread.
            SwingUtilities.invokeAndWait(() -> {
                Logger.logInfo("hello");
                Logger.logError("world");
            });

            assertThat(seen).hasSize(2);
            assertThat(seen.get(0)).startsWith("INFO:").contains("hello");
            assertThat(seen.get(1)).startsWith("ERROR:").contains("world");
        } finally {
            Logger.resetState();
        }
    }

    @Test
    void registerListener_receivesPanelOnlyWarnLogs() throws Exception {
        try {
            List<String> seen = new ArrayList<>();
            Logger.LogListener listener = (level, msg) -> seen.add(level + ":" + msg);

            Logger.registerListener(listener);

            SwingUtilities.invokeAndWait(() -> Logger.logWarnPanelOnly("recoverable-warning"));

            assertThat(seen).hasSize(1);
            assertThat(seen.getFirst()).startsWith("WARN:").contains("recoverable-warning");
        } finally {
            Logger.resetState();
        }
    }

    @Test
    void logInfoPanelAndBurp_usesSeparateTextForBurpOutputAndLogTab() throws Exception {
        try {
            Logging burpLogging = mock(Logging.class);
            Logger.initialize(burpLogging);
            List<String> panel = new ArrayList<>();
            Logger.registerListener((level, msg) -> panel.add(msg));

            String burpLine = "Burp Exporter v1 initialized successfully.";
            String panelLine = "[Exporter] " + burpLine;
            SwingUtilities.invokeAndWait(() -> Logger.logInfoPanelAndBurp(panelLine, burpLine));

            verify(burpLogging).logToOutput(burpLine);
            assertThat(panel).containsExactly(panelLine);
        } finally {
            Logger.resetState();
        }
    }

    @Test
    void generalRuntimeMethods_doNotWriteToBurpConsole() throws Exception {
        try {
            Logging burpLogging = mock(Logging.class);
            Logger.initialize(burpLogging);
            List<String> panel = new ArrayList<>();
            Logger.registerListener((level, msg) -> panel.add(level + ":" + msg));

            SwingUtilities.invokeAndWait(() -> {
                Logger.logInfo("runtime-info");
                Logger.logWarn("runtime-warn");
                Logger.logError("runtime-error");
                Logger.logError("runtime-exception", new IllegalStateException("boom"));
            });

            verifyNoInteractions(burpLogging);
            assertThat(panel)
                    .anyMatch(line -> line.equals("INFO:runtime-info"))
                    .anyMatch(line -> line.equals("WARN:runtime-warn"))
                    .anyMatch(line -> line.equals("ERROR:runtime-error"))
                    .anyMatch(line -> line.contains("ERROR:runtime-exception")
                            && line.contains("IllegalStateException"));
        } finally {
            Logger.resetState();
        }
    }

    @Test
    void lifecycleError_usesBurpErrorConsoleAndPanelText() throws Exception {
        try {
            Logging burpLogging = mock(Logging.class);
            Logger.initialize(burpLogging);
            List<String> panel = new ArrayList<>();
            Logger.registerListener((level, msg) -> panel.add(msg));
            IllegalStateException failure = new IllegalStateException("boom");

            SwingUtilities.invokeAndWait(() -> Logger.logErrorPanelAndBurp(
                    "[Exporter] initialization failed",
                    "Burp Exporter initialization failed",
                    failure));

            verify(burpLogging).logToError(org.mockito.ArgumentMatchers.<String>argThat(
                    line -> line.contains("Burp Exporter initialization failed")
                            && line.contains("IllegalStateException")));
            assertThat(panel)
                    .singleElement()
                    .asString()
                    .contains("[Exporter] initialization failed")
                    .contains("IllegalStateException")
                    .containsOnlyOnce("boom");
        } finally {
            Logger.resetState();
        }
    }

    /**
     * ReplayableLogListener receives buffered messages when registered (e.g. LogPanel after tab switch).
     * Plain LogListener does not receive replay, so tests and other listeners are not spammed.
     */
    @Test
    void replayableListener_receivesReplay_plainListener_doesNot() throws Exception {
        try {
            // Put a message in the buffer
            SwingUtilities.invokeAndWait(() -> Logger.logInfo("replay-this"));

            List<String> replaySeen = new ArrayList<>();
            Logger.ReplayableLogListener replayable = (level, msg) -> replaySeen.add(level + ":" + msg);
            Logger.registerListener(replayable);
            SwingUtilities.invokeAndWait(() -> { /* drain EDT so replay runnable runs */ });

            assertThat(replaySeen).anyMatch(s -> s.contains("replay-this"));
            Logger.unregisterListener(replayable);

            // Plain listener: register after buffer has content; should not receive replay
            List<String> plainSeen = new ArrayList<>();
            Logger.LogListener plain = (level, msg) -> plainSeen.add(level + ":" + msg);
            Logger.registerListener(plain);
            SwingUtilities.invokeAndWait(() -> {});
            assertThat(plainSeen).isEmpty();
            SwingUtilities.invokeAndWait(() -> Logger.logInfo("direct-only"));
            assertThat(plainSeen).hasSize(1).allMatch(s -> s.contains("direct-only"));
            Logger.unregisterListener(plain);
        } finally {
            Logger.resetState();
        }
    }

    @Test
    void replayBuffer_isBounded_andPreservesOrder() throws Exception {
        try {
            int cap = replayBufferSize();
            String prefix = "cap-test-";

            // Overwrite any previous buffer contents with our messages only.
            SwingUtilities.invokeAndWait(() -> {
                for (int i = 0; i < cap * 2; i++) {
                    Logger.logInfo(prefix + i);
                }
            });

            List<String> replaySeen = new ArrayList<>();
            Logger.ReplayableLogListener replayable = (level, msg) -> {
                if (msg != null && msg.startsWith(prefix)) {
                    replaySeen.add(msg);
                }
            };

            Logger.registerListener(replayable);
            drainEdtUntil(() -> replaySeen.size() == cap);

            assertThat(replaySeen).hasSize(cap);
            assertThat(replaySeen.get(0)).contains(prefix + cap);
            assertThat(replaySeen.get(replaySeen.size() - 1)).contains(prefix + (cap * 2 - 1));

            Logger.unregisterListener(replayable);
        } finally {
            Logger.resetState();
        }
    }

    @Test
    void registerListener_isIdempotent_noDuplicateDelivery() throws Exception {
        try {
            List<String> seen = new ArrayList<>();
            Logger.LogListener listener = (level, msg) -> seen.add(level + ":" + msg);

            Logger.registerListener(listener);
            Logger.registerListener(listener); // should be ignored

            SwingUtilities.invokeAndWait(() -> Logger.logInfo("dedupe-check"));

            assertThat(seen).hasSize(1);
            assertThat(seen.get(0)).contains("dedupe-check");

            Logger.unregisterListener(listener);
        } finally {
            Logger.resetState();
        }
    }

    @Test
    void replayableListener_reRegister_onlyReplaysNewMessages() throws Exception {
        try {
            String prefix = "replay-reg-";
            List<String> seen = new ArrayList<>();
            Logger.ReplayableLogListener listener = (level, msg) -> {
                if (msg != null && msg.startsWith(prefix)) {
                    seen.add(msg);
                }
            };

            SwingUtilities.invokeAndWait(() -> Logger.logInfo(prefix + "one"));
            Logger.registerListener(listener);
            SwingUtilities.invokeAndWait(() -> { /* drain EDT for replay */ });

            int sizeAfterFirst = seen.size();
            assertThat(sizeAfterFirst).isGreaterThanOrEqualTo(1);

            Logger.unregisterListener(listener);
            Logger.registerListener(listener);
            SwingUtilities.invokeAndWait(() -> { /* drain EDT for replay */ });

            assertThat(seen).hasSize(sizeAfterFirst);

            SwingUtilities.invokeAndWait(() -> Logger.logInfo(prefix + "two"));
            drainEdtUntil(() -> seen.stream().anyMatch(s -> s.equals(prefix + "two")));
            assertThat(seen).anyMatch(s -> s.equals(prefix + "two"));

            Logger.unregisterListener(listener);
        } finally {
            Logger.resetState();
        }
    }

    @Test
    void resetState_clearsListenersReplayBufferAndSequence() throws Exception {
        try {
            List<String> directSeen = new ArrayList<>();
            Logger.LogListener direct = (level, msg) -> directSeen.add(level + ":" + msg);

            Logger.registerListener(direct);
            SwingUtilities.invokeAndWait(() -> Logger.logInfo("before-reset"));
            assertThat(directSeen).hasSize(1);

            Logger.resetState();

            assertThat(Reflect.getStaticList(Logger.class, "LISTENERS")).isEmpty();
            assertThat(Reflect.getStaticList(Logger.class, "REPLAY_BUFFER")).isEmpty();
            assertThat(((java.util.concurrent.atomic.AtomicLong) Reflect.getStatic(Logger.class, "REPLAY_SEQ")).get())
                    .isZero();

            List<String> replaySeen = new ArrayList<>();
            Logger.ReplayableLogListener replayable = (level, msg) -> replaySeen.add(level + ":" + msg);
            Logger.registerListener(replayable);
            SwingUtilities.invokeAndWait(() -> { /* drain EDT for any replay */ });

            assertThat(replaySeen).isEmpty();

            SwingUtilities.invokeAndWait(() -> Logger.logInfo("after-reset"));
            drainEdtUntil(() -> replaySeen.size() == 1);
            assertThat(directSeen).hasSize(1);
            assertThat(replaySeen).hasSize(1).allMatch(s -> s.contains("after-reset"));
        } finally {
            Logger.resetState();
        }
    }

    @Test
    void uiBurst_isBoundedOrderedAndTimeSliced_whileDirectDeliveryRemainsLossless() throws Exception {
        try {
            int capacity = Reflect.getStaticInt(Logger.class, "UI_DELIVERY_CAPACITY");
            int total = capacity + 1000;
            String prefix = "ui-burst-";
            AtomicInteger directCount = new AtomicInteger();
            List<String> uiSeen = new ArrayList<>();
            AtomicInteger seenAtEdtSentinel = new AtomicInteger(-1);
            Logger.LogListener direct = (level, message) -> {
                if (message.startsWith(prefix)) {
                    directCount.incrementAndGet();
                }
            };
            Logger.ReplayableLogListener ui = (level, message) -> {
                assertThat(SwingUtilities.isEventDispatchThread()).isTrue();
                if (message.startsWith(prefix)) {
                    uiSeen.add(message);
                }
            };
            Logger.registerListener(direct);
            Logger.registerListener(ui);

            SwingUtilities.invokeAndWait(() -> {
                for (int i = 0; i < total; i++) {
                    Logger.emitToListeners("INFO", prefix + i);
                }
                SwingUtilities.invokeLater(() -> seenAtEdtSentinel.set(uiSeen.size()));
            });

            drainEdtUntil(() -> seenAtEdtSentinel.get() >= 0);
            assertThat(directCount).hasValue(total);
            assertThat(seenAtEdtSentinel.get()).isBetween(1, capacity - 1);

            drainEdtUntil(() -> uiSeen.size() == capacity);
            assertThat(uiSeen)
                    .hasSize(capacity)
                    .startsWith(prefix + (total - capacity))
                    .endsWith(prefix + (total - 1));
        } finally {
            Logger.resetState();
        }
    }

    @Test
    void directListener_runsSynchronouslyOnOriginatingThread() {
        try {
            AtomicReference<Thread> callbackThread = new AtomicReference<>();
            Logger.registerListener((level, message) -> callbackThread.set(Thread.currentThread()));
            Thread origin = Thread.currentThread();

            Logger.emitToListeners("INFO", "direct-thread");

            assertThat(callbackThread).hasValue(origin);
        } finally {
            Logger.resetState();
        }
    }

    @Test
    void resetState_discardsQueuedUiDeliveriesFromPriorGeneration() throws Exception {
        try {
            List<String> stale = new ArrayList<>();
            List<String> current = new ArrayList<>();
            Logger.ReplayableLogListener prior = (level, message) -> stale.add(message);
            Logger.ReplayableLogListener replacement = (level, message) -> current.add(message);
            Logger.registerListener(prior);

            SwingUtilities.invokeAndWait(() -> {
                Logger.emitToListeners("INFO", "prior-generation");
                Logger.resetState();
                Logger.registerListener(replacement);
                Logger.emitToListeners("INFO", "current-generation");
            });

            drainEdtUntil(() -> current.size() == 1);
            assertThat(stale).isEmpty();
            assertThat(current).containsExactly("current-generation");
        } finally {
            Logger.resetState();
        }
    }

    @Test
    void discardPendingUiEvents_preservesOnlyEventsEmittedAfterClearBoundary() throws Exception {
        try {
            List<String> seen = new ArrayList<>();
            Logger.ReplayableLogListener ui = (level, message) -> seen.add(message);
            Logger.registerListener(ui);

            SwingUtilities.invokeAndWait(() -> {
                for (int i = 0; i < 1000; i++) {
                    Logger.emitToListeners("INFO", "before-clear-" + i);
                }
                Logger.discardPendingUiEvents(ui);
                Logger.emitToListeners("INFO", "after-clear");
            });

            drainEdtUntil(() -> seen.size() == 1);
            assertThat(seen).containsExactly("after-clear");
        } finally {
            Logger.resetState();
        }
    }

    private static void drainEdtUntil(BooleanSupplier condition) throws Exception {
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(10L);
        while (!condition.getAsBoolean() && System.nanoTime() < deadline) {
            SwingUtilities.invokeAndWait(() -> { /* allow one queued EDT turn */ });
            Thread.onSpinWait();
        }
        assertThat(condition.getAsBoolean()).isTrue();
    }

    private static int replayBufferSize() {
        try {
            return Reflect.getStaticInt(Logger.class, "REPLAY_BUFFER_SIZE");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
