package ai.anomalousvectors.tools.burp.sinks;

import java.io.Serial;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import ai.anomalousvectors.tools.burp.utils.ExportAdmissionController;
import ai.anomalousvectors.tools.burp.utils.ExportPressureLogThrottler;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;
import ai.anomalousvectors.tools.burp.utils.concurrent.ExportRunContext;
import ai.anomalousvectors.tools.burp.utils.concurrent.Workers;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

/**
 * Owns byte-accounted live snapshots until preparation and spill admission finish.
 *
 * <p>Burp accessors are read before submission. One bounded worker performs body expansion,
 * serialization and delivery admission; rejection never runs work on a traffic callback. Pending
 * request-only captures share the same reservation pool as queued and in-flight preparation and
 * the prepared delivery queue. Parameter inference stays on the source thread so API provenance
 * is preserved. Each worker mutation is fenced to its captured run.</p>
 */
final class LiveTrafficPreparation {
    private static final ExportPressureLogThrottler PRESSURE =
            new ExportPressureLogThrottler("LiveTrafficPreparation");
    private static final Object LIFECYCLE = new Object();
    private static ThreadPoolExecutor executor;
    private static AtomicInteger outstanding = new AtomicInteger();
    private static RuntimeConfig.ExportRunToken executorToken;
    private static volatile boolean inlineForTests;

    private LiveTrafficPreparation() { }

    static Capture retain(Map<String, Object> document, RuntimeConfig.ExportRunToken token,
            RequestResponseDocBuilder.PreparedTrafficMessage... messages) {
        // Reserve future representation work with the compact capture. Pending requests must not
        // consume the headroom required to finish accepted work and admit it to managed spill.
        long bytes = 5L * estimate(document);
        for (var message : messages) {
            if (message != null) bytes += message.retainedBodyBytes() + message.preparationBytes();
        }
        if (!ExportAdmissionController.tryReserveLiveBytes(bytes)) {
            failed(document, token, "capture_capacity");
            return null;
        }
        return new Capture(document, token, messages, bytes);
    }

    static boolean submit(Capture capture) {
        if (capture == null) return false;
        if (inlineForTests) {
            capture.run();
            return true;
        }
        synchronized (LIFECYCLE) {
            if (!RuntimeConfig.isExportRunActive(capture.token)) {
                capture.close();
                return false;
            }
            if (executor != null && !capture.token.equals(executorToken)) cancelQueued(executor);
            if (executor == null || executor.isShutdown()) {
                executor = new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
                        new ArrayBlockingQueue<>(ExportAdmissionController.MEM_DOC_SAFETY_RAIL), task -> {
                            Thread thread = new Thread(task, "burp-exporter-live-preparation");
                            thread.setDaemon(true);
                            return thread;
                        }, new ThreadPoolExecutor.AbortPolicy());
                executorToken = capture.token;
                outstanding = new AtomicInteger();
            }
            if (!capture.track(outstanding)) return false;
            try {
                executor.execute(capture);
                return true;
            } catch (java.util.concurrent.RejectedExecutionException e) {
                failed(capture.document, capture.token, "preparation_capacity");
                capture.close();
                return false;
            }
        }
    }

    static boolean isIdle() {
        synchronized (LIFECYCLE) {
            // Executor activity is approximate and can be zero while its first task is handed
            // to a worker. Count accepted ownership until admission and allocation cleanup finish.
            return executor == null || outstanding.get() == 0;
        }
    }

    static String status() {
        synchronized (LIFECYCLE) {
            return executor == null ? "0 / 0" : executor.getQueue().size() + " / " + executor.getActiveCount();
        }
    }

    static void stop() {
        ThreadPoolExecutor owner;
        synchronized (LIFECYCLE) {
            owner = executor;
            executor = null;
            executorToken = null;
            if (owner != null) {
                cancelQueued(owner);
            }
        }
        long waitMs = RuntimeConfig.isExportStopping()
                ? Math.min(Workers.DEFAULT_SHUTDOWN_TIMEOUT_MS, RuntimeConfig.remainingExportStopBudgetMs())
                : Workers.DEFAULT_SHUTDOWN_TIMEOUT_MS;
        if (owner != null) Workers.awaitExecutorShutdown(owner, waitMs);
    }

    private static void cancelQueued(ThreadPoolExecutor owner) {
        for (Runnable task : owner.shutdownNow()) {
            if (task instanceof Capture capture) capture.close();
        }
    }

    // Deterministic document-contract tests use the real preparation path on their Mockito scope.
    static void setInlineForTests(boolean enabled) {
        inlineForTests = enabled;
    }

    private static void failed(Map<String, Object> document, RuntimeConfig.ExportRunToken token,
            String reason) {
        ExportRunContext.call(token, () -> {
            if (!RuntimeConfig.isExportRunActive(token)) return null;
            TrafficRouteBucket.Route route = TrafficRouteBucket.fromDocument(document);
            ExportStats.recordTrafficQueueDrop(1);
            ExportStats.recordTrafficDropReason(reason, 1);
            if (RuntimeConfig.isSearchTrafficEnabled()) {
                ExportStats.recordFailure("traffic", 1);
                TrafficRouteBucket.recordDatabaseFailure(route, 1);
            }
            if (RuntimeConfig.isAnyFileExportEnabled()) {
                FileExportStats.recordFailure("traffic", 1);
                TrafficRouteBucket.recordFileFailure(route, 1);
            }
            PRESSURE.record(reason, 1, () -> "liveBytes=" + ExportAdmissionController.liveBytesHeld()
                    + "; Burp traffic continued without waiting; this capture was not exported.");
            return null;
        });
    }

    // Conservative retained-heap estimate without JSON serialization on Burp's callback thread.
    // Captured maps are acyclic exporter-owned values, never arbitrary objects supplied by Burp.
    private static long estimate(Object value) {
        if (value == null) return 0L;
        if (value instanceof String text) return 48L + 2L * text.length();
        if (value instanceof byte[] bytes) return 24L + bytes.length;
        if (value instanceof Map<?, ?> map) {
            long bytes = 64L;
            for (var entry : map.entrySet()) bytes += 48L + estimate(entry.getKey()) + estimate(entry.getValue());
            return bytes;
        }
        if (value instanceof Collection<?> collection) {
            long bytes = 24L + 8L * collection.size();
            for (Object element : collection) bytes += estimate(element);
            return bytes;
        }
        return 32L;
    }

    /** Exactly-once allocation owner, transferred from pending capture to the preparation worker. */
    static final class Capture implements Runnable, AutoCloseable {
        private final Map<String, Object> document;
        private final RuntimeConfig.ExportRunToken token;
        private final RequestResponseDocBuilder.PreparedTrafficMessage[] messages;
        private long bytes;
        private boolean closed;
        private Runnable onClose;
        private AtomicInteger preparationOwner;

        private Capture(Map<String, Object> document, RuntimeConfig.ExportRunToken token,
                RequestResponseDocBuilder.PreparedTrafficMessage[] messages, long bytes) {
            this.document = document;
            this.token = token;
            this.messages = messages.clone();
            this.bytes = bytes;
        }

        /** Completes owned representations on the preparation worker, fenced to the captured run. */
        @Override
        public void run() {
            try {
                ExportRunContext.call(token, () -> {
                    if (!RuntimeConfig.isExportRunActive(token)) return null;
                    // The shared codec guard bounds transient decoded bytes. Reserve the actual
                    // successful expansion before creating decoded Base64/text representations.
                    for (var message : messages) if (message != null) message.complete(this::reserveDecodedBytes);
                    TrafficExportQueue.offerForRun(document, token);
                    return null;
                });
            } catch (CapacityException e) {
                failed(document, token, "preparation_capacity");
            } catch (RuntimeException e) {
                failed(document, token, "preparation_failed");
            } finally {
                close();
            }
        }

        private synchronized boolean expandReservation(long extra) {
            if (closed || !ExportAdmissionController.tryReserveLiveBytes(extra)) return false;
            bytes += extra;
            return true;
        }

        private synchronized boolean track(AtomicInteger owner) {
            if (closed || preparationOwner != null) return false;
            preparationOwner = owner;
            owner.incrementAndGet();
            return true;
        }

        private void reserveDecodedBytes(long extra) {
            if (!expandReservation(extra)) throw new CapacityException();
        }

        /** Releases this capture's allocation once; completion hooks run without the capture lock. */
        @Override
        public void close() {
            long released;
            Runnable completion;
            AtomicInteger owner;
            synchronized (this) {
                if (closed) return;
                closed = true;
                released = bytes;
                completion = onClose;
                onClose = null;
                owner = preparationOwner;
                preparationOwner = null;
            }
            ExportAdmissionController.releaseLiveBytes(released);
            try {
                if (completion != null) completion.run();
            } finally {
                if (owner != null) owner.decrementAndGet();
            }
        }

        void whenClosed(Runnable completion) {
            synchronized (this) {
                if (!closed) {
                    onClose = completion;
                    return;
                }
            }
            completion.run();
        }
    }

    static final class CapacityException extends RuntimeException {
        @Serial private static final long serialVersionUID = 1L;
    }
}
