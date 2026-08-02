package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import ai.anomalousvectors.tools.burp.utils.concurrent.ExportRunContext;

/**
 * Single shared controller for batch size (doc count per search database bulk request).
 * Grows on success (with smoothing) and shrinks on failure; used by all reporters
 * and {@link IndexingRetryCoordinator}. Bounds are fixed in code; effective range
 * is driven only by success/failure observations. Thread-safe.
 */
public final class BatchSizeController {

    private static final int INITIAL = 100;
    private static final int MIN = 50;
    private static final int MAX = 1000;
    private static final double GROWTH_FACTOR = 1.2;
    private static final int SMOOTHING_WINDOW = 5;
    private static final double SMOOTHING_THRESHOLD = 0.95;

    private static volatile BatchSizeController instance;

    private final AtomicInteger current = new AtomicInteger(INITIAL);
    private final Deque<Integer> successSizes = new ArrayDeque<>(SMOOTHING_WINDOW);
    private volatile Consumer<Integer> onChangeListener;

    /**
     * Constructs an isolated controller at the initial batch size.
     *
     * <p>Production callers normally obtain the shared instance from {@link #getInstance()}.</p>
     */
    public BatchSizeController() {
    }

    /**
     * Returns the shared batch-size controller instance.
     *
     * <p>Safe to call from any thread. Lazily creates the singleton on first access.</p>
     */
    public static synchronized BatchSizeController getInstance() {
        if (instance == null) {
            instance = new BatchSizeController();
        }
        return instance;
    }

    /**
     * Replaces the shared instance for isolated tests.
     *
     * @param c replacement controller; {@code null} makes the next access create a fresh instance
     */
    static void setInstance(BatchSizeController c) {
        instance = c;
    }

    /**
     * Returns the current batch size (doc count) to use for the next bulk request.
     *
     * @return current document-count ceiling
     */
    public int getCurrentBatchSize() {
        return current.get();
    }

    /**
     * Call after a bulk request fully succeeded. May increase batch size (with smoothing).
     *
     * @param docsSent number of documents successfully sent in this bulk
     */
    public void recordSuccess(int docsSent) {
        if (!ExportRunContext.allowsRunMutation()) {
            return;
        }
        int prev;
        int next;
        synchronized (this) {
            successSizes.addLast(docsSent);
            if (successSizes.size() > SMOOTHING_WINDOW) {
                successSizes.removeFirst();
            }
            prev = current.get();
            next = prev;
            if (successSizes.size() >= SMOOTHING_WINDOW) {
                double sum = 0;
                for (int v : successSizes) sum += v;
                double avg = sum / successSizes.size();
                if (avg >= prev * SMOOTHING_THRESHOLD) {
                    int proposed = (int) Math.round(prev * GROWTH_FACTOR);
                    next = Math.min(MAX, Math.max(prev + 1, proposed));
                }
            }
            if (next != prev) {
                current.set(next);
            }
        }
        if (next != prev) {
            notifyChange(next);
        }
    }

    /**
     * Call after a bulk request failed (full failure, 429, timeout, or partial success).
     * Decreases batch size.
     *
     * <p>The current algorithm halves from the existing ceiling; {@code attemptedDocs} is retained
     * as observation context and does not change the reduction amount.</p>
     *
     * @param attemptedDocs number of documents that were in the failed bulk
     */
    public void recordFailure(int attemptedDocs) {
        if (!ExportRunContext.allowsRunMutation()) {
            return;
        }
        int prev;
        int next;
        synchronized (this) {
            prev = current.get();
            next = Math.max(MIN, prev / 2);
            if (next != prev) {
                current.set(next);
                successSizes.clear();
            }
        }
        if (next != prev) {
            notifyChange(next);
        }
    }

    /**
     * Optional: treat partial success as failure for scaling (conservative).
     *
     * <p>The current algorithm uses {@code total} as failure context and deliberately does not
     * scale the reduction by {@code successCount}.</p>
     *
     * @param successCount number of docs that succeeded
     * @param total        total docs in the bulk
     */
    public void recordPartialSuccess(int successCount, int total) {
        recordFailure(total);
    }

    /**
     * Registers a listener called when the batch size changes.
     *
     * <p>Used by {@link ai.anomalousvectors.tools.burp.ui.StatsPanel} refresh hooks and
     * Exporter-index observability paths.</p>
     *
     * <p>Invoked from the thread that called {@link #recordSuccess} or {@link #recordFailure}.
     * Listener exceptions propagate to that caller after the size has changed.</p>
     *
     * @param listener replacement callback; {@code null} removes the current listener
     */
    public void setOnChangeListener(Consumer<Integer> listener) {
        this.onChangeListener = listener;
    }

    private void notifyChange(int newSize) {
        Consumer<Integer> listener = onChangeListener;
        if (listener != null) {
            listener.accept(newSize);
        }
    }
}
