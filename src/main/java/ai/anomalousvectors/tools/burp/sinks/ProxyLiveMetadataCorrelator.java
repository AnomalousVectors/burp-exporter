package ai.anomalousvectors.tools.burp.sinks;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.StringKeyedMaps;
import ai.anomalousvectors.tools.burp.utils.ExportAdmissionController;
import ai.anomalousvectors.tools.burp.utils.concurrent.LazyScheduler;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

/**
 * Deterministically joins live Proxy documents to their exact Proxy History rows.
 *
 * <p>A unique marker is added to each eligible intercepted request's notes. Burp carries the
 * annotation onto the corresponding History row, allowing correlation without URL, timing, or
 * FIFO guesses. Documents remain outside {@link TrafficExportQueue} until the token is found and
 * the History-backed fields are applied. Generated markers are removed from Burp annotations and
 * independently redacted by {@link BurpAnnotationFields} before any document is exported.</p>
 *
 * <p>Burp callbacks perform only marker bookkeeping and in-memory admission. A dedicated worker
 * performs History lookup, binding, cleanup, durable spooling, and queue handoff without holding
 * the callback-state lock. The 15-second threshold moves unresolved entries to disk; it never
 * authorizes an incomplete export. Thread-safe.</p>
 */
public final class ProxyLiveMetadataCorrelator implements ProxyRequestHandler, ProxyResponseHandler {

    private static final ProxyLiveMetadataCorrelator INSTANCE = new ProxyLiveMetadataCorrelator();
    private static final long DEFAULT_DURABLE_THRESHOLD_MS = 15_000L;
    private static final long INITIAL_COALESCE_MS = 10L;
    private static final long COLD_RETRY_MS = 60_000L;
    private static final long STOP_WAIT_MS = 10_000L;
    private static final long[] FRESH_RETRY_MS = {25L, 100L, 250L, 500L, 1_000L, 2_000L};
    private static final long HISTORY_TIME_VALIDATION_MS = 60_000L;
    private static final long WARN_INTERVAL_NANOS = TimeUnit.SECONDS.toNanos(30L);

    private static final ReentrantLock OWNER = new ReentrantLock();
    /*
     * OWNER guards live-token maps, PENDING membership, response leases, and generation lifecycle.
     * reconcileOwner serializes History/bind passes, but those passes acquire OWNER only for short
     * snapshots and mutations and never hold it during History, spool, or destination I/O.
     * Lifecycle flags read without OWNER are volatile; counters and wake coordination are atomic.
     * Code must never acquire reconcileOwner while holding OWNER.
     */
    private static final Condition RESPONSES_DRAINED = OWNER.newCondition();
    private static volatile ReentrantLock reconcileOwner = new ReentrantLock();
    private static final Map<Integer, LiveToken> LIVE_TOKENS = new HashMap<>();
    private static final Map<String, LiveToken> LIVE_TOKENS_BY_TOKEN = new HashMap<>();
    private static final Set<Integer> RETIRED_MESSAGE_IDS = new HashSet<>();
    private static final Set<String> RETIRED_TOKENS = new HashSet<>();
    private static final Map<String, DeferredEntry> PENDING = new LinkedHashMap<>();
    private static final LazyScheduler SCHEDULER =
            new LazyScheduler("burp-exporter-proxy-token-reconcile");
    private static final AtomicBoolean COALESCE_SCHEDULED = new AtomicBoolean();
    private static final AtomicBoolean HISTORY_PRIME_PENDING = new AtomicBoolean();
    private static final AtomicBoolean WORK_QUEUED = new AtomicBoolean();
    private static final AtomicLong WAKE_EPOCH = new AtomicLong();
    private static final AtomicLong RECONCILE_EPOCH = new AtomicLong();
    private static final AtomicLong ACTIVE_PERSIST_WORKERS = new AtomicLong();
    private static final AtomicReference<Thread> LAST_PERSIST_WORKER = new AtomicReference<>();
    private static final AtomicBoolean PERSIST_RERUN_REQUESTED = new AtomicBoolean();

    private static final AtomicLong ELIGIBLE_TOTAL = new AtomicLong();
    private static final AtomicLong BOUND_TOTAL = new AtomicLong();
    private static final AtomicLong DURABLE_TOTAL = new AtomicLong();
    private static final AtomicLong LOOKUP_FAILURES = new AtomicLong();
    private static final AtomicLong CLEANUP_FAILURES = new AtomicLong();
    private static final AtomicLong EXPLICIT_FAILURES = new AtomicLong();
    private static final AtomicLong PROXY_REQUEST_CALLBACKS = new AtomicLong();
    private static final AtomicLong HTTP_PROXY_REQUESTS = new AtomicLong();
    private static final AtomicLong HTTP_MARKED_REQUESTS = new AtomicLong();
    private static final AtomicLong HTTP_PROXY_RESPONSES = new AtomicLong();
    private static final AtomicLong HTTP_UNMARKED_TRACKED_RESPONSES = new AtomicLong();
    private static final AtomicLong HTTP_UNMARKED_UNTRACKED_RESPONSES = new AtomicLong();
    private static final AtomicLong HISTORY_LOOKUP_ATTEMPTS = new AtomicLong();
    private static final AtomicLong HISTORY_LOOKUP_MATCHED_ROWS = new AtomicLong();
    private static final AtomicLong LAST_LOOKUP_WARN_NANOS = new AtomicLong(Long.MIN_VALUE);
    private static final AtomicLong LAST_UNMARKED_WARN_NANOS = new AtomicLong(Long.MIN_VALUE);
    private static final AtomicLong LAST_EXPLICIT_FAILURE_LOG_NANOS =
            new AtomicLong(Long.MIN_VALUE);
    private static final AtomicLong SUPPRESSED_EXPLICIT_FAILURE_LOGS = new AtomicLong();
    private static final AtomicLong SPOOL_FAILURE_BASELINE = new AtomicLong();

    private static volatile boolean intakeOpen;
    private static volatile boolean handoffOpen;
    private static int inFlightResponses;
    private static long lateFinalizationGeneration;
    private static volatile boolean schedulerEnabled = true;
    private static volatile long generation;
    private static volatile long durableThresholdMs = DEFAULT_DURABLE_THRESHOLD_MS;
    private static volatile LongSupplier monotonicNanos = System::nanoTime;
    private static volatile LongSupplier epochMillis = System::currentTimeMillis;
    private static volatile Supplier<String> tokenSupplier = () -> UUID.randomUUID().toString();
    private static volatile HistorySource historySource = new BurpHistorySource();
    private static volatile OfferSink offerSink = TrafficExportQueue::offerAccepted;
    private static volatile ProxyCorrelationSpool spool = new ProxyCorrelationSpool();

    private ProxyLiveMetadataCorrelator() { }

    /**
     * Returns the singleton handler registered with Montoya.
     *
     * @return shared correlator
     */
    public static ProxyLiveMetadataCorrelator instance() {
        return INSTANCE;
    }

    /**
     * Opens token intake for a new export run and rehydrates unresolved durable entries.
     *
     * <p>Safe to call more than once. Existing in-memory entries are retained, and recovered
     * entries are merged by token. Disk recovery and worker creation complete before callbacks can
     * observe the run as open.</p>
     */
    public static void openRun() {
        OWNER.lock();
        try {
            if (intakeOpen) {
                return;
            }
            SPOOL_FAILURE_BASELINE.set(spool.permanentFailures());
        } finally {
            OWNER.unlock();
        }
        if (schedulerEnabled) {
            SCHEDULER.getOrStart();
        }
        if (historySource instanceof BurpHistorySource) {
            historySource = new BurpHistorySource();
        } else {
            historySource.reset();
        }
        HISTORY_PRIME_PENDING.set(schedulerEnabled);
        RECONCILE_EPOCH.incrementAndGet();
        reconcileOwner = new ReentrantLock();
        int recoveredCount = spool.recoverEach(stored -> {
            DeferredEntry entry = DeferredEntry.recovered(stored);
            OWNER.lock();
            try {
                PENDING.putIfAbsent(entry.token, entry);
            } finally {
                OWNER.unlock();
            }
        });
        OWNER.lock();
        try {
            if (intakeOpen) {
                return;
            }
            generation++;
            resetRunCountersLocked();
            intakeOpen = true;
            handoffOpen = true;
            Logger.logInfoPanelOnly("[ProxyCorrelation] Run opened: generation=" + generation
                    + ", pending=" + PENDING.size()
                    + ", recoveredFromDisk=" + recoveredCount
                    + ", pendingDurable=" + spool.count()
                    + ", markerSource=http_handler"
                    + ", durableThresholdMs=" + durableThresholdMs + ".");
        } finally {
            OWNER.unlock();
        }
        requestImmediateWake();
        if (recoveredCount > 0) {
            scheduleDelayedWake(COLD_RETRY_MS);
        }
    }

    /**
     * Atomically closes token intake for the active generation.
     *
     * <p>Response callbacks admitted before this transition may finish in the same generation.
     * Request-only markers are retired after those callbacks drain.</p>
     */
    public static void closeIntake() {
        OWNER.lock();
        try {
            if (!intakeOpen) {
                return;
            }
            logRunSummaryLocked("intake closing");
            intakeOpen = false;
        } finally {
            OWNER.unlock();
        }
    }

    /**
     * Closes worker handoff and asynchronously persists unresolved entries.
     *
     * <p>Stop never waits for History, spool, or destination I/O. Work already admitted to the
     * export queue is drained by the export lifecycle; unresolved correlation state remains outside
     * that queue and is persisted by a daemon worker. The method can wait up to
     * {@link #STOP_WAIT_MS} for response callbacks admitted before intake closed. Caller must not
     * invoke on the EDT.</p>
     */
    public static void closeAndDrainRun() {
        closeIntake();
        long closingGeneration = generation;
        boolean responsesDrained = awaitInFlightResponses(closingGeneration);
        if (responsesDrained) {
            retireRequestOnlyMarkers(closingGeneration);
        }
        handoffOpen = false;
        RECONCILE_EPOCH.incrementAndGet();
        WAKE_EPOCH.incrementAndGet();
        SCHEDULER.stop();
        COALESCE_SCHEDULED.set(false);
        WORK_QUEUED.set(false);
        persistPendingAsynchronously(Long.MIN_VALUE);
    }

    private static void persistPendingAsynchronously(long targetGeneration) {
        Thread worker = new Thread(
                () -> {
                    try {
                        List<DeferredEntry> unresolved;
                        OWNER.lock();
                        try {
                            unresolved = List.copyOf(PENDING.values());
                        } finally {
                            OWNER.unlock();
                        }
                        for (DeferredEntry entry : unresolved) {
                            if (targetGeneration == Long.MIN_VALUE
                                    || entry.generation == targetGeneration) {
                                entry.ensureEstimatedBytes();
                                persist(entry);
                            }
                        }
                    } finally {
                        ACTIVE_PERSIST_WORKERS.decrementAndGet();
                        LAST_PERSIST_WORKER.compareAndSet(Thread.currentThread(), null);
                        if (PERSIST_RERUN_REQUESTED.getAndSet(false)) {
                            persistPendingAsynchronously(Long.MIN_VALUE);
                        }
                    }
                },
                "burp-exporter-proxy-stop-persist");
        worker.setDaemon(true);
        while (true) {
            Thread existing = LAST_PERSIST_WORKER.get();
            if (existing != null && existing.isAlive()) {
                PERSIST_RERUN_REQUESTED.set(true);
                return;
            }
            if (LAST_PERSIST_WORKER.compareAndSet(existing, worker)) {
                break;
            }
        }
        ACTIVE_PERSIST_WORKERS.incrementAndGet();
        worker.start();
    }

    /**
     * Waits within a caller-owned shutdown budget for asynchronous correlation persistence.
     *
     * <p>Caller must not invoke on the EDT. Interruption restores the interrupt flag and returns
     * {@code false}.</p>
     *
     * @param timeoutMs maximum wait in milliseconds; non-positive values perform an immediate probe
     * @return {@code true} when no Stop-persistence worker remains active
     */
    public static boolean awaitPendingPersistence(long timeoutMs) {
        if (timeoutMs <= 0L) {
            Thread worker = LAST_PERSIST_WORKER.get();
            return (worker == null || !worker.isAlive())
                    && ACTIVE_PERSIST_WORKERS.get() == 0L
                    && !PERSIST_RERUN_REQUESTED.get();
        }
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs);
        while (true) {
            Thread worker = LAST_PERSIST_WORKER.get();
            if ((worker == null || !worker.isAlive())
                    && ACTIVE_PERSIST_WORKERS.get() == 0L
                    && !PERSIST_RERUN_REQUESTED.get()) {
                return true;
            }
            long remainingNanos = deadline - System.nanoTime();
            if (remainingNanos <= 0L) {
                return false;
            }
            if (worker == null) {
                Thread.onSpinWait();
                continue;
            }
            try {
                long waitMs = Math.max(1L, TimeUnit.NANOSECONDS.toMillis(remainingNanos));
                worker.join(waitMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
    }

    private static boolean awaitInFlightResponses(long closingGeneration) {
        long remainingNanos = TimeUnit.MILLISECONDS.toNanos(STOP_WAIT_MS);
        OWNER.lock();
        try {
            while (inFlightResponses > 0 && remainingNanos > 0L) {
                try {
                    remainingNanos = RESPONSES_DRAINED.awaitNanos(remainingNanos);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    lateFinalizationGeneration = closingGeneration;
                    return false;
                }
            }
            if (inFlightResponses > 0) {
                lateFinalizationGeneration = closingGeneration;
                Logger.logWarnPanelOnly(
                        "[ProxyCorrelation] Stop timed out waiting for HTTP response callbacks: "
                                + "generation=" + closingGeneration
                                + ", inFlightResponses=" + inFlightResponses
                                + ", waitMs=" + STOP_WAIT_MS
                                + "; late callbacks will finalize and persist asynchronously.");
                return false;
            }
            lateFinalizationGeneration = 0L;
            return true;
        } finally {
            OWNER.unlock();
        }
    }

    private static void retireRequestOnlyMarkers(long retiringGeneration) {
        List<LiveToken> closing;
        OWNER.lock();
        try {
            if (retiringGeneration == generation) {
                RETIRED_MESSAGE_IDS.clear();
                RETIRED_TOKENS.clear();
            }
            closing = LIVE_TOKENS_BY_TOKEN.values().stream()
                    .filter(live -> live.generation == retiringGeneration)
                    .distinct()
                    .toList();
            for (LiveToken live : closing) {
                RETIRED_MESSAGE_IDS.addAll(live.messageIds);
                RETIRED_TOKENS.add(live.token);
                removeLiveTokenLocked(live);
            }
        } finally {
            OWNER.unlock();
        }
        for (LiveToken live : closing) {
            cleanupAnnotations(live.annotations, live.token);
        }
    }

    /**
     * Admits one global HTTP response callback to the current correlation generation.
     *
     * <p>The returned lease keeps Stop from finalizing correlation state while the callback builds
     * its document. A callback beginning after intake closes receives an inactive lease.</p>
     *
     * @return response lease; always close it when callback processing finishes
     */
    static ResponseLease beginHttpResponse() {
        OWNER.lock();
        try {
            if (!intakeOpen) {
                return ResponseLease.inactive();
            }
            inFlightResponses++;
            return new ResponseLease(generation, true);
        } finally {
            OWNER.unlock();
        }
    }

    /**
     * Defers a completed live Proxy document until its token appears in Proxy History.
     *
     * @param document completed live traffic document
     * @param annotations response annotations expected to carry the request marker
     * @param messageId live HTTP handler message id
     * @param requestSentMs request callback epoch, used only to validate the History row
     */
    static void deferUntilHistoryBound(
            Map<String, Object> document,
            Annotations annotations,
            int messageId,
            Long requestSentMs) {
        deferUntilHistoryBound(document, annotations, messageId, requestSentMs, null);
    }

    static void deferUntilHistoryBound(
            Map<String, Object> document,
            Annotations annotations,
            int messageId,
            Long requestSentMs,
            ResponseLease responseLease) {
        if (document == null) {
            return;
        }
        HTTP_PROXY_RESPONSES.incrementAndGet();
        OWNER.lock();
        try {
            long admissionGeneration = responseLease != null && responseLease.active
                    ? responseLease.generation
                    : generation;
            boolean admittedBeforeClose = responseLease != null
                    && responseLease.active
                    && responseLease.generation == admissionGeneration;
            if (!intakeOpen && !admittedBeforeClose) {
                ProxyCorrelationToken.find(annotations)
                        .ifPresent(token -> ProxyCorrelationToken.remove(annotations, token));
                return;
            }
            String annotatedToken = ProxyCorrelationToken.find(annotations).orElse(null);
            LiveToken live = annotatedToken == null
                    ? LIVE_TOKENS.get(messageId)
                    : LIVE_TOKENS_BY_TOKEN.get(annotatedToken);
            if (live != null) {
                removeLiveTokenLocked(live);
            }
            if (live == null
                    && ((annotatedToken != null && RETIRED_TOKENS.remove(annotatedToken))
                            || RETIRED_MESSAGE_IDS.remove(messageId))) {
                ProxyCorrelationToken.find(annotations)
                        .ifPresent(token -> ProxyCorrelationToken.remove(annotations, token));
                return;
            }
            if (live == null && annotatedToken == null) {
                if (requestSentMs == null) {
                    HTTP_UNMARKED_UNTRACKED_RESPONSES.incrementAndGet();
                } else {
                    ELIGIBLE_TOTAL.incrementAndGet();
                    EXPLICIT_FAILURES.incrementAndGet();
                    long unmarked = HTTP_UNMARKED_TRACKED_RESPONSES.incrementAndGet();
                    logUnmarkedTrackedResponse(unmarked, messageId);
                }
                return;
            }
            ELIGIBLE_TOTAL.incrementAndGet();
            if (live == null || live.generation != admissionGeneration) {
                EXPLICIT_FAILURES.incrementAndGet();
                ProxyCorrelationToken.find(annotations)
                        .ifPresent(token -> ProxyCorrelationToken.remove(annotations, token));
                logExplicitFailure("inactive_generation", messageId);
                return;
            }
            String token = annotatedToken == null ? live.token : annotatedToken;
            if (token == null || token.isBlank()) {
                EXPLICIT_FAILURES.incrementAndGet();
                logExplicitFailure("missing_marker", messageId);
                return;
            }
            if (!live.token.equals(token)) {
                EXPLICIT_FAILURES.incrementAndGet();
                cleanupAnnotations(live.annotations, live.token);
                ProxyCorrelationToken.remove(annotations, token);
                logExplicitFailure("unexpected_marker", messageId);
                return;
            }
            if (PENDING.containsKey(token)) {
                EXPLICIT_FAILURES.incrementAndGet();
                cleanupAnnotations(live.annotations, live.token);
                ProxyCorrelationToken.remove(annotations, token);
                logExplicitFailure("duplicate_marker", messageId);
                return;
            }
            List<Annotations> cleanupTargets = new ArrayList<>();
            cleanupTargets.addAll(live.annotations);
            addIdentity(cleanupTargets, annotations);
            DeferredEntry entry = new DeferredEntry(
                    token,
                    messageId,
                    live.listenerPort,
                    live.generation,
                    requestSentMs,
                    epochMillis.getAsLong(),
                    monotonicNanos.getAsLong(),
                    document,
                    cleanupTargets);
            PENDING.put(token, entry);
        } finally {
            OWNER.unlock();
        }
        scheduleCoalescedWake();
    }

    /**
     * Removes marker state for a request that will not produce an eligible live Proxy document.
     *
     * @param messageId live HTTP handler message id
     */
    static void abandonMessage(int messageId) {
        abandonMessage(messageId, null);
    }

    /**
     * Removes marker state using the annotation token first and callback-local message ID second.
     *
     * @param messageId message ID from the callback abandoning export
     * @param annotations callback annotations, possibly carrying the authoritative token
     */
    static void abandonMessage(int messageId, Annotations annotations) {
        LiveToken removed;
        OWNER.lock();
        try {
            String token = ProxyCorrelationToken.find(annotations).orElse(null);
            LiveToken live = token == null
                    ? LIVE_TOKENS.get(messageId)
                    : LIVE_TOKENS_BY_TOKEN.get(token);
            removeLiveTokenLocked(live);
            removed = live;
            RETIRED_MESSAGE_IDS.remove(messageId);
            if (token != null) {
                RETIRED_TOKENS.remove(token);
            }
        } finally {
            OWNER.unlock();
        }
        if (removed != null) {
            cleanupAnnotations(removed.annotations, removed.token);
        }
    }

    private static void removeLiveTokenLocked(LiveToken live) {
        if (live == null) {
            return;
        }
        for (Integer messageId : live.messageIds) {
            LIVE_TOKENS.remove(messageId, live);
        }
        LIVE_TOKENS_BY_TOKEN.remove(live.token, live);
    }

    /**
     * Attaches the authoritative correlation marker in the global HTTP request callback.
     *
     * <p>The same callback family later builds the exported response document, so this path does
     * not depend on message IDs being shared with Proxy-specific handlers.</p>
     *
     * @param messageId global HTTP request ID
     * @param annotations annotations returned in the HTTP request action
     */
    static void markHttpRequest(int messageId, Annotations annotations) {
        HTTP_PROXY_REQUESTS.incrementAndGet();
        if (!intakeOpen) {
            return;
        }
        OWNER.lock();
        try {
            if (!intakeOpen) {
                return;
            }
            if (attachMarkerLocked(messageId, annotations, null)) {
                long marked = HTTP_MARKED_REQUESTS.incrementAndGet();
                if (marked == 1L) {
                    Logger.logDebug("[ProxyCorrelation] First live Proxy HTTP request marked: "
                            + "generation=" + generation + ", messageId=" + messageId + ".");
                }
            }
        } finally {
            OWNER.unlock();
        }
    }

    /** Returns current non-durable pending document count. */
    public static int pendingMemoryCount() {
        OWNER.lock();
        try {
            return (int) PENDING.values().stream().filter(entry -> !entry.durable).count();
        } finally {
            OWNER.unlock();
        }
    }

    /** Returns estimated bytes held by non-durable pending documents. */
    public static long pendingMemoryBytes() {
        OWNER.lock();
        try {
            return PENDING.values().stream()
                    .filter(entry -> !entry.durable)
                    .mapToLong(entry -> entry.estimatedBytes)
                    .sum();
        } finally {
            OWNER.unlock();
        }
    }

    /** Returns current durable pending document count. */
    public static int pendingDurableCount() {
        return spool.count();
    }

    /** Returns exact current durable spool bytes. */
    public static long pendingDurableBytes() {
        return spool.bytes();
    }

    /** Returns current-run live Proxy documents accepted after exact History binding. */
    public static long boundTotal() {
        return BOUND_TOTAL.get();
    }

    /** Returns documents moved to durable correlation storage during the current run. */
    public static long durableSpooledTotal() {
        return DURABLE_TOTAL.get();
    }

    /** Returns failed History lookup attempts in the current run. */
    public static long lookupFailures() {
        return LOOKUP_FAILURES.get();
    }

    /** Returns failed annotation cleanup attempts in the current run. */
    public static long cleanupFailures() {
        return CLEANUP_FAILURES.get();
    }

    /** Returns permanent durable-store failures in the current run. */
    public static long spoolFailures() {
        return Math.max(0L, spool.permanentFailures() - SPOOL_FAILURE_BASELINE.get());
    }

    /**
     * Returns eligible live Proxy documents in the current run, including recovered pending work.
     */
    public static long eligibleTotal() {
        return ELIGIBLE_TOTAL.get();
    }

    /** Returns live Proxy documents that could not be correlated because no token was available. */
    public static long explicitFailures() {
        return EXPLICIT_FAILURES.get();
    }

    /** Returns Proxy request-handler callbacks observed during the current run. */
    public static long proxyRequestCallbacks() {
        return PROXY_REQUEST_CALLBACKS.get();
    }

    /** Returns selected live Proxy requests observed by the global HTTP handler. */
    public static long httpProxyRequests() {
        return HTTP_PROXY_REQUESTS.get();
    }

    /** Returns global HTTP-handler Proxy requests that received a correlation marker. */
    public static long httpMarkedRequests() {
        return HTTP_MARKED_REQUESTS.get();
    }

    /** Returns selected live Proxy responses observed by the global HTTP handler. */
    public static long httpProxyResponses() {
        return HTTP_PROXY_RESPONSES.get();
    }

    /** Returns tracked HTTP responses that unexpectedly lacked a correlation marker. */
    public static long httpUnmarkedTrackedResponses() {
        return HTTP_UNMARKED_TRACKED_RESPONSES.get();
    }

    /** Returns untracked responses that began before the current export run. */
    public static long httpUnmarkedUntrackedResponses() {
        return HTTP_UNMARKED_UNTRACKED_RESPONSES.get();
    }

    /** Returns Proxy History token lookup attempts in the current run. */
    public static long historyLookupAttempts() {
        return HISTORY_LOOKUP_ATTEMPTS.get();
    }

    /** Returns cumulative token-bearing History rows returned by successful lookups. */
    public static long historyLookupMatchedRows() {
        return HISTORY_LOOKUP_MATCHED_ROWS.get();
    }

    /** {@inheritDoc} */
    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
        Annotations annotations = request.annotations();
        markRequest(request, annotations);
        return ProxyRequestReceivedAction.continueWith(request, annotations);
    }

    /** {@inheritDoc} */
    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest request) {
        Annotations annotations = request.annotations();
        markRequest(request, annotations);
        return ProxyRequestToBeSentAction.continueWith(request, annotations);
    }

    /** {@inheritDoc} */
    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
        Annotations annotations = response.annotations();
        rememberResponseAnnotations(response, annotations);
        return ProxyResponseReceivedAction.continueWith(response, annotations);
    }

    /** {@inheritDoc} */
    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
        Annotations annotations = response.annotations();
        rememberResponseAnnotations(response, annotations);
        return ProxyResponseToBeSentAction.continueWith(response, annotations);
    }

    private static void markRequest(InterceptedRequest request, Annotations annotations) {
        if (request == null) {
            return;
        }
        PROXY_REQUEST_CALLBACKS.incrementAndGet();
        if (!intakeOpen
                || !RuntimeConfig.isExportReady()
                || !RuntimeConfig.trafficExportGate().includesToolType("proxy")) {
            return;
        }
        OWNER.lock();
        try {
            if (!intakeOpen) {
                return;
            }
            String token = ProxyCorrelationToken.find(annotations).orElse(null);
            if (token == null) {
                return;
            }
            LiveToken live = LIVE_TOKENS_BY_TOKEN.get(token);
            if (live == null || live.generation != generation) {
                return;
            }
            addIdentity(live.annotations, annotations);
            Integer port = parseListenerPort(request.listenerInterface());
            if (port != null) {
                live.listenerPort = port;
            }
        } catch (RuntimeException e) {
            EXPLICIT_FAILURES.incrementAndGet();
            Logger.logError("[ProxyCorrelation] Unable to retain Proxy request metadata: " + e.getMessage());
        } finally {
            OWNER.unlock();
        }
    }

    private static boolean attachMarkerLocked(
            int messageId,
            Annotations annotations,
            Integer listenerPort) {
        String annotatedToken = ProxyCorrelationToken.find(annotations).orElse(null);
        LiveToken live = annotatedToken == null
                ? LIVE_TOKENS.get(messageId)
                : LIVE_TOKENS_BY_TOKEN.get(annotatedToken);
        if (live == null || live.generation != generation) {
            if (annotatedToken != null) {
                ProxyCorrelationToken.remove(annotations, annotatedToken);
            }
            live = new LiveToken(tokenSupplier.get(), generation);
            LIVE_TOKENS_BY_TOKEN.put(live.token, live);
        }
        live.messageIds.add(messageId);
        LIVE_TOKENS.put(messageId, live);
        RETIRED_MESSAGE_IDS.remove(messageId);
        RETIRED_TOKENS.remove(live.token);
        if (!ProxyCorrelationToken.append(annotations, live.token)) {
            removeLiveTokenLocked(live);
            EXPLICIT_FAILURES.incrementAndGet();
            logExplicitFailure("marker_attach_failed", messageId);
            return false;
        }
        addIdentity(live.annotations, annotations);
        if (listenerPort != null) {
            live.listenerPort = listenerPort;
        }
        return true;
    }

    private static void rememberResponseAnnotations(
            InterceptedResponse response,
            Annotations annotations) {
        if (response == null) {
            return;
        }
        OWNER.lock();
        try {
            String token = ProxyCorrelationToken.find(annotations).orElse(null);
            LiveToken live = token == null ? null : LIVE_TOKENS_BY_TOKEN.get(token);
            if (live == null || live.generation != generation) {
                return;
            }
            addIdentity(live.annotations, annotations);
            Integer port = parseListenerPort(response.listenerInterface());
            if (port != null) {
                live.listenerPort = port;
            }
        } catch (RuntimeException e) {
            Logger.logWarnPanelOnly("[ProxyCorrelation] Unable to retain response annotations: " + e.getMessage());
        } finally {
            OWNER.unlock();
        }
    }

    private static void scheduleDelayedWake(long delayMs) {
        if (!schedulerEnabled) {
            return;
        }
        var executor = SCHEDULER.peek();
        if (executor == null) {
            return;
        }
        long expectedEpoch = WAKE_EPOCH.get();
        try {
            executor.schedule(
                    () -> {
                        if (WAKE_EPOCH.get() == expectedEpoch) {
                            requestImmediateWake();
                        }
                    },
                    Math.max(0L, delayMs),
                    TimeUnit.MILLISECONDS);
        } catch (RejectedExecutionException ignored) {
            // Stop invalidates delayed work before shutting down the worker.
        }
    }

    private static void scheduleCoalescedWake() {
        if (!schedulerEnabled || !COALESCE_SCHEDULED.compareAndSet(false, true)) {
            return;
        }
        var executor = SCHEDULER.peek();
        if (executor == null) {
            COALESCE_SCHEDULED.set(false);
            return;
        }
        try {
            executor.schedule(
                    () -> {
                        COALESCE_SCHEDULED.set(false);
                        requestImmediateWake();
                    },
                    INITIAL_COALESCE_MS,
                    TimeUnit.MILLISECONDS);
        } catch (RejectedExecutionException ignored) {
            COALESCE_SCHEDULED.set(false);
        }
    }

    private static void requestImmediateWake() {
        if (!schedulerEnabled) {
            return;
        }
        var executor = SCHEDULER.peek();
        if (executor == null) {
            return;
        }
        WAKE_EPOCH.incrementAndGet();
        if (!WORK_QUEUED.compareAndSet(false, true)) {
            return;
        }
        try {
            executor.execute(() -> {
                WORK_QUEUED.set(false);
                reconcileSafely();
            });
        } catch (RejectedExecutionException ignored) {
            WORK_QUEUED.set(false);
        }
    }

    private static void reconcileSafely() {
        long reconcileEpoch = RECONCILE_EPOCH.get();
        HistorySource source = historySource;
        try {
            reconcileNow(false, reconcileEpoch, source);
        } catch (RuntimeException e) {
            LOOKUP_FAILURES.incrementAndGet();
            rateLimitedLookupWarning("Reconciliation task failed: " + e.getMessage());
        } finally {
            if (reconcileEpoch == RECONCILE_EPOCH.get()) {
                scheduleNextWake();
            }
        }
    }

    private static void reconcileNow(
            boolean finalPass,
            long reconcileEpoch,
            HistorySource source) {
        ReentrantLock owner = reconcileOwner;
        owner.lock();
        try {
            reconcileOwned(finalPass, reconcileEpoch, source);
        } finally {
            owner.unlock();
        }
    }

    private static void reconcileOwned(
            boolean finalPass,
            long reconcileEpoch,
            HistorySource source) {
        if (reconcileEpoch != RECONCILE_EPOCH.get()) {
            return;
        }
        long nowNanos = monotonicNanos.getAsLong();
        List<DeferredEntry> entries;
        OWNER.lock();
        try {
            entries = List.copyOf(PENDING.values());
        } finally {
            OWNER.unlock();
        }
        boolean primeHistory = HISTORY_PRIME_PENDING.get();
        if (entries.isEmpty()) {
            if (primeHistory) {
                primeHistoryCursor(source);
            }
            return;
        }

        long pendingMemoryBytes = 0L;
        int pendingMemoryDocs = 0;
        for (DeferredEntry entry : entries) {
            entry.ensureEstimatedBytes();
            if (!entry.durable) {
                pendingMemoryBytes += entry.estimatedBytes;
                pendingMemoryDocs++;
            }
        }
        for (DeferredEntry entry : entries) {
            if (reconcileEpoch != RECONCILE_EPOCH.get()) {
                return;
            }
            boolean memoryPressure = pendingMemoryDocs
                    > ExportAdmissionController.MEM_DOC_SAFETY_RAIL
                    || !ExportAdmissionController.memAccepts(pendingMemoryBytes, 0L);
            if (!entry.durable
                    && (memoryPressure || nowNanos >= entry.nextDurabilityAttemptAtNanos)) {
                if (!persist(entry)) {
                    entry.scheduleDurabilityRetry(nowNanos);
                } else {
                    pendingMemoryBytes = Math.max(0L, pendingMemoryBytes - entry.estimatedBytes);
                    pendingMemoryDocs = Math.max(0, pendingMemoryDocs - 1);
                }
            }
        }

        List<DeferredEntry> freshDue = new ArrayList<>();
        List<DeferredEntry> freshRescanDue = new ArrayList<>();
        List<DeferredEntry> coldDue = new ArrayList<>();
        List<DeferredEntry> handoffDue = new ArrayList<>();
        for (DeferredEntry entry : entries) {
            if (finalPass || entry.nextLookupAtNanos <= nowNanos) {
                if (entry.bound && entry.cleanupComplete) {
                    handoffDue.add(entry);
                } else if (entry.coldLane()) {
                    coldDue.add(entry);
                } else if (entry.requiresFullRescan()) {
                    freshRescanDue.add(entry);
                } else {
                    freshDue.add(entry);
                }
            }
        }
        if (!freshDue.isEmpty() || !freshRescanDue.isEmpty()) {
            HISTORY_PRIME_PENDING.set(false);
        } else if (primeHistory) {
            primeHistoryCursor(source);
        }
        Map<String, List<ProxyHttpRequestResponse>> rowsByToken = new HashMap<>();
        LookupBatch appendedBatch = lookup(freshDue, LookupScope.APPENDED_ROWS, source);
        mergeLookup(rowsByToken, appendedBatch);
        if (reconcileEpoch != RECONCILE_EPOCH.get()) {
            return;
        }
        Set<DeferredEntry> dueEntries = new HashSet<>(freshDue);
        dueEntries.addAll(freshRescanDue);
        dueEntries.addAll(coldDue);
        dueEntries.addAll(handoffDue);
        freshRescanDue.addAll(coldDue);
        LookupBatch allHistoryBatch = lookup(
                freshRescanDue, LookupScope.ALL_HISTORY, source);
        mergeLookup(rowsByToken, allHistoryBatch);
        if (reconcileEpoch != RECONCILE_EPOCH.get()) {
            return;
        }

        if (appendedBatch.status == LookupStatus.LOOKUP_FAILED) {
            dueEntries.removeAll(freshDue);
        }
        if (allHistoryBatch.status == LookupStatus.LOOKUP_FAILED) {
            dueEntries.removeAll(freshRescanDue);
        }
        Set<DeferredEntry> fullHistoryChecked =
                allHistoryBatch.status == LookupStatus.LOOKUP_FAILED
                        ? Set.of()
                        : new HashSet<>(freshRescanDue);

        for (DeferredEntry entry : entries) {
            if (reconcileEpoch != RECONCILE_EPOCH.get()) {
                return;
            }
            if (!dueEntries.contains(entry)) {
                continue;
            }
            processEntry(
                    entry,
                    rowsByToken.getOrDefault(entry.token, List.of()),
                    nowNanos,
                    reconcileEpoch,
                    source,
                    fullHistoryChecked.contains(entry));
        }
    }

    private static void primeHistoryCursor(HistorySource source) {
        HISTORY_LOOKUP_ATTEMPTS.incrementAndGet();
        LookupBatch batch = source.lookup(Set.of(), LookupScope.APPENDED_ROWS);
        if (batch == null || batch.status == LookupStatus.LOOKUP_FAILED) {
            LOOKUP_FAILURES.incrementAndGet();
            rateLimitedLookupWarning(batch == null ? "History cursor initialization returned no outcome."
                    : batch.failureMessage);
            scheduleDelayedWake(1_000L);
            return;
        }
        HISTORY_PRIME_PENDING.set(false);
    }

    private static LookupBatch lookup(
            List<DeferredEntry> entries,
            LookupScope scope,
            HistorySource source) {
        if (entries.isEmpty()) {
            return LookupBatch.success(List.of());
        }
        Set<String> tokens = new HashSet<>();
        for (DeferredEntry entry : entries) {
            tokens.add(entry.token);
        }
        HISTORY_LOOKUP_ATTEMPTS.incrementAndGet();
        LookupBatch batch = source.lookup(Set.copyOf(tokens), scope);
        if (batch == null || batch.status == LookupStatus.LOOKUP_FAILED) {
            LOOKUP_FAILURES.incrementAndGet();
            rateLimitedLookupWarning(batch == null ? "History lookup returned no outcome."
                    : batch.failureMessage);
            for (DeferredEntry entry : entries) {
                entry.scheduleRetry(monotonicNanos.getAsLong());
            }
            return batch == null
                    ? LookupBatch.failed("History lookup returned no outcome.")
                    : batch;
        }
        HISTORY_LOOKUP_MATCHED_ROWS.addAndGet(batch.rows.size());
        if (batch.rows.isEmpty()) {
            long nowNanos = monotonicNanos.getAsLong();
            for (DeferredEntry entry : entries) {
                entry.scheduleRetry(nowNanos);
            }
        }
        return batch;
    }

    private static void mergeLookup(
            Map<String, List<ProxyHttpRequestResponse>> destination,
            LookupBatch batch) {
        for (Map.Entry<String, List<ProxyHttpRequestResponse>> entry
                : indexRowsByToken(batch.rows).entrySet()) {
            destination.computeIfAbsent(entry.getKey(), ignored -> new ArrayList<>())
                    .addAll(entry.getValue());
        }
    }

    private static void processEntry(
            DeferredEntry entry,
            List<ProxyHttpRequestResponse> rows,
            long nowNanos,
            long reconcileEpoch,
            HistorySource source,
            boolean fullHistoryChecked) {
        if (reconcileEpoch != RECONCILE_EPOCH.get()) {
            return;
        }
        if (entry.document == null
                && (entry.bound || !rows.isEmpty())
                && !entry.loadDocument()) {
            entry.scheduleRetry(nowNanos);
            return;
        }
        if (!entry.bound) {
            if (rows.size() > 1) {
                rateLimitedLookupWarning(
                        "Multiple Proxy History rows matched one marker: generation="
                                + entry.generation + ", messageId=" + entry.messageId
                                + ", matches=" + rows.size() + "; document remains pending.");
                entry.scheduleRetry(nowNanos);
                return;
            }
            if (rows.size() == 1 && bind(entry, rows.get(0))) {
                entry.history = rows.get(0);
                if (entry.durable && !persist(entry)) {
                    entry.scheduleRetry(nowNanos);
                    return;
                }
            } else if (rows.isEmpty()) {
                if (entry.nextLookupAtNanos <= nowNanos) {
                    entry.scheduleRetry(nowNanos);
                }
                return;
            } else {
                entry.scheduleRetry(nowNanos);
                return;
            }
        }
        ProxyHttpRequestResponse history = entry.history;
        if (history == null && rows.size() == 1) {
            history = rows.get(0);
            entry.history = history;
        }
        if (!entry.cleanupComplete) {
            if (history == null) {
                if (entry.bound && entry.recovered && fullHistoryChecked) {
                    entry.cleanupComplete = true;
                } else {
                    entry.scheduleRetry(nowNanos);
                    return;
                }
            } else if (!cleanupBoundEntry(entry, history)) {
                entry.scheduleRetry(nowNanos);
                return;
            }
            entry.cleanupComplete = true;
        }
        if (entry.durable && !persist(entry)) {
            entry.scheduleRetry(nowNanos);
            return;
        }
        if (reconcileEpoch != RECONCILE_EPOCH.get()) {
            return;
        }
        if (!handoffOpen || !offerSink.offer(entry.document)) {
            persist(entry);
            entry.releaseDurableDocument();
            entry.scheduleRetry(nowNanos);
            return;
        }
        OWNER.lock();
        try {
            PENDING.remove(entry.token, entry);
        } finally {
            OWNER.unlock();
        }
        source.forget(entry.token);
        spool.complete(entry.token, ACTIVE_PERSIST_WORKERS.get() > 0L);
        BOUND_TOTAL.incrementAndGet();
    }

    private static void scheduleNextWake() {
        if (!schedulerEnabled) {
            return;
        }
        long nowNanos = monotonicNanos.getAsLong();
        long nextNanos = Long.MAX_VALUE;
        OWNER.lock();
        try {
            for (DeferredEntry entry : PENDING.values()) {
                nextNanos = Math.min(nextNanos, entry.nextLookupAtNanos);
                if (!entry.durable) {
                    nextNanos = Math.min(nextNanos, entry.nextDurabilityAttemptAtNanos);
                }
            }
        } finally {
            OWNER.unlock();
        }
        if (nextNanos == Long.MAX_VALUE) {
            return;
        }
        long delayNanos = Math.max(0L, nextNanos - nowNanos);
        long delayMs = TimeUnit.NANOSECONDS.toMillis(delayNanos);
        if (delayNanos > 0L && delayMs == 0L) {
            delayMs = 1L;
        }
        scheduleDelayedWake(delayMs);
    }

    private static boolean bind(DeferredEntry entry, ProxyHttpRequestResponse history) {
        if (!validates(entry, history)) {
            return false;
        }
        synchronized (entry) {
            try {
                applyHistoryFields(entry.document, history);
                entry.bound = true;
                return true;
            } catch (RuntimeException e) {
                LOOKUP_FAILURES.incrementAndGet();
                rateLimitedLookupWarning("History row could not be applied: " + e.getMessage());
                return false;
            }
        }
    }

    private static boolean validates(DeferredEntry entry, ProxyHttpRequestResponse history) {
        try {
            if (entry.listenerPort != null && history.listenerPort() != entry.listenerPort) {
                rateLimitedLookupWarning("Token matched a different Proxy listener port.");
                return false;
            }
        } catch (RuntimeException ignored) {
            // Missing listener metadata does not invalidate deterministic token identity.
        }
        if (entry.requestSentMs == null) {
            return true;
        }
        try {
            ZonedDateTime historyTime = history.time();
            if (historyTime == null) {
                return true;
            }
            long delta = Math.abs(historyTime.toInstant().toEpochMilli() - entry.requestSentMs);
            if (delta > HISTORY_TIME_VALIDATION_MS) {
                rateLimitedLookupWarning("Token matched a Proxy History row outside the request-time validation window.");
            }
        } catch (RuntimeException ignored) {
            // Missing time metadata does not invalidate deterministic token identity.
        }
        return true;
    }

    private static boolean cleanupBoundEntry(
            DeferredEntry entry,
            ProxyHttpRequestResponse history) {
        boolean success = true;
        if (history != null) {
            try {
                success &= cleanupAnnotation(history.annotations(), entry.token);
            } catch (RuntimeException e) {
                success = false;
            }
        }
        for (Annotations annotations : entry.cleanupTargets) {
            success &= cleanupAnnotation(annotations, entry.token);
        }
        if (!success) {
            CLEANUP_FAILURES.incrementAndGet();
            Logger.logError("[ProxyCorrelation] Unable to remove a generated annotation marker.");
        }
        return success;
    }

    private static boolean cleanupAnnotation(Annotations annotations, String token) {
        if (annotations == null) {
            return true;
        }
        ProxyCorrelationToken.remove(annotations, token);
        return ProxyCorrelationToken.find(annotations)
                .filter(token::equals)
                .isEmpty();
    }

    private static void cleanupAnnotations(List<Annotations> annotations, String token) {
        for (Annotations value : annotations) {
            try {
                if (!cleanupAnnotation(value, token)) {
                    CLEANUP_FAILURES.incrementAndGet();
                }
            } catch (RuntimeException e) {
                CLEANUP_FAILURES.incrementAndGet();
                Logger.logError("[ProxyCorrelation] Annotation cleanup failed: " + e.getMessage());
            }
        }
    }

    private static Map<String, List<ProxyHttpRequestResponse>> indexRowsByToken(
            List<ProxyHttpRequestResponse> rows) {
        Map<String, List<ProxyHttpRequestResponse>> result = new HashMap<>();
        if (rows == null) {
            return result;
        }
        for (ProxyHttpRequestResponse row : rows) {
            try {
                if (row == null) {
                    continue;
                }
                ProxyCorrelationToken.find(row.annotations())
                        .ifPresent(token -> result.computeIfAbsent(token, ignored -> new ArrayList<>()).add(row));
            } catch (RuntimeException e) {
                LOOKUP_FAILURES.incrementAndGet();
                rateLimitedLookupWarning("Malformed Proxy History row was skipped: " + e.getMessage());
            }
        }
        return result;
    }

    private static void applyHistoryFields(
            Map<String, Object> document,
            ProxyHttpRequestResponse history) {
        Object burpValue = document.get("burp");
        if (!(burpValue instanceof Map<?, ?> burpMap)) {
            throw new IllegalStateException("Live document has no burp object");
        }
        Map<String, Object> burp = StringKeyedMaps.copy(burpMap);
        burp.put("proxy", BurpProxyFields.forProxyHistory(history));
        burp.put("timing", BurpTimingFields.fromProxyHistory(history));
        document.put("burp", burp);
    }

    private static boolean persist(DeferredEntry entry) {
        synchronized (entry) {
            if (entry.durable && entry.document == null) {
                return true;
            }
            ProxyCorrelationSpool.PersistResult result = spool.persist(entry.toStoredEntry());
            if (result != ProxyCorrelationSpool.PersistResult.STORED) {
                return false;
            }
            if (!entry.durable) {
                OWNER.lock();
                try {
                    entry.durable = true;
                    entry.nextLookupAtNanos = Math.max(
                            entry.nextLookupAtNanos,
                            monotonicNanos.getAsLong()
                                    + TimeUnit.MILLISECONDS.toNanos(COLD_RETRY_MS));
                } finally {
                    OWNER.unlock();
                }
                DURABLE_TOTAL.incrementAndGet();
                entry.releaseDurableDocument();
            }
            return true;
        }
    }

    private static void resetRunCountersLocked() {
        ELIGIBLE_TOTAL.set(PENDING.size());
        BOUND_TOTAL.set(0L);
        DURABLE_TOTAL.set(0L);
        LOOKUP_FAILURES.set(0L);
        CLEANUP_FAILURES.set(0L);
        EXPLICIT_FAILURES.set(0L);
        PROXY_REQUEST_CALLBACKS.set(0L);
        HTTP_PROXY_REQUESTS.set(0L);
        HTTP_MARKED_REQUESTS.set(0L);
        HTTP_PROXY_RESPONSES.set(0L);
        HTTP_UNMARKED_TRACKED_RESPONSES.set(0L);
        HTTP_UNMARKED_UNTRACKED_RESPONSES.set(0L);
        HISTORY_LOOKUP_ATTEMPTS.set(0L);
        HISTORY_LOOKUP_MATCHED_ROWS.set(0L);
        LAST_LOOKUP_WARN_NANOS.set(Long.MIN_VALUE);
        LAST_UNMARKED_WARN_NANOS.set(Long.MIN_VALUE);
        LAST_EXPLICIT_FAILURE_LOG_NANOS.set(Long.MIN_VALUE);
        SUPPRESSED_EXPLICIT_FAILURE_LOGS.set(0L);
    }

    private static Integer parseListenerPort(String listenerInterface) {
        if (listenerInterface == null || listenerInterface.isBlank()) {
            return null;
        }
        int colon = listenerInterface.trim().lastIndexOf(':');
        if (colon < 0 || colon == listenerInterface.trim().length() - 1) {
            return null;
        }
        try {
            int port = Integer.parseInt(listenerInterface.trim().substring(colon + 1).trim());
            return port >= 1 && port <= 65_535 ? port : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static void addIdentity(List<Annotations> values, Annotations candidate) {
        if (candidate == null) {
            return;
        }
        for (Annotations value : values) {
            if (value == candidate) {
                return;
            }
        }
        values.add(candidate);
    }

    private static void rateLimitedLookupWarning(String message) {
        long now = monotonicNanos.getAsLong();
        long previous = LAST_LOOKUP_WARN_NANOS.get();
        if (previous == Long.MIN_VALUE
                || now - previous >= WARN_INTERVAL_NANOS) {
            if (LAST_LOOKUP_WARN_NANOS.compareAndSet(previous, now)) {
                Logger.logWarnPanelOnly("[ProxyCorrelation] " + message);
            }
        }
    }

    private static void logUnmarkedTrackedResponse(long unmarkedCount, int messageId) {
        long now = monotonicNanos.getAsLong();
        long previous = LAST_UNMARKED_WARN_NANOS.get();
        if (previous == Long.MIN_VALUE
                || now - previous >= WARN_INTERVAL_NANOS) {
            if (LAST_UNMARKED_WARN_NANOS.compareAndSet(previous, now)) {
                Logger.logError("[ProxyCorrelation] Tracked live Proxy response lacked an active "
                        + "correlation marker: messageId=" + messageId
                        + ", unmarkedTracked=" + unmarkedCount
                        + ", httpRequests=" + HTTP_PROXY_REQUESTS.get()
                        + ", markedRequests=" + HTTP_MARKED_REQUESTS.get()
                        + ", httpResponses=" + HTTP_PROXY_RESPONSES.get()
                        + ". The document was not exported.");
            }
        }
    }

    private static void logExplicitFailure(String reason, int messageId) {
        long now = monotonicNanos.getAsLong();
        long previous = LAST_EXPLICIT_FAILURE_LOG_NANOS.get();
        if (previous == Long.MIN_VALUE
                || now - previous >= WARN_INTERVAL_NANOS) {
            if (LAST_EXPLICIT_FAILURE_LOG_NANOS.compareAndSet(previous, now)) {
                long suppressed = SUPPRESSED_EXPLICIT_FAILURE_LOGS.getAndSet(0L);
                Logger.logError("[ProxyCorrelation] Live Proxy correlation rejected: reason="
                        + reason + ", generation=" + generation + ", messageId=" + messageId
                        + ", explicitFailures=" + EXPLICIT_FAILURES.get()
                        + ", suppressed=" + suppressed
                        + "; document not exported.");
                return;
            }
        }
        SUPPRESSED_EXPLICIT_FAILURE_LOGS.incrementAndGet();
    }

    private static void logRunSummaryLocked(String phase) {
        long memoryCount = PENDING.values().stream().filter(entry -> !entry.durable).count();
        long durableCount = PENDING.values().stream().filter(entry -> entry.durable).count();
        Logger.logInfoPanelOnly("[ProxyCorrelation] Run summary (" + phase + "): generation="
                + generation
                + ", proxyRequestCallbacks=" + PROXY_REQUEST_CALLBACKS.get()
                + ", httpRequests=" + HTTP_PROXY_REQUESTS.get()
                + ", markedRequests=" + HTTP_MARKED_REQUESTS.get()
                + ", httpResponses=" + HTTP_PROXY_RESPONSES.get()
                + ", unmarkedTracked=" + HTTP_UNMARKED_TRACKED_RESPONSES.get()
                + ", unmarkedPreRun=" + HTTP_UNMARKED_UNTRACKED_RESPONSES.get()
                + ", historyLookups=" + HISTORY_LOOKUP_ATTEMPTS.get()
                + ", historyMatchedRows=" + HISTORY_LOOKUP_MATCHED_ROWS.get()
                + ", eligible=" + ELIGIBLE_TOTAL.get()
                + ", bound=" + BOUND_TOTAL.get()
                + ", pendingMemory=" + memoryCount
                + ", pendingDurable=" + durableCount
                + ", durableSpooled=" + DURABLE_TOTAL.get()
                + ", lookupFailures=" + LOOKUP_FAILURES.get()
                + ", cleanupFailures=" + CLEANUP_FAILURES.get()
                + ", spoolFailures=" + spoolFailures()
                + ", inFlightResponses=" + inFlightResponses
                + ", explicitFailures=" + EXPLICIT_FAILURES.get() + ".");
    }

    static void runReconciliationForTest() {
        long reconcileEpoch = RECONCILE_EPOCH.get();
        reconcileNow(false, reconcileEpoch, historySource);
    }

    static void registerLiveTokenForTest(
            int messageId,
            String token,
            Integer listenerPort,
            Annotations annotations) {
        OWNER.lock();
        try {
            intakeOpen = true;
            LiveToken live = new LiveToken(token, generation);
            live.messageIds.add(messageId);
            live.listenerPort = listenerPort;
            addIdentity(live.annotations, annotations);
            ProxyCorrelationToken.append(annotations, token);
            LIVE_TOKENS.put(messageId, live);
            LIVE_TOKENS_BY_TOKEN.put(token, live);
            RETIRED_MESSAGE_IDS.remove(messageId);
            RETIRED_TOKENS.remove(token);
        } finally {
            OWNER.unlock();
        }
    }

    static void dropMemoryForRestartTest() {
        intakeOpen = false;
        RECONCILE_EPOCH.incrementAndGet();
        WAKE_EPOCH.incrementAndGet();
        SCHEDULER.stop();
        reconcileOwner = new ReentrantLock();
        OWNER.lock();
        try {
            handoffOpen = false;
            LIVE_TOKENS.clear();
            LIVE_TOKENS_BY_TOKEN.clear();
            RETIRED_MESSAGE_IDS.clear();
            RETIRED_TOKENS.clear();
            PENDING.clear();
            inFlightResponses = 0;
            lateFinalizationGeneration = 0L;
            COALESCE_SCHEDULED.set(false);
            HISTORY_PRIME_PENDING.set(false);
            WORK_QUEUED.set(false);
        } finally {
            OWNER.unlock();
        }
    }

    static int pendingCountForTest() {
        OWNER.lock();
        try {
            return PENDING.size();
        } finally {
            OWNER.unlock();
        }
    }

    static boolean intakeOpenForTest() {
        return intakeOpen;
    }

    static boolean pendingDocumentLoadedForTest(String token) {
        OWNER.lock();
        try {
            DeferredEntry entry = PENDING.get(token);
            return entry != null && entry.document != null;
        } finally {
            OWNER.unlock();
        }
    }

    static void awaitPendingPersistenceForTest() {
        awaitPendingPersistence(2_000L);
    }

    static void enableSchedulerForTests() {
        schedulerEnabled = true;
        SCHEDULER.getOrStart();
    }

    static HistorySource newBurpHistorySourceForTest() {
        return new BurpHistorySource();
    }

    static void configureForTests(
            HistorySource source,
            OfferSink sink,
            ProxyCorrelationSpool testSpool,
            LongSupplier testMonotonicNanos,
            LongSupplier testEpochMillis,
            Supplier<String> testTokenSupplier,
            long testDurableThresholdMs) {
        OWNER.lock();
        try {
            historySource = source;
            offerSink = sink;
            spool = testSpool;
            monotonicNanos = testMonotonicNanos;
            epochMillis = testEpochMillis;
            tokenSupplier = testTokenSupplier;
            durableThresholdMs = testDurableThresholdMs;
            schedulerEnabled = false;
        } finally {
            OWNER.unlock();
        }
    }

    static void resetForTests() {
        awaitPendingPersistenceForTest();
        intakeOpen = false;
        RECONCILE_EPOCH.incrementAndGet();
        WAKE_EPOCH.incrementAndGet();
        SCHEDULER.stop();
        reconcileOwner = new ReentrantLock();
        ProxyCorrelationSpool previousSpool;
        OWNER.lock();
        try {
            schedulerEnabled = true;
            generation = 0L;
            handoffOpen = false;
            LIVE_TOKENS.clear();
            LIVE_TOKENS_BY_TOKEN.clear();
            RETIRED_MESSAGE_IDS.clear();
            RETIRED_TOKENS.clear();
            PENDING.clear();
            inFlightResponses = 0;
            lateFinalizationGeneration = 0L;
            previousSpool = spool;
            historySource = new BurpHistorySource();
            offerSink = TrafficExportQueue::offerAccepted;
            spool = new ProxyCorrelationSpool();
            monotonicNanos = System::nanoTime;
            epochMillis = System::currentTimeMillis;
            tokenSupplier = () -> UUID.randomUUID().toString();
            durableThresholdMs = DEFAULT_DURABLE_THRESHOLD_MS;
            ELIGIBLE_TOTAL.set(0L);
            BOUND_TOTAL.set(0L);
            DURABLE_TOTAL.set(0L);
            LOOKUP_FAILURES.set(0L);
            CLEANUP_FAILURES.set(0L);
            EXPLICIT_FAILURES.set(0L);
            PROXY_REQUEST_CALLBACKS.set(0L);
            HTTP_PROXY_REQUESTS.set(0L);
            HTTP_MARKED_REQUESTS.set(0L);
            HTTP_PROXY_RESPONSES.set(0L);
            HTTP_UNMARKED_TRACKED_RESPONSES.set(0L);
            HTTP_UNMARKED_UNTRACKED_RESPONSES.set(0L);
            HISTORY_LOOKUP_ATTEMPTS.set(0L);
            HISTORY_LOOKUP_MATCHED_ROWS.set(0L);
            LAST_LOOKUP_WARN_NANOS.set(Long.MIN_VALUE);
            LAST_UNMARKED_WARN_NANOS.set(Long.MIN_VALUE);
            LAST_EXPLICIT_FAILURE_LOG_NANOS.set(Long.MIN_VALUE);
            SUPPRESSED_EXPLICIT_FAILURE_LOGS.set(0L);
            SPOOL_FAILURE_BASELINE.set(0L);
            COALESCE_SCHEDULED.set(false);
            HISTORY_PRIME_PENDING.set(false);
            WORK_QUEUED.set(false);
            WAKE_EPOCH.set(0L);
            LAST_PERSIST_WORKER.set(null);
            ACTIVE_PERSIST_WORKERS.set(0L);
            PERSIST_RERUN_REQUESTED.set(false);
        } finally {
            OWNER.unlock();
        }
        previousSpool.clearForTests();
    }

    interface HistorySource {
        LookupBatch lookup(Set<String> tokens, LookupScope scope);

        default void forget(String token) { }

        default void reset() { }
    }

    @FunctionalInterface
    interface OfferSink {
        boolean offer(Map<String, Object> document);
    }

    enum LookupStatus {
        SUCCESS_ROWS,
        SUCCESS_EMPTY,
        LOOKUP_FAILED
    }

    enum LookupScope {
        APPENDED_ROWS,
        ALL_HISTORY
    }

    static final class LookupBatch {
        final LookupStatus status;
        final List<ProxyHttpRequestResponse> rows;
        final String failureMessage;

        private LookupBatch(
                LookupStatus status,
                List<ProxyHttpRequestResponse> rows,
                String failureMessage) {
            this.status = status;
            this.rows = rows;
            this.failureMessage = failureMessage;
        }

        static LookupBatch success(List<ProxyHttpRequestResponse> rows) {
            List<ProxyHttpRequestResponse> normalized = rows == null ? List.of() : List.copyOf(rows);
            return new LookupBatch(
                    normalized.isEmpty() ? LookupStatus.SUCCESS_EMPTY : LookupStatus.SUCCESS_ROWS,
                    normalized,
                    "");
        }

        static LookupBatch failed(String message) {
            return new LookupBatch(LookupStatus.LOOKUP_FAILED, List.of(), message == null ? "" : message);
        }
    }

    /**
     * Reads only Proxy History rows appended since the previous fresh lookup.
     *
     * <p>The first lookup scans the current snapshot once. Recovered durable entries use an
     * explicit all-History lookup on their independent cold schedule. A changed or cleared History
     * invalidates the append cursor and causes one safe rescan.</p>
     */
    private static final class BurpHistorySource implements HistorySource {
        private final Map<String, List<ProxyHttpRequestResponse>> rowsByToken = new HashMap<>();
        private int cursorSize;
        private Integer cursorLastId;
        private boolean initialized;

        @Override
        public LookupBatch lookup(Set<String> tokens, LookupScope scope) {
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null || api.proxy() == null) {
                return LookupBatch.failed("Montoya Proxy History is unavailable.");
            }
            try {
                List<ProxyHttpRequestResponse> returned = api.proxy().history();
                List<ProxyHttpRequestResponse> history =
                        returned == null ? List.of() : returned;
                int start;
                if (scope == LookupScope.ALL_HISTORY) {
                    rowsByToken.clear();
                    start = 0;
                } else {
                    start = appendedStart(history);
                }
                for (int index = start; index < history.size(); index++) {
                    ProxyHttpRequestResponse row = history.get(index);
                    if (row == null) {
                        continue;
                    }
                    try {
                        ProxyCorrelationToken.find(row.annotations())
                                .ifPresent(token -> rowsByToken
                                        .computeIfAbsent(token, ignored -> new ArrayList<>())
                                        .add(row));
                    } catch (RuntimeException e) {
                        LOOKUP_FAILURES.incrementAndGet();
                        rateLimitedLookupWarning(
                                "Malformed Proxy History row was skipped: " + e.getMessage());
                    }
                }
                updateCursor(history);
                List<ProxyHttpRequestResponse> matches = new ArrayList<>();
                for (String token : tokens) {
                    matches.addAll(rowsByToken.getOrDefault(token, List.of()));
                }
                return LookupBatch.success(matches);
            } catch (RuntimeException e) {
                return LookupBatch.failed("Proxy History lookup failed: " + e.getMessage());
            }
        }

        @Override
        public void reset() {
            rowsByToken.clear();
            initialized = false;
            cursorSize = 0;
            cursorLastId = null;
        }

        @Override
        public void forget(String token) {
            rowsByToken.remove(token);
        }

        private int appendedStart(List<ProxyHttpRequestResponse> history) {
            if (!initialized || cursorSize > history.size()) {
                rowsByToken.clear();
                return 0;
            }
            if (cursorSize == 0) {
                return 0;
            }
            try {
                ProxyHttpRequestResponse previousTail = history.get(cursorSize - 1);
                if (previousTail == null
                        || cursorLastId == null
                        || previousTail.id() != cursorLastId.intValue()) {
                    rowsByToken.clear();
                    return 0;
                }
                return cursorSize;
            } catch (RuntimeException e) {
                rowsByToken.clear();
                return 0;
            }
        }

        private void updateCursor(List<ProxyHttpRequestResponse> history) {
            cursorSize = history.size();
            cursorLastId = null;
            if (!history.isEmpty()) {
                try {
                    ProxyHttpRequestResponse tail = history.get(history.size() - 1);
                    if (tail != null) {
                        cursorLastId = tail.id();
                    }
                } catch (RuntimeException ignored) {
                    // A missing tail ID invalidates the append cursor on the next lookup.
                }
            }
            initialized = true;
        }
    }

    static final class ResponseLease implements AutoCloseable {
        /*
         * Closing is idempotent. An active lease decrements in-flight response accounting and
         * signals Stop waiters. A lease that outlives the Stop wait may also retire its original
         * generation's markers and request asynchronous persistence.
         */
        private static final ResponseLease INACTIVE = new ResponseLease(0L, false);

        private final long generation;
        private final boolean active;
        private final AtomicBoolean closed = new AtomicBoolean();

        private ResponseLease(long generation, boolean active) {
            this.generation = generation;
            this.active = active;
        }

        private static ResponseLease inactive() {
            return INACTIVE;
        }

        /** {@inheritDoc} */
        @Override
        public void close() {
            if (!active || !closed.compareAndSet(false, true)) {
                return;
            }
            long finalizeGeneration = 0L;
            OWNER.lock();
            try {
                inFlightResponses = Math.max(0, inFlightResponses - 1);
                if (inFlightResponses == 0) {
                    RESPONSES_DRAINED.signalAll();
                    if (lateFinalizationGeneration == generation) {
                        finalizeGeneration = generation;
                        lateFinalizationGeneration = 0L;
                    }
                }
            } finally {
                OWNER.unlock();
            }
            if (finalizeGeneration > 0L) {
                retireRequestOnlyMarkers(finalizeGeneration);
                persistPendingAsynchronously(finalizeGeneration);
            }
        }
    }

    private static final class LiveToken {
        private final String token;
        private final long generation;
        private final Set<Integer> messageIds = new HashSet<>();
        private final List<Annotations> annotations = new ArrayList<>();
        private Integer listenerPort;

        private LiveToken(String token, long generation) {
            this.token = token;
            this.generation = generation;
        }
    }

    private static final class DeferredEntry {
        /*
         * Identity and source metadata are immutable. Reconciliation serializes binding, cleanup,
         * retry scheduling, and History ownership. Volatile durability/state fields are also read
         * by asynchronous Stop persistence and Stats. A durable entry is persisted again after
         * binding and cleanup before destination handoff.
         */
        private final String token;
        private final int messageId;
        private final Integer listenerPort;
        private final long generation;
        private final Long requestSentMs;
        private final long createdAtEpochMs;
        private volatile Map<String, Object> document;
        private final List<Annotations> cleanupTargets;
        private volatile long estimatedBytes;
        private final boolean recovered;
        private volatile boolean durable;
        private volatile boolean bound;
        private volatile boolean cleanupComplete;
        private int lookupAttempts;
        private volatile long nextLookupAtNanos;
        private volatile long nextDurabilityAttemptAtNanos;
        private ProxyHttpRequestResponse history;

        private DeferredEntry(
                String token,
                int messageId,
                Integer listenerPort,
                long generation,
                Long requestSentMs,
                long createdAtEpochMs,
                long createdAtNanos,
                Map<String, Object> document,
                List<Annotations> cleanupTargets) {
            this.token = token;
            this.messageId = messageId;
            this.listenerPort = listenerPort;
            this.generation = generation;
            this.requestSentMs = requestSentMs;
            this.createdAtEpochMs = createdAtEpochMs;
            this.document = document;
            this.cleanupTargets = cleanupTargets;
            this.recovered = false;
            this.nextLookupAtNanos = createdAtNanos;
            this.nextDurabilityAttemptAtNanos = createdAtNanos
                    + TimeUnit.MILLISECONDS.toNanos(durableThresholdMs);
        }

        private DeferredEntry(
                ProxyCorrelationSpool.StoredEntry stored,
                long recoveredAtNanos) {
            this.token = stored.token();
            this.messageId = stored.messageId();
            this.listenerPort = stored.listenerPort();
            this.generation = stored.generation();
            this.requestSentMs = stored.requestSentMs();
            this.createdAtEpochMs = stored.createdAtEpochMs();
            this.document = null;
            this.cleanupTargets = new ArrayList<>();
            this.recovered = true;
            this.durable = true;
            this.bound = stored.bound();
            this.cleanupComplete = stored.cleanupComplete();
            this.nextLookupAtNanos = recoveredAtNanos
                    + TimeUnit.MILLISECONDS.toNanos(COLD_RETRY_MS);
            this.nextDurabilityAttemptAtNanos = Long.MAX_VALUE;
        }

        private static DeferredEntry recovered(ProxyCorrelationSpool.StoredEntry stored) {
            return new DeferredEntry(stored, monotonicNanos.getAsLong());
        }

        private void scheduleRetry(long nowNanos) {
            long delayMs;
            if (recovered) {
                delayMs = COLD_RETRY_MS;
            } else {
                int index = Math.min(lookupAttempts, FRESH_RETRY_MS.length - 1);
                delayMs = FRESH_RETRY_MS[index];
            }
            lookupAttempts++;
            nextLookupAtNanos = nowNanos + TimeUnit.MILLISECONDS.toNanos(delayMs);
        }

        private void scheduleDurabilityRetry(long nowNanos) {
            nextDurabilityAttemptAtNanos =
                    nowNanos + TimeUnit.MILLISECONDS.toNanos(FRESH_RETRY_MS[FRESH_RETRY_MS.length - 1]);
        }

        private boolean coldLane() {
            return recovered || durable;
        }

        private boolean requiresFullRescan() {
            return lookupAttempts == 2 || lookupAttempts == 5;
        }

        private void ensureEstimatedBytes() {
            if (estimatedBytes == 0L) {
                estimatedBytes = Math.max(1L, BulkPayloadEstimator.estimateBytes(document));
            }
        }

        private synchronized boolean loadDocument() {
            if (document != null) {
                return true;
            }
            ProxyCorrelationSpool.StoredEntry stored = spool.load(token);
            if (stored == null || stored.document() == null) {
                return false;
            }
            document = stored.document();
            return true;
        }

        private synchronized void releaseDurableDocument() {
            if (durable) {
                document = null;
            }
        }

        private ProxyCorrelationSpool.StoredEntry toStoredEntry() {
            return new ProxyCorrelationSpool.StoredEntry(
                    token,
                    messageId,
                    listenerPort,
                    generation,
                    requestSentMs,
                    createdAtEpochMs,
                    document,
                    bound,
                    cleanupComplete);
        }
    }
}
