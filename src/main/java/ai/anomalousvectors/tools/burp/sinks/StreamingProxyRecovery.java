package ai.anomalousvectors.tools.burp.sinks;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiPredicate;
import java.util.function.LongSupplier;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.ScopeFilter;
import ai.anomalousvectors.tools.burp.utils.concurrent.LazyScheduler;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

/**
 * Observes retained streaming responses for live Proxy export without changing traffic or Notes.
 *
 * <p>Each exact History row owns an independent capture. Immutable, numbered snapshots may
 * overlap a request-only live HTTP observation; no cross-API pairing is attempted. All History
 * reads, message preparation and delivery run on one bounded, cost-paced worker, never on a
 * forwarding callback or the EDT. A five-minute observation deadline is not HTTP completion.</p>
 */
public final class StreamingProxyRecovery {
    private static final Object OWNER = new Object();
    private static final LazyScheduler SCHEDULER = new LazyScheduler("burp-exporter-stream-recovery");
    private static volatile StreamingProxyRecovery current;
    private static volatile String lastSummary = "Not running";
    private final MontoyaApi api;
    private final ExportRunToken token;
    private final LongSupplier clock;
    private final BiPredicate<Map<String, Object>, ExportRunToken> output;
    private final long startedWallMs;
    private final long startedMs;
    private final Map<Integer, Capture> tracked = new LinkedHashMap<>();
    private final Set<Integer> baseline = java.util.Collections.synchronizedSet(new HashSet<>());
    private final StreamingPollPolicy policy = new StreamingPollPolicy();
    private final AtomicLong discoveryUntil = new AtomicLong();
    private volatile boolean closed;
    private volatile boolean finishing;
    private boolean initialized;
    private long nextDiscovery;
    private long snapshots;
    private long expired;
    private long rejected;
    private long failures;
    private long removed;
    private long lastWarning;
    private int diagnosticRows;
    private StreamingResponseRules rules = StreamingResponseRules.empty();

    StreamingProxyRecovery(MontoyaApi api, ExportRunToken token, LongSupplier clock,
            BiPredicate<Map<String, Object>, ExportRunToken> output, long wallMs) {
        this.api = api;
        this.token = token;
        this.clock = clock;
        this.output = output;
        startedWallMs = wallMs;
        startedMs = clock.getAsLong();
    }

    /**
     * Starts one run-owned observer when live Proxy export is selected.
     *
     * <p>Called from the background Start owner. Repeated calls for the same run are harmless;
     * Stop/unload owns teardown. No History payload is acquired by this method.</p>
     */
    public static void start() {
        synchronized (OWNER) {
            ExportRunToken token = RuntimeConfig.currentExportRunToken();
            if (!enabled(token) || current != null) return;
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null || api.proxy() == null) return;
            StreamingProxyRecovery fresh = new StreamingProxyRecovery(api, token,
                    () -> TimeUnit.NANOSECONDS.toMillis(System.nanoTime()),
                    null, System.currentTimeMillis());
            current = fresh;
            SCHEDULER.getOrStart().scheduleWithFixedDelay(fresh::tickSafely, 0L, 250L,
                    TimeUnit.MILLISECONDS);
        }
    }

    /**
     * Coalesces a live Proxy request notification into worker discovery; never reads History.
     *
     * <p>The atomic deadline is payload-free and does not identify a History row. Only an already
     * running observer may be awakened, so late callbacks cannot recreate a stopped worker.</p>
     */
    public static void requestObserved() {
        StreamingProxyRecovery observer = current;
        if (observer != null && !observer.closed && enabled(observer.token)) {
            observer.discoveryUntil.accumulateAndGet(
                    observer.clock.getAsLong() + StreamingPollPolicy.WINDOW_MS, Math::max);
        }
    }

    /**
     * Fences publication and stops the owned worker within the shared shutdown budget.
     *
     * <p>Available snapshots already admitted to the normal queue drain normally. Unread later
     * bytes are not claimed as captured; non-cooperative public API reads cannot publish after
     * closure or into a new run. Safe to call repeatedly, off the EDT.</p>
     */
    public static void stop() {
        StreamingProxyRecovery observer;
        synchronized (OWNER) {
            observer = current;
            // One Stop owner submits the final read; concurrent lifecycle cleanup is a no-op.
            if (observer == null || observer.finishing) return;
            observer.finishing = true;
        }
        if (observer != null && RuntimeConfig.isExportStopping()
                && RuntimeConfig.remainingExportStopBudgetMs() > 0L
                && observer.active() && SCHEDULER.peek() != null) {
            var finalRead = SCHEDULER.peek().submit(() -> {
                observer.tracked.values().forEach(c -> c.nextRead = 0L);
                observer.tickSafely();
            });
            try {
                finalRead.get(Math.min(1_000L, RuntimeConfig.remainingExportStopBudgetMs()),
                        TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                finalRead.cancel(true);
            } catch (java.util.concurrent.ExecutionException | java.util.concurrent.TimeoutException e) {
                finalRead.cancel(true);
                Logger.logWarnPanelOnly("[StreamingRecovery] Final observation did not finish within "
                        + "the Stop budget; earlier snapshots are retained.");
            }
        }
        synchronized (OWNER) {
            observer.closed = true;
            if (current == observer) current = null;
            // Do not let a new Start acquire the old scheduler while teardown is in progress.
            SCHEDULER.stop();
        }
        if (observer != null) {
            lastSummary = "Stopped; " + lastSummary;
            Logger.logInfoPanelOnly("[StreamingRecovery] " + lastSummary
                    + "; retained snapshots are observations, not proof of complete responses.");
        }
    }

    /** Returns the latest payload-free worker status for both file and search Stats. */
    public static String status() {
        return lastSummary;
    }

    private static boolean enabled(ExportRunToken token) {
        return RuntimeConfig.isExportRunActive(token) && !RuntimeConfig.isExportStopping()
                && RuntimeConfig.trafficExportGate().includesToolType("proxy");
    }

    private boolean active() {
        return !closed && (enabled(token) || (finishing && RuntimeConfig.isExportStopping()
                && token.equals(RuntimeConfig.lastInvalidatedExportRunToken())
                && !RuntimeConfig.currentExportRunToken().isValid()
                && !RuntimeConfig.isExportStopForceAbortRequested()
                && !RuntimeConfig.isExportStopBudgetExpired()));
    }

    private void tickSafely() {
        if (!active()) return;
        try {
            tick();
        } catch (RuntimeException e) {
            failures++;
            if (!initialized) {
                closed = true;
                warn("History recovery initialization failed (" + e.getClass().getSimpleName()
                        + "); live HTTP capture continues without streaming recovery");
            } else {
                warn("History read failed; previously captured snapshots are retained");
            }
        } finally {
            lastSummary = "tracking=" + tracked.size() + "/" + StreamingPollPolicy.MAX_TRACKED
                    + ", snapshots=" + snapshots + ", cutoff=" + expired
                    + ", capacity_checks=" + rejected + ", removed=" + removed + ", failures=" + failures;
        }
    }

    // One worker owns mutable tracking state. Tests drive this method with a deterministic clock.
    void tick() {
        long now = clock.getAsLong();
        if (!active()) return;
        if (!initialized) {
            long began = clock.getAsLong();
            // Baseline IDs plus request-time fencing exclude old/imported project backlog.
            api.proxy().history(row -> {
                if (baseline.size() >= 250_000) {
                    throw new IllegalStateException("History baseline capacity");
                }
                if (receivedMs(row) < startedWallMs) baseline.add(row.id());
                return false;
            });
            rules = StreamingResponseRules.read(api);
            initialized = true;
            discoveryUntil.set(now + StreamingPollPolicy.WINDOW_MS);
            policy.charge(began, clock.getAsLong());
            return;
        }
        tracked.values().removeIf(capture -> {
            if (now >= capture.deadline) {
                expired++;
                return true;
            }
            return false;
        });
        if (!finishing && now < policy.allowedAt()) return;
        boolean discover = !finishing && now >= nextDiscovery && now <= discoveryUntil.get();
        boolean due = tracked.values().stream().anyMatch(c -> c.nextRead <= now);
        if (!discover && !due) return;
        long began = clock.getAsLong();
        Map<Integer, ProxyHttpRequestResponse> selected = new HashMap<>();
        // The predicate must remain metadata-only; payload acquisition happens after enumeration.
        api.proxy().history(row -> select(row, now, discover, selected));
        if (discover) nextDiscovery = now + 5_000L;
        // Expensive reads are individually budgeted. Leave other due rows for a later turn.
        List<Capture> ready = new ArrayList<>(tracked.values());
        ready.sort(Comparator.comparingLong(c -> c.nextRead));
        int reads = 0;
        for (Capture capture : ready) {
            if (!active()) break;
            if (capture.nextRead > now) continue;
            ProxyHttpRequestResponse row = selected.get(capture.id);
            if (row == null) {
                tracked.remove(capture.id);
                removed++;
                continue;
            }
            // Share enumeration across cheap reads; a single costly read ends this pass.
            if (reads > 0 && clock.getAsLong() - began >= 100L) break;
            try {
                read(capture, row, now);
            } catch (RuntimeException e) {
                failures++;
                capture.nextRead = now + StreamingPollPolicy.intervalMs(
                        StreamingPollPolicy.WINDOW_MS - (capture.deadline - now));
                warn("A stream observation failed; other exchanges remain eligible");
            }
            reads++;
        }
        policy.charge(began, clock.getAsLong());
        if (rejected > 0L) warn("Tracking capacity reached; some exchanges may not be observed");
    }

    // Burp may invoke filter predicates on its own threads; do not assume worker-thread affinity.
    private synchronized boolean select(ProxyHttpRequestResponse row, long now, boolean discover,
            Map<Integer, ProxyHttpRequestResponse> selected) {
        if (!active()) return false;
        int id = row.id();
        Capture known = tracked.get(id);
        if (known != null) {
            if (known.nextRead <= now) selected.put(id, row);
            return false;
        }
        if (!discover || baseline.contains(id)) return false;
        long received = receivedMs(row);
        long deadline = startedMs + (received - startedWallMs) + StreamingPollPolicy.WINDOW_MS;
        if (received < startedWallMs || received > startedWallMs + (now - startedMs)
                || now >= deadline) return false;
        if (diagnosticRows++ < 32) {
            Logger.logDebug("[StreamingRecovery] Candidate: history_id=" + id
                    + ", has_response=" + row.hasResponse() + ", mime=" + row.mimeType() + ".");
        }
        if (tracked.size() >= StreamingPollPolicy.MAX_TRACKED) {
            rejected++;
            return false;
        }
        // A missing response may still become a stream; descriptors contain no payload views.
        Capture capture = new Capture(id, deadline, now);
        tracked.put(id, capture);
        selected.put(id, row);
        return false;
    }

    private void read(Capture capture, ProxyHttpRequestResponse row, long now) {
        long age = StreamingPollPolicy.WINDOW_MS - (capture.deadline - now);
        capture.nextRead = Math.min(capture.deadline, now + StreamingPollPolicy.intervalMs(age));
        HttpRequest request = row.finalRequest();
        if (request == null) return;
        boolean inScope = request.isInScope();
        String url = request.url();
        if (!ScopeFilter.shouldExport(RuntimeConfig.getState(), url, inScope)) {
            // A held request can still be edited into scope. Once a response exists, its sent
            // request is authoritative and an excluded row must not occupy a stream slot.
            if (row.hasResponse()) retire(capture);
            return;
        }
        if (!row.hasResponse()) return;
        // Burp's inferred History MIME can be UNRECOGNIZED even while its UI labels the row SSE.
        // Acquiring the original public response for header classification may itself copy bytes;
        // account for that cost on this worker, never inside the metadata filter or a callback.
        HttpResponse response = row.originalResponse();
        if (response == null || clock.getAsLong() >= capture.deadline) return;
        String contentType = response.headerValue("Content-Type");
        boolean declaredSse = contentType != null
                && "text/event-stream".equalsIgnoreCase(contentType.split(";", 2)[0].trim());
        boolean stream = capture.stream || declaredSse || rules.matches(url);
        if (!stream) {
            // Classification is sufficient; do not build/hash/export ordinary response bodies.
            retire(capture);
            return;
        }
        capture.stream = true;
        Map<String, Object> document = document(row, request, response, inScope);
        String signature = SnapshotFingerprint.of(document);
        if (signature.equals(capture.signature) && !finishing) return;
        Map<String, Object> observation = new LinkedHashMap<>();
        observation.put("id", capture.captureId);
        observation.put("source", "proxy_history_stream");
        observation.put("revision", capture.revision + 1L);
        observation.put("observed_at", Instant.now().toString());
        observation.put("window_ends_at", Instant.ofEpochMilli(startedWallMs
                + capture.deadline - startedMs).toString());
        observation.put("response_state", responseState(response, document));
        observation.put("observation_state", finishing ? "stopped" : "observing");
        Map<String, Object> meta = ExportMetaFields.meta("1");
        meta.put("capture", observation);
        document.put("meta", meta);
        boolean accepted = active() && clock.getAsLong() < capture.deadline && (output == null
                ? TrafficExportQueue.offerStreamingObservationForRun(document, token, this::active)
                : output.test(document, token));
        Logger.logDebug("[StreamingRecovery] Snapshot: history_id=" + capture.id
                + ", revision=" + (capture.revision + 1L) + ", admitted=" + accepted + ".");
        if (accepted) {
            capture.revision++;
            capture.signature = signature;
            snapshots++;
        }
    }

    private void retire(Capture capture) {
        tracked.remove(capture.id);
        if (baseline.size() < 250_000) baseline.add(capture.id);
    }

    private static Map<String, Object> document(ProxyHttpRequestResponse row, HttpRequest request,
            HttpResponse response, boolean inScope) {
        Map<String, Object> document = new LinkedHashMap<>();
        Map<String, Object> burp = new LinkedHashMap<>();
        burp.put("reporting_tool", "Proxy");
        burp.put("is_in_scope", inScope);
        burp.put("message_id", row.id());
        burp.put("proxy", BurpProxyFields.forProxyHistory(row));
        burp.put("timing", BurpTimingFields.fromProxyHistory(row));
        BurpAnnotationFields.put(burp, row.annotations());
        document.put("burp", burp);
        Map<String, Object> requestDoc = RequestResponseDocBuilder.buildTrafficRequestDoc(request);
        requestDoc.put("url", HttpMessageDocSupport.urlObject(request.url(), row.httpService()));
        requestDoc.put("protocol", TrafficProtocolFields.requestProtocol(
                RequestResponseDocBuilder.safeRequestHttpVersion(request)));
        document.put("request", requestDoc);
        document.put("response", response == null ? RequestResponseDocBuilder.emptyTrafficResponseDoc()
                : RequestResponseDocBuilder.buildTrafficResponseDoc(response));
        document.put("websocket", WebSocketTrafficDocumentBuilder.notWebSocket());
        return document;
    }

    private static long receivedMs(ProxyHttpRequestResponse row) {
        java.time.ZonedDateTime time = row.time();
        return time == null ? Long.MIN_VALUE / 2L : time.toInstant().toEpochMilli();
    }

    // Length agreement is not end-of-stream proof. Encoded/transfer-framed views are left unknown.
    private static String responseState(HttpResponse response, Map<String, Object> document) {
        if (response == null) return "not_observed";
        String declared = response.headerValue("Content-Length");
        if (declared != null && response.headerValue("Content-Encoding") == null
                && response.headerValue("Transfer-Encoding") == null) {
            try {
                long expected = Long.parseLong(declared.trim());
                Object responseDoc = document.get("response");
                if (expected >= 0L && responseDoc instanceof Map<?, ?> responseMap
                        && responseMap.get("body") instanceof Map<?, ?> body
                        && body.get("length") instanceof Number length) {
                    if (length.longValue() < expected) return "incomplete_declared_length";
                    if (length.longValue() > expected) return "inconsistent_declared_length";
                }
            } catch (NumberFormatException ignored) {
                // Malformed or combined lengths cannot prove framing, but the payload is preserved.
            }
        }
        return "observed_completion_unknown";
    }

    private void warn(String reason) {
        long now = clock.getAsLong();
        if (lastWarning == 0L || now - lastWarning >= 30_000L) {
            lastWarning = now;
            Logger.logWarnPanelOnly("[StreamingRecovery] " + reason + ".");
        }
    }

    private static final class Capture {
        private final int id;
        private final long deadline;
        private final String captureId = UUID.randomUUID().toString();
        private long nextRead;
        private long revision;
        private String signature = "";
        private boolean stream;

        private Capture(int id, long deadline, long now) {
            this.id = id;
            this.deadline = deadline;
            nextRead = now;
        }
    }
}
