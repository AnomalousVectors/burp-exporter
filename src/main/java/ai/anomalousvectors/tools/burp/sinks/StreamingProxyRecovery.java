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
import ai.anomalousvectors.tools.burp.utils.export.SearchDocumentRevision;
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
 * overlap a request-only live Proxy observation; no cross-API pairing is attempted. Search
 * destinations replace one exact capture's document using ordered revisions; Files append each
 * admitted snapshot. All History reads and message preparation run on one bounded, cost-paced
 * worker, never on a forwarding callback or the EDT. Admitted snapshots use the traffic queue
 * for asynchronous destination delivery. A five-minute observation deadline is not HTTP completion.</p>
 *
 * <p>History display IDs can repeat after project imports. Pre-run requests are excluded before
 * tracking lookup; current-run captures also retain the request's received time and listener port
 * so an imported row cannot replace or suppress a new live exchange with the same display ID.</p>
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
    private final Map<HistoryRowKey, Capture> tracked = new LinkedHashMap<>();
    private final Set<HistoryRowKey> baseline = java.util.Collections.synchronizedSet(new HashSet<>());
    private final StreamingPollPolicy policy = new StreamingPollPolicy();
    private final StreamingRecoveryLog diagnostics;
    private final AtomicLong discoveryUntil = new AtomicLong();
    private volatile boolean closed;
    private volatile boolean finishing;
    private volatile long finalReadDeadline = Long.MAX_VALUE;
    private boolean initialized;
    private long nextDiscovery;
    private long snapshots;
    private long expired;
    private long rejected;
    private long failures;
    private long removed;
    private long snapshotWireBytes;
    private volatile int finalUnread;
    private boolean finalPass;
    private boolean capacityPressure;
    private StreamingResponseRules rules = StreamingResponseRules.empty();

    StreamingProxyRecovery(MontoyaApi api, ExportRunToken token, LongSupplier clock,
            BiPredicate<Map<String, Object>, ExportRunToken> output, long wallMs) {
        this.api = api;
        this.token = token;
        this.clock = clock;
        this.output = output;
        startedWallMs = wallMs;
        startedMs = clock.getAsLong();
        diagnostics = new StreamingRecoveryLog(clock);
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
     * closure or into a new run. Final reads receive at most half the remaining Stop time and
     * leave a delivery/cleanup reserve; they do not extend the shared deadline. Safe to call
     * repeatedly, off the EDT. Interrupted waits preserve the caller's interrupt status.</p>
     */
    public static void stop() {
        StreamingProxyRecovery observer;
        long readBudgetMs;
        synchronized (OWNER) {
            observer = current;
            // One Stop owner submits the final read; concurrent lifecycle cleanup is a no-op.
            if (observer == null || observer.finishing) return;
            readBudgetMs = StreamingPollPolicy.finalReadBudgetMs(
                    RuntimeConfig.remainingExportStopBudgetMs());
            observer.finalReadDeadline = observer.clock.getAsLong() + readBudgetMs;
            observer.finishing = true;
            observer.finalUnread = -1;
        }
        if (observer != null && RuntimeConfig.isExportStopping()
                && readBudgetMs > 0L
                && observer.active() && SCHEDULER.peek() != null) {
            var finalRead = SCHEDULER.peek().submit(observer::observeFinalSnapshots);
            try {
                finalRead.get(readBudgetMs, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                finalRead.cancel(true);
            } catch (java.util.concurrent.TimeoutException e) {
                finalRead.cancel(true);
                Logger.logWarnPanelOnly("[StreamingRecovery] Final observation exceeded its Stop "
                        + "allowance; remaining time is reserved for delivery and cleanup.");
            } catch (java.util.concurrent.ExecutionException e) {
                finalRead.cancel(true);
                Logger.logWarnPanelOnly("[StreamingRecovery] Final observation failed; "
                        + "earlier snapshots are retained.");
            }
        }
        synchronized (OWNER) {
            observer.closed = true;
            if (current == observer) current = null;
            // Do not let a new Start acquire the old scheduler while teardown is in progress.
            SCHEDULER.stop();
        }
        if (observer != null) {
            observer.diagnostics.flush(true);
            if (observer.finalUnread != 0 && observer.initialized) {
                Logger.logWarnPanelOnly("[StreamingRecovery] Final refresh incomplete: unread="
                        + (observer.finalUnread < 0 ? "not_attempted" : observer.finalUnread)
                        + "; response tails may be absent from retained snapshots.");
            }
            lastSummary = "Stopped; " + observer.summary();
            Logger.logInfoPanelOnly("[StreamingRecovery] " + lastSummary
                    + "; retained snapshots are observations, not proof of complete responses.");
        }
    }

    /** Returns the latest payload-free worker status for both file and search Stats. */
    public static String status() {
        return lastSummary;
    }

    // The single worker owns this final pass. The Stop caller still enforces the absolute budget
    // and closes publication even if a public API read does not respond to interruption.
    void observeFinalSnapshots() {
        finishing = true;
        finalPass = true;
        finalUnread = tracked.size();
        tracked.values().forEach(c -> c.nextRead = 0L);
        tickSafely();
    }

    private static boolean enabled(ExportRunToken token) {
        return RuntimeConfig.isExportRunActive(token) && !RuntimeConfig.isExportStopping()
                && RuntimeConfig.trafficExportGate().includesToolType("proxy");
    }

    private boolean active() {
        // Normal UI Stop keeps the token active until accepted work drains; cleanup callers may
        // have invalidated it already. Both paths must refer to this exact run, never a later one.
        boolean ownsStoppingRun = RuntimeConfig.isExportRunActive(token)
                || (token.equals(RuntimeConfig.lastInvalidatedExportRunToken())
                && !RuntimeConfig.currentExportRunToken().isValid());
        return !closed && (!finishing || clock.getAsLong() < finalReadDeadline)
                && (enabled(token) || (finishing && RuntimeConfig.isExportStopping()
                && ownsStoppingRun
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
                diagnostics.warn(StreamingRecoveryLog.Reason.INITIALIZATION,
                        "History recovery initialization failed (" + e.getClass().getSimpleName()
                        + "); live HTTP capture continues without streaming recovery");
            } else {
                diagnostics.warn(StreamingRecoveryLog.Reason.HISTORY,
                        "History read failed; previously captured snapshots are retained");
            }
        } finally {
            // A late non-cooperative read must not overwrite a newer run's status/log window.
            if (!closed || (current == this && !initialized)) {
                lastSummary = summary();
                diagnostics.flush(false);
            }
        }
    }

    private String summary() {
        return "tracking=" + tracked.size() + "/" + StreamingPollPolicy.MAX_TRACKED
                + ", snapshots=" + snapshots + ", cutoff=" + expired
                + ", capacity_checks=" + rejected + ", removed=" + removed + ", failures=" + failures
                + ", snapshot_wire_bytes=" + snapshotWireBytes + ", final_unread="
                + (finalUnread < 0 ? "not_attempted" : finalUnread);
    }

    // One worker owns mutable tracking state. Tests drive this method with a deterministic clock.
    void tick() {
        long now = clock.getAsLong();
        if (!active()) return;
        if (!initialized) {
            long began = clock.getAsLong();
            // Imported rows keep their full context; a display ID alone must not exclude live work.
            api.proxy().history(row -> {
                if (baseline.size() >= 250_000) {
                    throw new IllegalStateException("History baseline capacity");
                }
                HistoryRowKey key = rowKey(row);
                if (key != null && key.received().toEpochMilli() < startedWallMs) baseline.add(key);
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
        capacityPressure = false;
        Map<HistoryRowKey, ProxyHttpRequestResponse> selected = new HashMap<>();
        // The predicate must remain metadata-only; payload acquisition happens after enumeration.
        api.proxy().history(row -> select(row, now, discover, selected));
        if (discover) nextDiscovery = now + 5_000L;
        // Expensive reads are individually budgeted. Leave other due rows for a later turn.
        List<Capture> ready = new ArrayList<>(tracked.values());
        // Oldest attempted reads win among due rows. A repeatedly growing large body cannot
        // keep overtaking unread small exchanges just because its original deadline is older.
        ready.sort(Comparator.comparingLong(c -> c.lastRead));
        int reads = 0;
        for (Capture capture : ready) {
            if (!active()) break;
            if (capture.nextRead > now) continue;
            ProxyHttpRequestResponse row = selected.get(capture.key);
            if (row == null) {
                tracked.remove(capture.key);
                removed++;
                continue;
            }
            // Share enumeration across cheap reads; a single costly read ends this pass.
            if (!finishing && reads > 0 && clock.getAsLong() - began >= 100L) break;
            try {
                capture.lastRead = now;
                boolean refreshed = read(capture, row, now);
                if (finalPass && refreshed) finalUnread--;
            } catch (RuntimeException e) {
                failures++;
                capture.nextRead = now + StreamingPollPolicy.intervalMs(
                        StreamingPollPolicy.WINDOW_MS - (capture.deadline - now));
                diagnostics.warn(StreamingRecoveryLog.Reason.OBSERVATION,
                        "A stream observation failed; other exchanges remain eligible");
            }
            reads++;
        }
        policy.charge(began, clock.getAsLong());
        if (discover) diagnostics.capacity(capacityPressure);
    }

    // Burp may invoke filter predicates on its own threads; do not assume worker-thread affinity.
    private synchronized boolean select(ProxyHttpRequestResponse row, long now, boolean discover,
            Map<HistoryRowKey, ProxyHttpRequestResponse> selected) {
        if (!active()) return false;
        HistoryRowKey key = rowKey(row);
        if (key == null) return false;
        long received = key.received().toEpochMilli();
        long deadline = startedMs + (received - startedWallMs) + StreamingPollPolicy.WINDOW_MS;
        // Fence every read, including refreshes: an imported row must never stand in for a live row.
        if (received < startedWallMs || received > startedWallMs + (now - startedMs)
                || now >= deadline) return false;
        Capture known = tracked.get(key);
        if (known != null) {
            if (known.nextRead <= now) selected.put(key, row);
            return false;
        }
        if (!discover || baseline.contains(key)) return false;
        diagnostics.candidate();
        if (tracked.size() >= StreamingPollPolicy.MAX_TRACKED) {
            rejected++;
            capacityPressure = true;
            return false;
        }
        // A missing response may still become a stream; descriptors contain no payload views.
        Capture capture = new Capture(key, deadline, now);
        tracked.put(key, capture);
        selected.put(key, row);
        return false;
    }

    private boolean read(Capture capture, ProxyHttpRequestResponse row, long now) {
        long age = StreamingPollPolicy.WINDOW_MS - (capture.deadline - now);
        capture.nextRead = Math.min(capture.deadline, now + StreamingPollPolicy.intervalMs(age));
        HttpRequest request = row.finalRequest();
        if (request == null) return false;
        boolean inScope = request.isInScope();
        String url = request.url();
        if (!ScopeFilter.shouldExport(RuntimeConfig.getState(), url, inScope)) {
            // A held request can still be edited into scope. Once a response exists, its sent
            // request is authoritative and an excluded row must not occupy a stream slot.
            if (row.hasResponse()) retire(capture);
            return true;
        }
        if (!row.hasResponse()) return true;
        // Burp's inferred History MIME can be UNRECOGNIZED even while its UI labels the row SSE.
        // Acquiring the original public response for header classification may itself copy bytes;
        // account for that cost on this worker, never inside the metadata filter or a callback.
        HttpResponse response = row.originalResponse();
        if (response == null || clock.getAsLong() >= capture.deadline) return false;
        String contentType = response.headerValue("Content-Type");
        boolean declaredSse = contentType != null
                && "text/event-stream".equalsIgnoreCase(contentType.split(";", 2)[0].trim());
        boolean stream = capture.stream || declaredSse || rules.matches(url);
        if (!stream) {
            // Classification is sufficient; do not build/hash/export ordinary response bodies.
            retire(capture);
            return true;
        }
        capture.stream = true;
        if (!active()) return false;
        var preparedResponse = RequestResponseDocBuilder.prepareTrafficResponse(response);
        long wireBytes = preparedResponse.wireBodyLength();
        capture.nextRead = Math.min(capture.deadline,
                now + StreamingPollPolicy.intervalMs(age, wireBytes));
        if (!active()) return false;
        var preparedRequest = RequestResponseDocBuilder.prepareTrafficRequest(request);
        Map<String, Object> document = document(
                row, request, preparedRequest.document(), preparedResponse.document(), inScope);
        String preparationSignature = SnapshotFingerprint.of(Map.of(
                "document", document, "request_body_inputs", preparedRequest.bodyInputs(),
                "response_body_inputs", preparedResponse.bodyInputs()));
        if (preparationSignature.equals(capture.preparationSignature) && !finishing) {
            diagnostics.unchanged();
            return true;
        }
        preparedRequest.complete();
        preparedResponse.complete();
        String signature = SnapshotFingerprint.of(document);
        if (signature.equals(capture.signature) && !finishing) {
            capture.preparationSignature = preparationSignature;
            diagnostics.unchanged();
            return true;
        }
        Map<String, Object> observation = new LinkedHashMap<>();
        observation.put("id", capture.captureId);
        observation.put("source", "proxy_history_stream");
        observation.put("revision", capture.revision + 1L);
        observation.put("observed_at", Instant.now().toString());
        observation.put("window_ends_at", Instant.ofEpochMilli(startedWallMs
                + capture.deadline - startedMs).toString());
        observation.put("response_state", responseState(response, document));
        observation.put("observation_state", finishing ? "stopped" : "observing");
        if (contentType != null && contentType.toLowerCase(java.util.Locale.ROOT).startsWith("application/grpc")) {
            observation.put("grpc_status_state", response.headerValue("grpc-status") == null
                    ? "not_observed" : "observed");
        }
        Map<String, Object> meta = ExportMetaFields.meta("1");
        meta.put("capture", observation);
        document.put("meta", meta);
        boolean accepted = active() && clock.getAsLong() < capture.deadline && (output == null
                ? TrafficExportQueue.offerStreamingObservationForRun(document, token, this::active,
                        new SearchDocumentRevision(
                                capture.captureId, capture.revision + 1L))
                : output.test(document, token));
        if (!closed) diagnostics.snapshot(accepted);
        if (accepted) {
            capture.revision++;
            capture.signature = signature;
            capture.preparationSignature = preparationSignature;
            snapshots++;
            snapshotWireBytes += wireBytes;
        }
        return accepted;
    }

    private void retire(Capture capture) {
        tracked.remove(capture.key);
        if (baseline.size() < 250_000) baseline.add(capture.key);
    }

    private static Map<String, Object> document(ProxyHttpRequestResponse row, HttpRequest request,
            Map<String, Object> requestDoc, Map<String, Object> response, boolean inScope) {
        Map<String, Object> document = new LinkedHashMap<>();
        Map<String, Object> burp = new LinkedHashMap<>();
        burp.put("reporting_tool", "Proxy");
        burp.put("is_in_scope", inScope);
        burp.put("message_id", row.id());
        burp.put("proxy", BurpProxyFields.forProxyHistory(row));
        burp.put("timing", BurpTimingFields.fromProxyHistory(row));
        BurpAnnotationFields.put(burp, row.annotations());
        document.put("burp", burp);
        requestDoc.put("url", HttpMessageDocSupport.urlObject(request.url(), row.httpService()));
        requestDoc.put("protocol", TrafficProtocolFields.requestProtocol(
                RequestResponseDocBuilder.safeRequestHttpVersion(request)));
        document.put("request", requestDoc);
        document.put("response", response);
        document.put("websocket", WebSocketTrafficDocumentBuilder.notWebSocket());
        return document;
    }

    private static HistoryRowKey rowKey(ProxyHttpRequestResponse row) {
        java.time.ZonedDateTime time = row.time();
        return time == null ? null : new HistoryRowKey(row.id(), time.toInstant(), row.listenerPort());
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

    // Metadata-only current-run context survives fresh API wrappers without hashing message bytes.
    private record HistoryRowKey(int id, Instant received, int listenerPort) { }

    private static final class Capture {
        private final HistoryRowKey key;
        private final long deadline;
        private final String captureId = UUID.randomUUID().toString();
        private long nextRead;
        private long lastRead;
        private long revision;
        private String signature = "";
        private String preparationSignature = "";
        private boolean stream;

        private Capture(HistoryRowKey key, long deadline, long now) {
            this.key = key;
            this.deadline = deadline;
            nextRead = now;
        }
    }
}
