package ai.anomalousvectors.tools.burp.sinks;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

/**
 * Builds {@code burp.timing.*} sub-documents for traffic-index exports.
 */
final class BurpTimingFields {

    private BurpTimingFields() { }

    /**
     * Builds timing from Montoya {@link TimingData} on a request/response pair.
     *
     * @param item request/response pair; {@code null} yields an all-null timing map
     * @return {@code burp.timing.*} sub-document keys
     */
    static Map<String, Object> from(HttpRequestResponse item) {
        String timeRequestSent = null;
        Integer timeToFirstByteMs = null;
        Integer durationMs = null;
        String timeEnd = null;
        try {
            Optional<TimingData> timingData = item == null ? Optional.empty() : item.timingData();
            if (timingData != null && timingData.isPresent()) {
                TimingData timing = timingData.get();
                ZonedDateTime sent = timing.timeRequestSent();
                if (sent != null) {
                    timeRequestSent = sent.toInstant().toString();
                }
                if (timing.timeBetweenRequestSentAndStartOfResponse() != null) {
                    timeToFirstByteMs = (int) timing.timeBetweenRequestSentAndStartOfResponse().toMillis();
                }
                if (timing.timeBetweenRequestSentAndEndOfResponse() != null) {
                    durationMs = (int) timing.timeBetweenRequestSentAndEndOfResponse().toMillis();
                    if (sent != null) {
                        timeEnd = sent.plus(timing.timeBetweenRequestSentAndEndOfResponse()).toInstant().toString();
                    }
                }
            }
        } catch (RuntimeException ignored) {
            // Montoya timing accessors may throw on restored or synthetic pairs; leave fields null.
        }
        return timingMap(timeRequestSent, timeEnd, timeToFirstByteMs, durationMs);
    }

    /**
     * Builds timing for a Proxy History row.
     *
     * <p>{@link ProxyHttpRequestResponse#time()} is not used as a fallback because Montoya defines
     * it as the time Proxy received the request, not the time Burp sent it. Burp can expose an
     * epoch request-sent time with zero durations for manually intercepted exchanges; that entire
     * timing tuple is treated as unavailable.</p>
     *
     * @param item proxy history entry; {@code null} yields an all-null timing map
     * @return {@code burp.timing.*} sub-document keys
     */
    static Map<String, Object> fromProxyHistory(ProxyHttpRequestResponse item) {
        String timeRequestSent = null;
        Integer timeToFirstByteMs = null;
        Integer durationMs = null;
        String timeEnd = null;
        if (item != null) {
            try {
                TimingData td = item.timingData();
                if (td != null) {
                    ZonedDateTime sent = td.timeRequestSent();
                    if (sent == null || !Instant.EPOCH.equals(sent.toInstant())) {
                        if (sent != null) {
                            timeRequestSent = sent.toInstant().toString();
                        }
                        var start = td.timeBetweenRequestSentAndStartOfResponse();
                        if (start != null) {
                            timeToFirstByteMs = (int) start.toMillis();
                        }
                        var end = td.timeBetweenRequestSentAndEndOfResponse();
                        if (end != null) {
                            durationMs = (int) end.toMillis();
                            if (sent != null) {
                                timeEnd = sent.plus(end).toInstant().toString();
                            }
                        }
                    }
                }
            } catch (RuntimeException ignored) {
                // Same optional-timing contract as {@link #from(HttpRequestResponse)}.
            }
        }
        return timingMap(timeRequestSent, timeEnd, timeToFirstByteMs, durationMs);
    }

    /**
     * Overlays available Proxy History timing onto timing already captured by live callbacks.
     *
     * <p>History values are authoritative when present. Missing or sentinel History values leave
     * the corresponding live value unchanged.</p>
     *
     * @param liveTiming timing captured by the live HTTP callbacks
     * @param item matching Proxy History row
     * @return complete timing map with available History values preferred
     */
    static Map<String, Object> mergeProxyHistoryOverLive(
            Map<?, ?> liveTiming,
            ProxyHttpRequestResponse item) {
        Map<String, Object> merged = timingMap(null, null, null, null);
        if (liveTiming != null) {
            for (Map.Entry<?, ?> entry : liveTiming.entrySet()) {
                if (entry.getKey() instanceof String key && merged.containsKey(key)) {
                    merged.put(key, entry.getValue());
                }
            }
        }
        fromProxyHistory(item).forEach((key, value) -> {
            if (value != null) {
                merged.put(key, value);
            }
        });
        return merged;
    }

    /**
     * Builds timing from wall-clock epoch millis on live HTTP handler callbacks (not Montoya
     * {@link TimingData}).
     *
     * @param requestSentMs request-sent epoch millis, or {@code null} when only end time is known
     * @param responseEndMs response-end epoch millis, or {@code null} when still in flight
     * @return {@code burp.timing.*} sub-document keys
     */
    static Map<String, Object> fromHandlerEpochMillis(Long requestSentMs, Long responseEndMs) {
        if (requestSentMs == null) {
            return timingMap(
                    null,
                    responseEndMs == null ? null : Instant.ofEpochMilli(responseEndMs).toString(),
                    null,
                    null);
        }
        Long durationMs = responseEndMs == null ? null : durationMillis(requestSentMs, responseEndMs);
        return timingMap(
                Instant.ofEpochMilli(requestSentMs).toString(),
                responseEndMs == null ? null : Instant.ofEpochMilli(responseEndMs).toString(),
                null,
                durationMs);
    }

    private static Map<String, Object> timingMap(
            String reqSent,
            String end,
            Integer reqSentToResStart,
            Number reqSentToResEnd) {
        Map<String, Object> timing = new LinkedHashMap<>();
        timing.put("req_sent_to_res_end", reqSentToResEnd);
        timing.put("end", end);
        timing.put("req_sent", reqSent);
        timing.put("req_sent_to_res_start", reqSentToResStart);
        return timing;
    }

    private static Long durationMillis(long startMs, long endMs) {
        long delta = endMs - startMs;
        return delta >= 0 ? delta : 0L;
    }
}
