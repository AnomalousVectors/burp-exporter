package ai.anomalousvectors.tools.burp.sinks;

import ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotExportEngine;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

/** Source-size admission estimates without copying or encoding message payloads. */
final class SnapshotMemoryEstimate {
    private static final long BASE_BYTES = 64L * 1024L;
    private static final long REPRESENTATION_FACTOR = 8L;

    private SnapshotMemoryEstimate() {}

    static long proxy(ProxyHttpRequestResponse item) {
        return item == null ? BASE_BYTES : http(item.finalRequest(), item.response());
    }

    static long exchange(HttpRequestResponse item) {
        return item == null ? BASE_BYTES : http(item.request(), item.response());
    }

    static long webSocket(ProxyWebSocketMessage item) {
        if (item == null) return BASE_BYTES;
        var payload = item.editedPayload();
        if (payload == null) payload = item.payload();
        return add(http(item.upgradeRequest(), null), scaled(payload == null ? 0L : payload.length()));
    }

    static long finding(AuditIssue issue) {
        if (issue == null) return BASE_BYTES;
        // Collaborator data can contain additional raw messages outside requestResponses().
        // Keep that less predictable source exclusive rather than copying it for an estimate.
        var interactions = issue.collaboratorInteractions();
        if (interactions != null && !interactions.isEmpty()) return SnapshotExportEngine.maxBuildAheadBytes();
        long bytes = add(BASE_BYTES, scaled(length(issue.detail()) + length(issue.remediation())));
        var exchanges = issue.requestResponses();
        if (exchanges != null) {
            for (HttpRequestResponse exchange : exchanges) bytes = add(bytes, exchange(exchange));
        }
        return bytes;
    }

    private static long http(HttpRequest request, HttpResponse response) {
        var requestBody = request == null ? null : request.body();
        var responseBody = response == null ? null : response.body();
        long requestBytes = requestBody == null ? 0L : Math.max(0, requestBody.length());
        long responseBytes = responseBody == null ? 0L : Math.max(0, responseBody.length());
        return add(BASE_BYTES, scaled(requestBytes + responseBytes));
    }

    private static long length(String value) {
        return value == null ? 0L : value.length();
    }

    private static long scaled(long bytes) {
        long positive = Math.max(0L, bytes);
        return positive > Long.MAX_VALUE / REPRESENTATION_FACTOR
                ? Long.MAX_VALUE : positive * REPRESENTATION_FACTOR;
    }

    private static long add(long left, long right) {
        return right > Long.MAX_VALUE - left ? Long.MAX_VALUE : left + right;
    }
}
