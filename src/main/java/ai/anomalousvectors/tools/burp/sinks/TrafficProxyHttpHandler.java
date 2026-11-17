package ai.anomalousvectors.tools.burp.sinks;

import ai.anomalousvectors.tools.burp.utils.Logger;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

/**
 * Captures live Proxy exchanges with their directly observed listener metadata.
 *
 * <p>Burp callback threads capture the initiating sent request and original server response using
 * only native Proxy message IDs. No general HTTP or History association is attempted. Shared
 * run admission, queueing, request-only timeout and Stop cleanup belong to
 * {@link TrafficHttpHandlerSupport}. Every action preserves the message, interception rules and
 * annotations; capture failures are logged without preventing forwarding.</p>
 */
public final class TrafficProxyHttpHandler extends TrafficHttpHandlerSupport
        implements ProxyRequestHandler, ProxyResponseHandler {

    /** {@inheritDoc} */
    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
        return ProxyRequestReceivedAction.continueWith(request);
    }

    /** {@inheritDoc} */
    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest request) {
        try {
            captureNativeRequest(request, request.messageId(), request.annotations(),
                    observedListenerPort(request));
        } catch (RuntimeException e) {
            Logger.logError("[Traffic] Native Proxy request capture failed safely: error="
                    + e.getClass().getSimpleName() + "; Burp traffic continued.");
        }
        return ProxyRequestToBeSentAction.continueWith(request);
    }

    /** {@inheritDoc} */
    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
        try {
            captureNativeResponse(response, response.initiatingRequest(), response.messageId(),
                    response.annotations());
        } catch (RuntimeException e) {
            Logger.logError("[Traffic] Native Proxy response capture failed safely: error="
                    + e.getClass().getSimpleName() + "; Burp traffic continued; document not exported.");
        }
        return ProxyResponseReceivedAction.continueWith(response);
    }

    /** {@inheritDoc} */
    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
        // This client-bound view can contain edits; the original response was captured earlier.
        return ProxyResponseToBeSentAction.continueWith(response);
    }

    private static Integer observedListenerPort(InterceptedRequest request) {
        try {
            return listenerPort(request.listenerInterface());
        } catch (RuntimeException e) {
            // Missing optional metadata must not discard an otherwise exportable exchange.
            return null;
        }
    }

    /**
     * Reads the numeric suffix of Burp's host:port listener name without resolving the host.
     * IPv4, bracketed/unbracketed IPv6 and wildcard bind addresses share the same port suffix.
     * Unavailable or malformed metadata remains null rather than guessing a default listener.
     */
    static Integer listenerPort(String listenerInterface) {
        if (listenerInterface == null) {
            return null;
        }
        int separator = listenerInterface.lastIndexOf(':');
        if (separator <= 0 || separator == listenerInterface.length() - 1) {
            return null;
        }
        String suffix = listenerInterface.substring(separator + 1);
        if (!suffix.chars().allMatch(c -> c >= '0' && c <= '9')) {
            return null;
        }
        try {
            int port = Integer.parseInt(suffix);
            return port >= 1 && port <= 65535 ? port : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
