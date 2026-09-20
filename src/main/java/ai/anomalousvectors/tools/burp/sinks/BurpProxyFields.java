package ai.anomalousvectors.tools.burp.sinks;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;

/**
 * Builds {@code burp.proxy.*} History and observable pipeline-stage fields.
 */
final class BurpProxyFields {

    private BurpProxyFields() {}

    /**
     * Builds {@code burp.proxy.*} for a Proxy History row.
     *
     * @param item proxy history row
     * @return {@code burp.proxy} sub-document map
     */
    public static Map<String, Object> forProxyHistory(ProxyHttpRequestResponse item) {
        Map<String, Object> proxy = new LinkedHashMap<>();
        proxy.put("history_id", item.id());
        proxy.put("listener_port", item.listenerPort());
        proxy.put("history_is_edited", item.edited());
        proxy.put("request_change_stages", null);
        proxy.put("response_change_stages", null);
        return proxy;
    }

    /**
     * Builds {@code burp.proxy.*} for live HTTP, Repeater tabs, or WebSocket documents.
     *
     * <p>History-backed fields and pipeline stages are unknown on these paths.</p>
     *
     * @param listenerPort listener port when known, otherwise {@code null}
     * @return {@code burp.proxy} sub-document map
     */
    public static Map<String, Object> withoutProxyHistoryEditMetadata(Integer listenerPort) {
        Map<String, Object> proxy = new LinkedHashMap<>();
        proxy.put("history_id", null);
        proxy.put("listener_port", listenerPort);
        proxy.put("history_is_edited", null);
        proxy.put("request_change_stages", null);
        proxy.put("response_change_stages", null);
        return proxy;
    }

    static Map<String, Object> withChangeStages(
            Map<String, Object> existing,
            List<String> requestChangeStages,
            List<String> responseChangeStages) {
        Map<String, Object> proxy = existing == null
                ? withoutProxyHistoryEditMetadata(null)
                : new LinkedHashMap<>(existing);
        proxy.put("request_change_stages", requestChangeStages);
        proxy.put("response_change_stages", responseChangeStages);
        return proxy;
    }
}
