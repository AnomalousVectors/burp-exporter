package ai.anomalousvectors.tools.burp.ui.text;

/**
 * High-level tooltips for parent (directory) nodes in the Config Fields catalog.
 * Leaf field detail lives in {@link ExportFieldTooltips}.
 */
public final class ExportFieldSectionTooltips {

    private ExportFieldSectionTooltips() {}

    public static String sectionTooltipFor(String indexShortName, String sectionPath) {
        return Tooltips.html(descriptionFor(indexShortName, sectionPath));
    }

    private static String descriptionFor(String indexShortName, String sectionPath) {
        return switch (indexShortName) {
            case "traffic" -> trafficDescription(sectionPath);
            case "settings" -> settingsDescription(sectionPath);
            case "sitemap" -> sitemapDescription(sectionPath);
            case "findings" -> findingsDescription(sectionPath);
            case "exporter" -> exporterDescription(sectionPath);
            default -> genericDescription(sectionPath);
        };
    }

    private static String genericDescription(String sectionPath) {
        return "Optional fields grouped under " + sectionPath
                + ". Use the tri-state checkbox to enable or disable all toggleable children.";
    }

    // --- traffic ---

    private static String trafficDescription(String path) {
        return switch (path) {
            case "burp" ->
                    "Burp tool attribution, scope, message correlation, user annotations, and nested proxy, repeater, and timing groups.";
            case "burp.proxy" ->
                    "Proxy History HTTP pair identifiers and edit flags (not used for live handler traffic or WebSocket frames).";
            case "burp.repeater" ->
                    "Best-effort Repeater tab name and tab-group labels for Repeater-origin traffic.";
            case "burp.timing" ->
                    "Start, end, duration, and latency timestamps for live HTTP, Proxy History, and WebSocket traffic.";
            case "meta" ->
                    "Required document metadata (always exported as a whole). Expand to see sub-fields; "
                            + "individual meta leaves are shown for visibility only and cannot be disabled.";
            case "request" ->
                    "HTTP request URL, method, path, service, headers, body, parameters, markers, and protocol facets.";
            case "request.body" ->
                    "Request wire bytes, deepest successful Content-Encoding decode, chain status, and searchable text when bytes classify as text.";
            case "request.body.content_encoding" ->
                    "Progressive Content-Encoding decode status: layers applied, layers remaining, and whether the chain completed.";
            case "request.headers" -> "Ordered request header rows with normalized names, raw names, values, and ordinals.";
            case "request.cookies" -> "Cookie header pairs parsed from the request.";
            case "request.body.markers" -> "Request highlight ranges (inclusive start, exclusive end offsets).";
            case "request.markers" -> "Request highlight ranges (inclusive start, exclusive end offsets).";
            case "request.parameters" -> "Parsed request parameters from the query string and body.";
            case "request.protocol" -> "HTTP version from the request line.";
            case "response" ->
                    "HTTP status, headers, body, MIME classification, and response markers.";
            case "response.status" -> "HTTP status code, status family, and reason phrase from the response.";
            case "response.body" ->
                    "Response wire bytes, deepest successful Content-Encoding decode, chain status, and searchable text when bytes classify as text.";
            case "response.body.content_encoding" ->
                    "Progressive Content-Encoding decode status: layers applied, layers remaining, and whether the chain completed.";
            case "response.body.html" -> "HTML parser attributes derived from the response body.";
            case "response.body.html.dom" -> "HTML tag, id, and CSS-class facets parsed from the response body.";
            case "response.body.html.forms" -> "HTML form controls and submit-label facets parsed from the response body.";
            case "response.body.html.links" -> "HTML links and outbound references parsed from the response body.";
            case "response.body.html.text" -> "Visible rendered-text facets parsed from the HTML response body.";
            case "response.body.markers" -> "Response highlight ranges (inclusive start, exclusive end offsets).";
            case "response.headers" -> "Ordered response header rows with normalized names, raw names, values, and ordinals.";
            case "response.cookies" -> "Set-Cookie attributes parsed from the response.";
            case "response.markers" -> "Response highlight ranges (inclusive start, exclusive end offsets).";
            case "response.protocol" -> "HTTP version (status line) for the response.";
            case "response.mime_type" ->
                    "Burp MIME classifications: determined by Burp Suite, inferred from the body, and stated in headers.";
            case "websocket" ->
                    "WebSocket frame identity, direction, type, timing, and edit flag (separate from burp.proxy HTTP edit flags).";
            case "websocket.payload" ->
                    "Effective WebSocket frame payload after any user edit (text and/or Base64, plus length).";
            default -> genericDescription(path);
        };
    }

    // --- settings ---

    private static String settingsDescription(String path) {
        return switch (path) {
            case "burp" -> "Burp Suite edition and project identity for settings snapshots.";
            case "meta" ->
                    "Required settings metadata (always exported). Sub-fields are view-only in the Fields panel.";
            default -> genericDescription(path);
        };
    }

    // --- sitemap ---

    private static String sitemapDescription(String path) {
        if (path.startsWith("request.") || path.startsWith("response.")) {
            return trafficDescription(path);
        }
        if (path.equals("burp.timing")) {
            return "Request-sent, response-start, and response-end timing fields when Burp exposes sitemap item timing data.";
        }
        if (path.startsWith("burp.")) {
            return trafficDescription(path);
        }
        return switch (path) {
            case "burp" -> "Burp annotations, scope, and timing for the sitemap item.";
            case "meta" ->
                    "Required sitemap metadata (always exported). Sub-fields are view-only in the Fields panel.";
            case "request" -> "HTTP request captured for a sitemap tree item.";
            case "response" -> "HTTP response captured for a sitemap tree item.";
            default -> genericDescription(path);
        };
    }

    // --- findings ---

    private static String findingsDescription(String path) {
        if (path.equals("meta")) {
            return "Required findings metadata (always exported). Sub-fields are view-only in the Fields panel.";
        }
        if (path.equals("burp")) {
            return "Burp attribution and raw Burp scope metadata for the finding.";
        }
        if (path.equals("issue")) {
            return "Burp audit issue metadata: name, severity, confidence, type, description, and remediation text.";
        }
        if (path.equals("issue.remediation")) {
            return "Burp issue remediation guidance from the issue definition and concrete issue instance.";
        }
        if (path.equals("target")) {
            return "Finding-level target URL and service details from AuditIssue.";
        }
        if (path.equals("target.protocol")) {
            return "Finding-level target protocol facets.";
        }
        if (path.equals("collaborator")) {
            return "Burp Collaborator interactions linked to an issue (id, type, time, client, and protocol-specific detail).";
        }
        if (path.startsWith("collaborator.")) {
            return findingsCollaboratorDescription(path.substring("collaborator.".length()));
        }
        if (path.equals("requests_responses")) {
            return "HTTP request/response evidence pairs attached to a finding, each using the traffic request and response shape.";
        }
        if (path.startsWith("requests_responses.")) {
            return findingsRequestResponsesDescription(path.substring("requests_responses.".length()));
        }
        return genericDescription(path);
    }

    private static String findingsCollaboratorDescription(String leaf) {
        return switch (leaf) {
            case "dns" -> "DNS Collaborator interaction fields (query type and raw query bytes).";
            case "http" -> "HTTP Collaborator pingback protocol label and raw request/response bytes.";
            case "smtp" -> "SMTP Collaborator interaction protocol label and conversation transcript.";
            default -> genericDescription("collaborator." + leaf);
        };
    }

    private static String findingsRequestResponsesDescription(String path) {
        if (path.equals("burp")) {
            return "User notes and highlight color on issue evidence pairs.";
        }
        if (path.equals("request")) {
            return "HTTP request half of an issue evidence pair.";
        }
        if (path.startsWith("request.")) {
            return "Request " + path.substring("request.".length()).replace('_', ' ') + " on issue evidence.";
        }
        if (path.equals("response")) {
            return "HTTP response half of an issue evidence pair.";
        }
        if (path.startsWith("response.")) {
            return "Response " + path.substring("response.".length()).replace('_', ' ') + " on issue evidence.";
        }
        return genericDescription("requests_responses." + path);
    }

    // --- exporter ---

    private static String exporterDescription(String path) {
        return switch (path) {
            case "event" -> "Exporter log event fields (level, type, source, thread) written to the exporter index.";
            case "meta" ->
                    "Required exporter metadata (always exported). Sub-fields are view-only in the Fields panel.";
            default -> genericDescription(path);
        };
    }
}
