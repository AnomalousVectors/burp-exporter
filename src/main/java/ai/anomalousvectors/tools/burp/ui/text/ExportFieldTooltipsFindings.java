package ai.anomalousvectors.tools.burp.ui.text;

import java.util.Map;

final class ExportFieldTooltipsFindings {

    private ExportFieldTooltipsFindings() { }

    static final Map<String, String> DISPLAY_NAMES = Map.ofEntries(
            Map.entry("issue.type_id", "issue.definition.type_id"),
            Map.entry("issue.remediation.background", "issue.definition.remediation"),
            Map.entry("issue.remediation.detail", "issue.remediation"),
            Map.entry("target.url", "issue.base_url"),
            Map.entry("target.host", "issue.http_service.host"),
            Map.entry("target.port", "issue.http_service.port"),
            Map.entry("target.protocol.scheme", "issue.http_service.scheme"),
            Map.entry("collaborator", "issue.collaborator"));
    static String findingsDisplayName(String fieldKey) {
        if (fieldKey == null) {
            return null;
        }
        String override = DISPLAY_NAMES.get(fieldKey);
        if (override != null) {
            return override;
        }
        return fieldKey.startsWith("collaborator.") ? "issue." + fieldKey : fieldKey;
    }

    static String findingsTooltip(String fieldKey) {
        return switch (fieldKey) {
            case "burp.is_in_scope" -> Tooltips.textWithSource(
                    "Raw Burp Suite scope flag for the finding target URL, not the extension's export-scope decision.",
                    "FindingsIndexReporter.pushIssues() uses MontoyaApi.scope().isInScope(AuditIssue.baseUrl()).");
            case "burp.reporting_tool" -> Tooltips.textWithSource(
                    "Burp tool family that produced the finding.",
                    "FindingsIndexReporter.buildRootBurpDoc() writes Scanner for AuditIssue findings returned by MontoyaApi.siteMap().issues().");
            case "issue.name" -> Tooltips.textWithSource(
                    "Issue name.",
                    "FindingsIndexReporter.buildFindingDoc() uses AuditIssue.name().");
            case "issue.severity" -> Tooltips.textWithSource(
                    "Issue severity (Montoya enum name, e.g. INFORMATION).",
                    "FindingsIndexReporter.buildFindingDoc() uses AuditIssue.severity(). "
                            + "Config/UI severity checkboxes use lowercase tokens (e.g. informational maps to INFORMATION).");
            case "issue.confidence" -> Tooltips.textWithSource(
                    "Issue confidence.",
                    "FindingsIndexReporter.buildFindingDoc() uses AuditIssue.confidence().");
            case "issue.type_id" -> Tooltips.textWithSource(
                    "Burp issue type identifier.",
                    "FindingsIndexReporter.buildFindingDoc() uses AuditIssue.definition().typeIndex().");
            case "issue.typical_severity" -> Tooltips.textWithSource(
                    "Typical severity from the issue definition.",
                    "FindingsIndexReporter.buildFindingDoc() uses AuditIssue.definition().typicalSeverity().");
            case "issue.description" -> Tooltips.textWithSource(
                    "Issue description.",
                    "FindingsIndexReporter.buildFindingDoc() uses AuditIssue.detail().");
            case "issue.background" -> Tooltips.textWithSource(
                    "Issue background text.",
                    "FindingsIndexReporter.buildFindingDoc() uses AuditIssue.definition().background().");
            case "issue.remediation.background" -> Tooltips.textWithSource(
                    "Remediation background text.",
                    "FindingsIndexReporter.buildFindingDoc() uses AuditIssue.definition().remediation().");
            case "issue.remediation.detail" -> Tooltips.textWithSource(
                    "Remediation detail text.",
                    "FindingsIndexReporter.buildFindingDoc() uses AuditIssue.remediation().");
            case "target.url" -> Tooltips.textWithSource(
                    "Base target URL for the finding.",
                    "FindingsIndexReporter.buildTargetDoc() uses AuditIssue.baseUrl().");
            case "target.host" -> Tooltips.textWithSource(
                    "Target host for the finding.",
                    "FindingsIndexReporter.buildTargetDoc() uses AuditIssue.httpService().host().");
            case "target.port" -> Tooltips.textWithSource(
                    "Target port for the finding.",
                    "FindingsIndexReporter.buildTargetDoc() uses AuditIssue.httpService().port().");
            case "target.protocol.scheme" -> Tooltips.textWithSource(
                    "Target URL scheme for the finding: https or http.",
                    "FindingsIndexReporter.buildTargetDoc() maps AuditIssue.httpService().secure() to https or http.");
            case "collaborator" -> Tooltips.textWithSource(
                    "Burp Collaborator pingbacks (DNS, HTTP, SMTP) tied to the issue. Each entry records "
                            + "the interaction id, type, timestamp, client ip/port, protocol-specific details, "
                            + "and (for HTTP) base64-encoded raw request/response bytes for forensic preservation.",
                    "FindingsIndexReporter.buildFindingDoc() uses AuditIssue.collaboratorInteractions(). "
                            + "Only populated for OOB-detected issues such as blind SSRF, blind XXE, or "
                            + "command injection via OAST.");
            default -> findingsTooltipByPattern(fieldKey);
        };
    }

    static String findingsTooltipByPattern(String fieldKey) {
        if (fieldKey == null) {
            return ExportFieldTooltips.genericLeafTooltip("<unknown>");
        }
        if (fieldKey.startsWith("requests_responses.burp.")) {
            return findingsPairBurpTooltip(fieldKey.substring("requests_responses.burp.".length()));
        }
        if (fieldKey.startsWith("requests_responses.")) {
            String nested = fieldKey.substring("requests_responses.".length());
            if (nested.startsWith("request.body.markers.")) {
                return findingsRequestMarkerTooltip(nested.substring("request.body.markers.".length()));
            }
            if (nested.startsWith("response.body.markers.")) {
                return findingsResponseMarkerTooltip(nested.substring("response.body.markers.".length()));
            }
            return findingsEvidenceHttpTooltip(nested);
        }
        if (fieldKey.startsWith("collaborator.")) {
            return findingsCollaboratorInteractionTooltip(fieldKey.substring("collaborator.".length()));
        }
        return ExportFieldTooltips.genericLeafTooltip(fieldKey);
    }

    static String findingsEvidenceHttpTooltip(String nestedFieldKey) {
        return switch (nestedFieldKey) {
            case "request.url" -> Tooltips.textWithSource(
                    "Full request URL for this issue evidence pair.",
                    "FindingsIndexReporter.putPairRequestServiceFields() uses RequestResponseDocBuilder.buildBestEffortUrl() from HttpRequest and the pair or issue HttpService.");
            case "request.port" -> Tooltips.textWithSource(
                    "Target port for this issue evidence pair.",
                    "FindingsIndexReporter.putPairRequestServiceFields() uses HttpRequestResponse.httpService().port(), falling back to AuditIssue.httpService().port().");
            case "request.protocol.scheme" -> Tooltips.textWithSource(
                    "Request scheme for this issue evidence pair: https or http.",
                    "FindingsIndexReporter.putPairRequestServiceFields() maps the pair or issue HttpService.secure() flag to https or http.");
            case "request.protocol.http_version" -> Tooltips.textWithSource(
                    "HTTP version on the evidence request line.",
                    "FindingsIndexReporter.putPairRequestServiceFields() uses RequestResponseDocBuilder.safeRequestHttpVersion().");
            case "request.header" -> Tooltips.textWithSource(
                    "Actual evidence request headers as ordered rows.",
                    "RequestResponseDocBuilder.buildTrafficRequestDoc() writes HttpHeader values into request.headers rows with name, raw, value, and ordinal fields; request.content_type carries parsed content-type helpers.");
            case "response.header" -> Tooltips.textWithSource(
                    "Actual evidence response headers as ordered rows.",
                    "RequestResponseDocBuilder.buildTrafficResponseDoc() writes HttpHeader values into response.headers rows with name, raw, value, and ordinal fields; response.mime_type carries Burp and parsed MIME helpers.");
            default -> ExportFieldTooltipsTraffic.trafficTooltip(nestedFieldKey);
        };
    }

    static String findingsPairBurpTooltip(String leaf) {
        return switch (leaf) {
            case "notes" -> Tooltips.textWithSource(
                    "User notes on the issue evidence request/response pair.",
                    "FindingsIndexReporter.buildPairBurpDoc() uses HttpRequestResponse.annotations().notes().");
            case "highlight" -> Tooltips.textWithSource(
                    "Burp highlight color on the issue evidence pair.",
                    "FindingsIndexReporter.buildPairBurpDoc() uses HttpRequestResponse.annotations().highlightColor().name().");
            case "timing.req_sent" -> Tooltips.textWithSource(
                    "Request-sent timestamp for this issue evidence pair when Burp exposes timing data.",
                    "FindingsIndexReporter.buildPairBurpDoc() uses BurpTimingFields.from(HttpRequestResponse).");
            case "timing.end" -> Tooltips.textWithSource(
                    "Absolute response-end timestamp for this issue evidence pair when Burp exposes timing data.",
                    "BurpTimingFields.from() derives this from TimingData.timeRequestSent() plus timeBetweenRequestSentAndEndOfResponse().");
            case "timing.req_sent_to_res_start" -> Tooltips.textWithSource(
                    "Time to first response byte in milliseconds for this issue evidence pair.",
                    "BurpTimingFields.from() uses TimingData.timeBetweenRequestSentAndStartOfResponse().");
            case "timing.req_sent_to_res_end" -> Tooltips.textWithSource(
                    "Total observed evidence-pair duration in milliseconds: request sent to end of response.",
                    "BurpTimingFields.from() uses TimingData.timeBetweenRequestSentAndEndOfResponse().");
            default -> ExportFieldTooltips.genericLeafTooltip("requests_responses.burp." + leaf);
        };
    }

    static String findingsRequestMarkerTooltip(String leaf) {
        return switch (leaf) {
            case "start_inclusive" -> Tooltips.textWithSource(
                    "Inclusive start offset of a request highlight on issue evidence.",
                    "TrafficPairMarkers.overlayPairMarkers() prefers HttpRequestResponse.requestMarkers() over HttpRequest.markers(); otherwise RequestResponseDocBuilder.convertTrafficMarkersToList() from HttpRequest.markers().");
            case "end_exclusive" -> Tooltips.textWithSource(
                    "Exclusive end offset of a request highlight on issue evidence.",
                    "TrafficPairMarkers.overlayPairMarkers() prefers HttpRequestResponse.requestMarkers() over HttpRequest.markers(); otherwise RequestResponseDocBuilder.convertTrafficMarkersToList() from HttpRequest.markers().");
            default -> ExportFieldTooltips.genericLeafTooltip("requests_responses.request.body.markers." + leaf);
        };
    }

    static String findingsResponseMarkerTooltip(String leaf) {
        return switch (leaf) {
            case "start_inclusive" -> Tooltips.textWithSource(
                    "Inclusive start offset of a response highlight on issue evidence.",
                    "TrafficPairMarkers.overlayPairMarkers() prefers HttpRequestResponse.responseMarkers() over HttpResponse.markers(); otherwise RequestResponseDocBuilder.convertTrafficMarkersToList() from HttpResponse.markers().");
            case "end_exclusive" -> Tooltips.textWithSource(
                    "Exclusive end offset of a response highlight on issue evidence.",
                    "TrafficPairMarkers.overlayPairMarkers() prefers HttpRequestResponse.responseMarkers() over HttpResponse.markers(); otherwise RequestResponseDocBuilder.convertTrafficMarkersToList() from HttpResponse.markers().");
            default -> ExportFieldTooltips.genericLeafTooltip("requests_responses.response.body.markers." + leaf);
        };
    }

    static String findingsCollaboratorInteractionTooltip(String path) {
        if (path.startsWith("dns.")) {
            return findingsCollaboratorDnsTooltip(path.substring("dns.".length()));
        }
        if (path.startsWith("http.")) {
            return findingsCollaboratorHttpTooltip(path.substring("http.".length()));
        }
        if (path.startsWith("smtp.")) {
            return findingsCollaboratorSmtpTooltip(path.substring("smtp.".length()));
        }
        return switch (path) {
            case "id" -> Tooltips.textWithSource(
                    "Burp Collaborator interaction identifier.",
                    "FindingsIndexReporter.buildCollaboratorInteractionsList() uses Interaction.id().");
            case "type" -> Tooltips.textWithSource(
                    "Collaborator interaction type (DNS, HTTP, SMTP, etc.).",
                    "FindingsIndexReporter.buildCollaboratorInteractionsList() uses Interaction.type().name().");
            case "time" -> Tooltips.textWithSource(
                    "Collaborator interaction timestamp.",
                    "FindingsIndexReporter.buildCollaboratorInteractionsList() uses Interaction.timeStamp() as an ISO-8601 instant string.");
            case "client_ip" -> Tooltips.textWithSource(
                    "Remote client IP that triggered the Collaborator interaction.",
                    "FindingsIndexReporter.buildCollaboratorInteractionsList() uses Interaction.clientIp().getHostAddress().");
            case "client_port" -> Tooltips.textWithSource(
                    "Remote client port for the Collaborator interaction.",
                    "FindingsIndexReporter.buildCollaboratorInteractionsList() uses Interaction.clientPort().");
            case "custom_data" -> Tooltips.textWithSource(
                    "Optional custom Collaborator payload metadata.",
                    "FindingsIndexReporter.buildCollaboratorInteractionsList() uses Interaction.customData() when present.");
            default -> ExportFieldTooltips.genericLeafTooltip("collaborator." + path);
        };
    }

    static String findingsCollaboratorDnsTooltip(String leaf) {
        return switch (leaf) {
            case "query_type" -> Tooltips.textWithSource(
                    "DNS query type for the Collaborator interaction.",
                    "FindingsIndexReporter.buildCollaboratorInteractionsList() uses DnsDetails.queryType().name() from Interaction.dnsDetails().");
            case "query_b64" -> Tooltips.textWithSource(
                    "Raw DNS query bytes as Base64.",
                    "FindingsIndexReporter.buildCollaboratorInteractionsList() Base64-encodes DnsDetails.query().getBytes() from Interaction.dnsDetails().");
            default -> ExportFieldTooltips.genericLeafTooltip("collaborator.dns." + leaf);
        };
    }

    static String findingsCollaboratorHttpTooltip(String leaf) {
        if (leaf.startsWith("request.body.markers.")) {
            return findingsCollaboratorRequestMarkerTooltip(leaf.substring("request.body.markers.".length()));
        }
        if (leaf.startsWith("response.body.markers.")) {
            return findingsCollaboratorResponseMarkerTooltip(leaf.substring("response.body.markers.".length()));
        }
        if (leaf.startsWith("request.") || leaf.startsWith("response.")) {
            String tooltip = findingsEvidenceHttpTooltip(leaf);
            if (!tooltip.contains("Included when this toggle is enabled in the Fields panel.")) {
                return tooltip;
            }
        }
        return switch (leaf) {
            case "protocol" -> Tooltips.textWithSource(
                    "Application protocol for the Collaborator HTTP interaction.",
                    "FindingsIndexReporter.buildCollaboratorInteractionsList() uses HttpDetails.protocol().name() from Interaction.httpDetails().");
            case "request_b64" -> Tooltips.textWithSource(
                    "Raw HTTP request bytes from the Collaborator pingback as Base64.",
                    "FindingsIndexReporter.buildCollaboratorInteractionsList() uses HttpRequest.toByteArray() from HttpDetails.requestResponse().request() and Base64-encodes the bytes.");
            case "response_b64" -> Tooltips.textWithSource(
                    "Raw HTTP response bytes from the Collaborator pingback as Base64.",
                    "FindingsIndexReporter.buildCollaboratorInteractionsList() uses HttpResponse.toByteArray() from HttpDetails.requestResponse().response() and Base64-encodes the bytes.");
            case "request.header" -> Tooltips.textWithSource(
                    "Parsed Collaborator HTTP request headers as ordered rows.",
                    "FindingsIndexReporter.buildCollaboratorInteractionsList() uses RequestResponseDocBuilder.buildTrafficRequestDoc() for HttpDetails.requestResponse().request(), which writes request.headers rows.");
            case "response.header" -> Tooltips.textWithSource(
                    "Parsed Collaborator HTTP response headers as ordered rows.",
                    "FindingsIndexReporter.buildCollaboratorInteractionsList() uses RequestResponseDocBuilder.buildTrafficResponseDoc() for HttpDetails.requestResponse().response(), which writes response.headers rows.");
            default -> {
                yield ExportFieldTooltips.genericLeafTooltip("collaborator.http." + leaf);
            }
        };
    }

    static String findingsCollaboratorRequestMarkerTooltip(String leaf) {
        return switch (leaf) {
            case "start_inclusive" -> Tooltips.textWithSource(
                    "Inclusive start offset of a request highlight on the Collaborator HTTP request.",
                    "TrafficPairMarkers.overlayPairMarkers() writes HttpRequestResponse.requestMarkers() into collaborator.http.request.body.markers.");
            case "end_exclusive" -> Tooltips.textWithSource(
                    "Exclusive end offset of a request highlight on the Collaborator HTTP request.",
                    "TrafficPairMarkers.overlayPairMarkers() writes HttpRequestResponse.requestMarkers() into collaborator.http.request.body.markers.");
            default -> ExportFieldTooltips.genericLeafTooltip("collaborator.http.request.body.markers." + leaf);
        };
    }

    static String findingsCollaboratorResponseMarkerTooltip(String leaf) {
        return switch (leaf) {
            case "start_inclusive" -> Tooltips.textWithSource(
                    "Inclusive start offset of a response highlight on the Collaborator HTTP response.",
                    "TrafficPairMarkers.overlayPairMarkers() writes HttpRequestResponse.responseMarkers() into collaborator.http.response.body.markers.");
            case "end_exclusive" -> Tooltips.textWithSource(
                    "Exclusive end offset of a response highlight on the Collaborator HTTP response.",
                    "TrafficPairMarkers.overlayPairMarkers() writes HttpRequestResponse.responseMarkers() into collaborator.http.response.body.markers.");
            default -> ExportFieldTooltips.genericLeafTooltip("collaborator.http.response.body.markers." + leaf);
        };
    }

    static String findingsCollaboratorSmtpTooltip(String leaf) {
        return switch (leaf) {
            case "protocol" -> Tooltips.textWithSource(
                    "SMTP protocol label for the Collaborator interaction.",
                    "FindingsIndexReporter.buildCollaboratorInteractionsList() uses SmtpDetails.protocol().name() from Interaction.smtpDetails().");
            case "conversation" -> Tooltips.textWithSource(
                    "SMTP conversation transcript for the Collaborator interaction.",
                    "FindingsIndexReporter.buildCollaboratorInteractionsList() uses SmtpDetails.conversation() from Interaction.smtpDetails().");
            default -> ExportFieldTooltips.genericLeafTooltip("collaborator.smtp." + leaf);
        };
    }
}
