package ai.anomalousvectors.tools.burp.ui.text;

/**
 * Request/response nested field tooltips shared by traffic, sitemap, and findings evidence paths.
 */
final class ExportFieldTooltipsRequestResponse {

    private ExportFieldTooltipsRequestResponse() { }
    static String requestResponseNestedTooltip(String fieldKey) {
        if (fieldKey == null) {
            return ExportFieldTooltips.genericLeafTooltip(fieldKey);
        }
        if (fieldKey.startsWith("request.body.markers.")) {
            return requestMarkerFieldTooltip(fieldKey.substring("request.body.markers.".length()));
        }
        if (fieldKey.startsWith("request.body.")) {
            return requestBodyFieldTooltip(fieldKey.substring("request.body.".length()));
        }
        if (fieldKey.startsWith("response.body.markers.")) {
            return responseMarkerFieldTooltip(fieldKey.substring("response.body.markers.".length()));
        }
        if (fieldKey.startsWith("response.body.html.")) {
            return responseBodyHtmlFieldTooltip(fieldKey.substring("response.body.html.".length()));
        }
        if (fieldKey.startsWith("response.body.")) {
            return responseBodyFieldTooltip(fieldKey.substring("response.body.".length()));
        }
        if (fieldKey.startsWith("request.markers.")) {
            return requestMarkerFieldTooltip(fieldKey.substring("request.markers.".length()));
        }
        if (fieldKey.startsWith("response.markers.")) {
            return responseMarkerFieldTooltip(fieldKey.substring("response.markers.".length()));
        }
        if (fieldKey.startsWith("request.parameters.")) {
            return requestParameterFieldTooltip(fieldKey.substring("request.parameters.".length()));
        }
        if (fieldKey.startsWith("request.url.")) {
            return requestUrlFieldTooltip(fieldKey.substring("request.url.".length()));
        }
        if (fieldKey.startsWith("request.content_type.")) {
            return requestContentTypeFieldTooltip(fieldKey.substring("request.content_type.".length()));
        }
        if (fieldKey.startsWith("response.mime_type.")) {
            return responseMimeTypeFieldTooltip(fieldKey.substring("response.mime_type.".length()));
        }
        if (fieldKey.startsWith("response.header_attributes.")) {
            return responseHeaderAttributesFieldTooltip(fieldKey.substring("response.header_attributes.".length()));
        }
        if (fieldKey.startsWith("request.headers.")) {
            return requestHeaderEntryFieldTooltip(fieldKey.substring("request.headers.".length()));
        }
        if (fieldKey.startsWith("response.headers.")) {
            return responseHeaderEntryFieldTooltip(fieldKey.substring("response.headers.".length()));
        }
        if (fieldKey.startsWith("request.cookies.")) {
            return requestCookieFieldTooltip(fieldKey.substring("request.cookies.".length()));
        }
        if (fieldKey.startsWith("response.cookies.")) {
            return responseCookieFieldTooltip(fieldKey.substring("response.cookies.".length()));
        }
        return switch (fieldKey) {
            case "request.method" -> Tooltips.textWithSource(
                    "HTTP method.",
                    "RequestResponseDocBuilder.buildTrafficRequestDoc() uses HttpRequest.method().");
            case "request.path" -> Tooltips.textWithSource(
                    "Request path summary object.",
                    "Traffic, sitemap, and findings evidence write path details under request.path.with_query, request.path.without_query, request.path.query, and request.path.file_extension.");
            case "response.status_code" -> Tooltips.textWithSource(
                    "Obtain the HTTP status code contained in the response.",
                    "Current HTTP documents write this under response.status.code from HttpResponse.statusCode().");
            case "response.status_description" -> Tooltips.textWithSource(
                    "Obtain the HTTP reason phrase contained in the response for HTTP 1 messages.",
                    "Current HTTP documents write this under response.status.description from HttpResponse.reasonPhrase().");
            case "request.content_type" -> Tooltips.textWithSource(
                    "Request content-type summary object.",
                    "HttpMessageDocSupport.requestContentType() combines the raw Content-Type header, Burp ContentType, parsed media type, charset, and exporter inference.");
            case "request.file_extension" -> Tooltips.textWithSource(
                    "File extension inferred from the request URL path.",
                    "Current HTTP documents write this under request.path.file_extension from HttpRequest.fileExtension().");
            case "request.http_version" -> Tooltips.textWithSource(
                    "HTTP version on the request line (for example HTTP/1.1).",
                    "Current HTTP documents write this under request.protocol.http_version from HttpRequest.httpVersion().");
            case "request.path_without_query" -> Tooltips.textWithSource(
                    "Request path without the query string.",
                    "Current HTTP documents write this under request.path.without_query from HttpRequest.pathWithoutQuery().");
            case "request.query" -> Tooltips.textWithSource(
                    "Raw query string from the request URL.",
                    "Current HTTP documents write this under request.path.query from HttpRequest.query().");
            case "response.http_version" -> Tooltips.textWithSource(
                    "HTTP version on the response status line.",
                    "Current HTTP documents write this under response.protocol.http_version from HttpResponse.httpVersion().");
            case "response.status_code_class" -> Tooltips.textWithSource(
                    "HTTP status family derived from the status code (for example 2xx, 4xx).",
                    "Current HTTP documents write this under response.status.code_class from HttpResponse.statusCode().");
            case "response.mime_type" -> Tooltips.textWithSource(
                    "Response MIME/content-type summary object.",
                    "HttpMessageDocSupport.responseMimeType() combines the raw Content-Type header with Burp MIME, stated MIME, body-inferred MIME, parsed media type, and charset.");
            case "response.location" -> Tooltips.textWithSource(
                    "Location response header value (redirect target).",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.LOCATION).");
            case "response.content_length" -> Tooltips.textWithSource(
                    "Content-Length header value when present.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.CONTENT_LENGTH).");
            case "response.cookie_names" -> Tooltips.textWithSource(
                    "Cookie names set on the response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.COOKIE_NAMES).");
            case "response.canonical_link" -> Tooltips.textWithSource(
                    "Canonical link URL parsed from HTML when present.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.CANONICAL_LINK).");
            case "response.comments" -> Tooltips.textWithSource(
                    "HTML comments extracted from the response body.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.COMMENTS).");
            case "response.non_hidden_form_input_types" -> Tooltips.textWithSource(
                    "Non-hidden HTML form input types present in the response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.NON_HIDDEN_FORM_INPUT_TYPES).");
            case "response.input_submit_labels" -> Tooltips.textWithSource(
                    "Labels of submit inputs in HTML forms.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.INPUT_SUBMIT_LABELS).");
            case "response.button_submit_labels" -> Tooltips.textWithSource(
                    "Labels of submit buttons in HTML forms.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.BUTTON_SUBMIT_LABELS).");
            case "response.input_image_labels" -> Tooltips.textWithSource(
                    "Alt text of image submit inputs in HTML forms.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.INPUT_IMAGE_LABELS).");
            case "response.outbound_edge_count" -> Tooltips.textWithSource(
                    "Count of outbound links/edges Burp parsed from the HTML response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.OUTBOUND_EDGE_COUNT).");
            case "response.outbound_edge_tag_names" -> Tooltips.textWithSource(
                    "Tag names of outbound edges parsed from the HTML response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.OUTBOUND_EDGE_TAG_NAMES).");
            default -> ExportFieldTooltips.genericLeafTooltip(fieldKey);
        };
    }

    static String requestBodyFieldTooltip(String leaf) {
        return switch (leaf) {
            case "b64" -> Tooltips.textWithSource(
                    "On-the-wire body bytes as Base64 — exactly what Burp captured (still compressed when Content-Encoding is set). "
                            + "Use for exact replay; use body.text for searchable text after Content-Encoding removal when applicable.",
                    "HttpMessageDocSupport.buildBodyContent() Base64-encodes the raw body bytes.");
            case "length" -> Tooltips.textWithSource(
                    "On-the-wire body length in bytes (compressed size when Content-Encoding is set).",
                    "HttpMessageDocSupport.buildBodyContent() uses HttpRequest.body().getBytes().length.");
            case "offset" -> Tooltips.textWithSource(
                    "Byte offset of the request body within the raw HTTP message.",
                    "HttpMessageDocSupport.buildBodyContent() uses HttpRequest.bodyOffset().");
            case "text" -> Tooltips.textWithSource(
                    "UTF-8 or charset-decoded body string after Content-Encoding removal (when applicable) and text classification. "
                            + "Indexed as OpenSearch text for full-text search. "
                            + "Null when the payload remains binary after decompress (e.g. protobuf inside gzip) or is not textual.",
                    "HttpMessageDocSupport.decodeHumanReadableBodyText() on logical bytes from BodyContentEncodingSupport.resolveForExport().");
            case "markers" -> Tooltips.textWithSource(
                    "Burp request highlight marker ranges.",
                    "RequestResponseDocBuilder.markersToList() copies HttpRequest.markers() into request.body.markers.");
            case "truncated" -> Tooltips.textWithSource(
                    "True when search/database export prefix-truncated this request body to fit the live bulk byte budget. "
                            + "body.length remains the original wire size; file export is not truncated by this path.",
                    "SearchBodyPrefixFitter.fitToLiveBudget() sets body.truncated when shortening b64/text under BulkByteBudget pressure.");
            default -> ExportFieldTooltips.genericLeafTooltip("request.body." + leaf);
        };
    }

    static String responseBodyFieldTooltip(String leaf) {
        return switch (leaf) {
            case "b64" -> Tooltips.textWithSource(
                    "On-the-wire body bytes as Base64 — exactly what Burp captured (still compressed when Content-Encoding is set). "
                            + "Use for exact replay; use body.text for searchable text after Content-Encoding removal when applicable.",
                    "HttpMessageDocSupport.buildBodyContent() Base64-encodes the raw body bytes.");
            case "length" -> Tooltips.textWithSource(
                    "On-the-wire body length in bytes (compressed size when Content-Encoding is set).",
                    "HttpMessageDocSupport.buildBodyContent() uses HttpResponse.body().getBytes().length.");
            case "offset" -> Tooltips.textWithSource(
                    "Byte offset of the response body within the raw HTTP message.",
                    "HttpMessageDocSupport.buildBodyContent() uses HttpResponse.bodyOffset().");
            case "text" -> Tooltips.textWithSource(
                    "UTF-8 or charset-decoded body string after Content-Encoding removal (when applicable) and text classification. "
                            + "Indexed as OpenSearch text for full-text search. "
                            + "Null when the payload remains binary after decompress or is not textual.",
                    "HttpMessageDocSupport.decodeHumanReadableBodyText() on logical bytes from BodyContentEncodingSupport.resolveForExport().");
            case "truncated" -> Tooltips.textWithSource(
                    "True when search/database export prefix-truncated this response body to fit the live bulk byte budget. "
                            + "body.length remains the original wire size; file export is not truncated by this path.",
                    "SearchBodyPrefixFitter.fitToLiveBudget() sets body.truncated when shortening b64/text under BulkByteBudget pressure.");
            case "page_title" -> Tooltips.textWithSource(
                    "HTML page title parsed from the response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.PAGE_TITLE) into response.body.page_title.");
            case "visible_text" -> Tooltips.textWithSource(
                    "Visible text content extracted from HTML.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.VISIBLE_TEXT) into response.body.visible_text.");
            case "word_count" -> Tooltips.textWithSource(
                    "Word count of the full response body text.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.WORD_COUNT) into response.body.word_count.");
            case "visible_word_count" -> Tooltips.textWithSource(
                    "Word count of visible text in HTML responses.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.VISIBLE_WORD_COUNT) into response.body.visible_word_count.");
            case "line_count" -> Tooltips.textWithSource(
                    "Line count of the response body text.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.LINE_COUNT) into response.body.line_count.");
            case "anchor_labels" -> Tooltips.textWithSource(
                    "Text labels of HTML anchor elements.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.ANCHOR_LABELS) into response.body.anchor_labels.");
            case "button_submit_labels" -> Tooltips.textWithSource(
                    "Labels of submit buttons in HTML forms.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.BUTTON_SUBMIT_LABELS) into response.body.button_submit_labels.");
            case "canonical_link" -> Tooltips.textWithSource(
                    "Canonical link URL parsed from HTML when present.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.CANONICAL_LINK) into response.body.canonical_link.");
            case "comments" -> Tooltips.textWithSource(
                    "HTML comments extracted from the response body.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.COMMENTS) into response.body.comments.");
            case "tag_names" -> Tooltips.textWithSource(
                    "HTML tag names present in the response body.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.TAG_NAMES) into response.body.tag_names.");
            case "div_ids" -> Tooltips.textWithSource(
                    "HTML div id attributes found in the response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.DIV_IDS) into response.body.div_ids.");
            case "css_classes" -> Tooltips.textWithSource(
                    "CSS class names found in the HTML response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.CSS_CLASSES) into response.body.css_classes.");
            case "input_image_labels" -> Tooltips.textWithSource(
                    "Alt text of image submit inputs in HTML forms.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.INPUT_IMAGE_LABELS) into response.body.input_image_labels.");
            case "markers" -> Tooltips.textWithSource(
                    "Burp response highlight marker ranges.",
                    "RequestResponseDocBuilder.markersToList() copies HttpResponse.markers() into response.body.markers.");
            case "non_hidden_form_input_types" -> Tooltips.textWithSource(
                    "Non-hidden HTML form input types present in the response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.NON_HIDDEN_FORM_INPUT_TYPES) into response.body.non_hidden_form_input_types.");
            case "outbound_edge_count" -> Tooltips.textWithSource(
                    "Count of outbound links/edges Burp parsed from the HTML response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.OUTBOUND_EDGE_COUNT) into response.body.outbound_edge_count.");
            case "outbound_edge_tag_names" -> Tooltips.textWithSource(
                    "Tag names of outbound edges parsed from the HTML response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.OUTBOUND_EDGE_TAG_NAMES) into response.body.outbound_edge_tag_names.");
            default -> ExportFieldTooltips.genericLeafTooltip("response.body." + leaf);
        };
    }

    static String responseBodyHtmlFieldTooltip(String leaf) {
        return switch (leaf) {
            case "page_title" -> Tooltips.textWithSource(
                    "HTML page title parsed from the response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.PAGE_TITLE) into response.body.html.page_title.");
            case "text.visible_text" -> Tooltips.textWithSource(
                    "Visible text content extracted from HTML.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.VISIBLE_TEXT) into response.body.html.text.visible_text.");
            case "text.visible_word_count" -> Tooltips.textWithSource(
                    "Word count of visible text in HTML responses.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.VISIBLE_WORD_COUNT) into response.body.html.text.visible_word_count.");
            case "links.anchor_labels" -> Tooltips.textWithSource(
                    "Text labels of HTML anchor elements.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.ANCHOR_LABELS) into response.body.html.links.anchor_labels.");
            case "forms.button_submit_labels" -> Tooltips.textWithSource(
                    "Labels of submit buttons in HTML forms.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.BUTTON_SUBMIT_LABELS) into response.body.html.forms.button_submit_labels.");
            case "links.canonical_link" -> Tooltips.textWithSource(
                    "Canonical link URL parsed from HTML when present.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.CANONICAL_LINK) into response.body.html.links.canonical_link.");
            case "comments" -> Tooltips.textWithSource(
                    "HTML comments extracted from the response body.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.COMMENTS) into response.body.html.comments.");
            case "dom.tag_names" -> Tooltips.textWithSource(
                    "HTML tag names present in the response body.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.TAG_NAMES) into response.body.html.dom.tag_names.");
            case "dom.div_ids" -> Tooltips.textWithSource(
                    "HTML div id attributes found in the response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.DIV_IDS) into response.body.html.dom.div_ids.");
            case "dom.css_classes" -> Tooltips.textWithSource(
                    "CSS class names found in the HTML response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.CSS_CLASSES) into response.body.html.dom.css_classes.");
            case "forms.input_image_labels" -> Tooltips.textWithSource(
                    "Alt text of image submit inputs in HTML forms.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.INPUT_IMAGE_LABELS) into response.body.html.forms.input_image_labels.");
            case "forms.input_submit_labels" -> Tooltips.textWithSource(
                    "Labels of submit inputs in HTML forms.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.INPUT_SUBMIT_LABELS) into response.body.html.forms.input_submit_labels.");
            case "forms.non_hidden_form_input_types" -> Tooltips.textWithSource(
                    "Non-hidden HTML form input types present in the response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.NON_HIDDEN_FORM_INPUT_TYPES) into response.body.html.forms.non_hidden_form_input_types.");
            case "links.outbound_edge_count" -> Tooltips.textWithSource(
                    "Count of outbound links/edges Burp parsed from the HTML response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.OUTBOUND_EDGE_COUNT) into response.body.html.links.outbound_edge_count.");
            case "links.outbound_edge_tag_names" -> Tooltips.textWithSource(
                    "Tag names of outbound edges parsed from the HTML response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.OUTBOUND_EDGE_TAG_NAMES) into response.body.html.links.outbound_edge_tag_names.");
            default -> ExportFieldTooltips.genericLeafTooltip("response.body.html." + leaf);
        };
    }

    static String requestMarkerFieldTooltip(String leaf) {
        return switch (leaf) {
            case "start_inclusive" -> Tooltips.textWithSource(
                    "Inclusive start offset of a Burp request body highlight marker.",
                    "RequestResponseDocBuilder.trafficMarkersToList() copies Marker.range().startIndexInclusive() from HttpRequest.markers() into request.body.markers.start_inclusive.");
            case "end_exclusive" -> Tooltips.textWithSource(
                    "Exclusive end offset of a Burp request body highlight marker.",
                    "RequestResponseDocBuilder.trafficMarkersToList() copies Marker.range().endIndexExclusive() from HttpRequest.markers() into request.body.markers.end_exclusive.");
            case "start_index_inclusive" -> Tooltips.textWithSource(
                    "Inclusive start offset of a Burp request highlight marker.",
                    "RequestResponseDocBuilder.markersToList() copies Marker.range().startIndexInclusive() from HttpRequest.markers().");
            case "end_index_exclusive" -> Tooltips.textWithSource(
                    "Exclusive end offset of a Burp request highlight marker.",
                    "RequestResponseDocBuilder.markersToList() copies Marker.range().endIndexExclusive() from HttpRequest.markers().");
            default -> ExportFieldTooltips.genericLeafTooltip("request.markers." + leaf);
        };
    }

    static String responseMarkerFieldTooltip(String leaf) {
        return switch (leaf) {
            case "start_inclusive" -> Tooltips.textWithSource(
                    "Inclusive start offset of a Burp response body highlight marker.",
                    "RequestResponseDocBuilder.trafficMarkersToList() copies Marker.range().startIndexInclusive() from HttpResponse.markers() into response.body.markers.start_inclusive.");
            case "end_exclusive" -> Tooltips.textWithSource(
                    "Exclusive end offset of a Burp response body highlight marker.",
                    "RequestResponseDocBuilder.trafficMarkersToList() copies Marker.range().endIndexExclusive() from HttpResponse.markers() into response.body.markers.end_exclusive.");
            case "start_index_inclusive" -> Tooltips.textWithSource(
                    "Inclusive start offset of a Burp response highlight marker.",
                    "RequestResponseDocBuilder.markersToList() copies Marker.range().startIndexInclusive() from HttpResponse.markers().");
            case "end_index_exclusive" -> Tooltips.textWithSource(
                    "Exclusive end offset of a Burp response highlight marker.",
                    "RequestResponseDocBuilder.markersToList() copies Marker.range().endIndexExclusive() from HttpResponse.markers().");
            default -> ExportFieldTooltips.genericLeafTooltip("response.markers." + leaf);
        };
    }

    static String requestParameterFieldTooltip(String leaf) {
        return switch (leaf) {
            case "name" -> Tooltips.textWithSource(
                    "Parsed HTTP parameter name.",
                    "RequestResponseDocBuilder.parametersToList() uses ParsedHttpParameter.name() from HttpRequest.parameters(); BODY parameters may be filtered on binary bodies.");
            case "type" -> Tooltips.textWithSource(
                    "Burp parameter type (URL, BODY, JSON, XML, etc.; cookies are exported under request.cookies).",
                    "RequestResponseDocBuilder.parametersToList() uses ParsedHttpParameter.type().name().");
            case "value" -> Tooltips.textWithSource(
                    "Parsed HTTP parameter value.",
                    "RequestResponseDocBuilder.parametersToList() uses ParsedHttpParameter.value().");
            case "truncated" -> Tooltips.textWithSource(
                    "True when search/database export prefix-truncated this parameter value to fit the live bulk byte budget.",
                    "SearchBodyPrefixFitter sets truncated when shortening parameter values under BulkByteBudget pressure.");
            default -> ExportFieldTooltips.genericLeafTooltip("request.parameters." + leaf);
        };
    }

    static String requestUrlFieldTooltip(String leaf) {
        return switch (leaf) {
            case "raw" -> Tooltips.textWithSource(
                    "Full request URL.",
                    "HttpMessageDocSupport.urlObject() writes RequestResponseDocBuilder.buildBestEffortUrl() into request.url.raw.");
            case "text" -> Tooltips.textWithSource(
                    "Full request URL indexed for text search, including long query strings.",
                    "HttpMessageDocSupport.urlObject() copies request.url.raw into request.url.text.");
            case "scheme" -> Tooltips.textWithSource(
                    "Request URL scheme.",
                    "HttpMessageDocSupport.urlObject() parses request.url.raw and falls back to HttpService.secure().");
            case "host" -> Tooltips.textWithSource(
                    "Target host parsed from the request URL.",
                    "HttpMessageDocSupport.urlObject() parses request.url.raw and falls back to HttpService.host().");
            case "port" -> Tooltips.textWithSource(
                    "Target port parsed from the request URL or HTTP service.",
                    "HttpMessageDocSupport.urlObject() uses an explicit URL port when present, otherwise HttpService.port().");
            case "path" -> Tooltips.textWithSource(
                    "Path component parsed from the request URL.",
                    "HttpMessageDocSupport.urlObject() parses URI.getRawPath() from request.url.raw.");
            case "query" -> Tooltips.textWithSource(
                    "Query component parsed from the request URL without the leading question mark.",
                    "HttpMessageDocSupport.urlObject() parses URI.getRawQuery() from request.url.raw.");
            case "fragment" -> Tooltips.textWithSource(
                    "Fragment component parsed from the request URL without the leading hash.",
                    "HttpMessageDocSupport.urlObject() parses URI.getRawFragment() from request.url.raw.");
            default -> ExportFieldTooltips.genericLeafTooltip("request.url." + leaf);
        };
    }

    static String requestContentTypeFieldTooltip(String leaf) {
        return switch (leaf) {
            case "raw" -> Tooltips.textWithSource(
                    "Raw request Content-Type header value.",
                    "HttpMessageDocSupport.requestContentType() reads the Content-Type header via headerValue().");
            case "media_type" -> Tooltips.textWithSource(
                    "Parsed request media type without parameters.",
                    "HttpMessageDocSupport.requestContentType() resolves the primary media type from Content-Type and Burp ContentType hints.");
            case "charset" -> Tooltips.textWithSource(
                    "Charset declared in the request Content-Type header.",
                    "HttpMessageDocSupport.requestContentType() parses the charset parameter from Content-Type.");
            case "burp_declared" -> Tooltips.textWithSource(
                    "Burp request ContentType string.",
                    "HttpMessageDocSupport.requestContentType() writes HttpRequest.contentType().toString().");
            case "burp_enum" -> Tooltips.textWithSource(
                    "Burp request ContentType enum name.",
                    "HttpMessageDocSupport.requestContentType() writes HttpRequest.contentType().name().");
            case "inferred" -> Tooltips.textWithSource(
                    "Exporter-inferred request payload class from body bytes and headers.",
                    "RequestResponseParametersSupport.inferRequestContentType() supplies request.content_type.inferred.");
            default -> ExportFieldTooltips.genericLeafTooltip("request.content_type." + leaf);
        };
    }

    static String responseMimeTypeFieldTooltip(String leaf) {
        return switch (leaf) {
            case "raw_content_type" -> Tooltips.textWithSource(
                    "Raw response Content-Type header value.",
                    "HttpMessageDocSupport.responseMimeType() reads the Content-Type response header via headerValue().");
            case "media_type" -> Tooltips.textWithSource(
                    "Parsed response media type without parameters.",
                    "HttpMessageDocSupport.responseMimeType() resolves the primary media type from Content-Type and Burp MIME hints.");
            case "charset" -> Tooltips.textWithSource(
                    "Charset declared in the response Content-Type header.",
                    "HttpMessageDocSupport.responseMimeType() parses the charset parameter from Content-Type.");
            case "burp" -> Tooltips.textWithSource(
                    "Burp response MIME verdict.",
                    "HttpMessageDocSupport.responseMimeType() writes HttpResponse.mimeType().name().");
            case "stated" -> Tooltips.textWithSource(
                    "MIME type stated by Burp from response metadata.",
                    "HttpMessageDocSupport.responseMimeType() writes HttpResponse.statedMimeType().name().");
            case "inferred_body" -> Tooltips.textWithSource(
                    "MIME type Burp inferred from the response body.",
                    "HttpMessageDocSupport.responseMimeType() writes HttpResponse.inferredMimeType().name().");
            default -> ExportFieldTooltips.genericLeafTooltip("response.mime_type." + leaf);
        };
    }

    static String responseHeaderAttributesFieldTooltip(String leaf) {
        return switch (leaf) {
            case "date" -> Tooltips.textWithSource(
                    "Typed helper for the standard HTTP response Date header.",
                    "RequestResponseDocBuilder.populateResponsePayload() copies the raw Date header into response.header_attributes.date; the raw header row remains in response.headers.");
            default -> ExportFieldTooltips.genericLeafTooltip("response.header_attributes." + leaf);
        };
    }

    static String requestHeaderEntryFieldTooltip(String leaf) {
        return switch (leaf) {
            case "name" -> Tooltips.textWithSource(
                    "Normalized request header name.",
                    "HttpMessageDocSupport.headersToList() lower-cases HttpHeader.name() into request.headers.name.");
            case "raw" -> Tooltips.textWithSource(
                    "Original request header name as Burp exposed it.",
                    "HttpMessageDocSupport.headersToList() copies HttpHeader.name() into request.headers.raw.");
            case "value" -> Tooltips.textWithSource(
                    "Request header value.",
                    "HttpMessageDocSupport.headersToList() copies HttpHeader.value() into request.headers.value.");
            case "ordinal" -> Tooltips.textWithSource(
                    "Zero-based request header order in the message.",
                    "HttpMessageDocSupport.headersToList() assigns ordinals while preserving duplicate header order.");
            case "truncated" -> Tooltips.textWithSource(
                    "True when search/database export prefix-truncated this header value/raw to fit the live bulk byte budget.",
                    "SearchBodyPrefixFitter sets truncated when shortening header strings under BulkByteBudget pressure.");
            default -> ExportFieldTooltips.genericLeafTooltip("request.headers." + leaf);
        };
    }

    static String responseHeaderEntryFieldTooltip(String leaf) {
        return switch (leaf) {
            case "name" -> Tooltips.textWithSource(
                    "Normalized response header name.",
                    "HttpMessageDocSupport.headersToList() lower-cases HttpHeader.name() into response.headers.name.");
            case "raw" -> Tooltips.textWithSource(
                    "Original response header name as Burp exposed it.",
                    "HttpMessageDocSupport.headersToList() copies HttpHeader.name() into response.headers.raw.");
            case "value" -> Tooltips.textWithSource(
                    "Response header value.",
                    "HttpMessageDocSupport.headersToList() copies HttpHeader.value() into response.headers.value.");
            case "ordinal" -> Tooltips.textWithSource(
                    "Zero-based response header order in the message.",
                    "HttpMessageDocSupport.headersToList() assigns ordinals while preserving duplicate header order.");
            case "truncated" -> Tooltips.textWithSource(
                    "True when search/database export prefix-truncated this header value/raw to fit the live bulk byte budget.",
                    "SearchBodyPrefixFitter sets truncated when shortening header strings under BulkByteBudget pressure.");
            default -> ExportFieldTooltips.genericLeafTooltip("response.headers." + leaf);
        };
    }

    static String requestCookieFieldTooltip(String leaf) {
        return switch (leaf) {
            case "name" -> Tooltips.textWithSource(
                    "Request cookie name.",
                    "HttpMessageDocSupport.requestCookiesToList() parses Cookie header pairs into request.cookies.name.");
            case "value" -> Tooltips.textWithSource(
                    "Request cookie value.",
                    "HttpMessageDocSupport.requestCookiesToList() parses Cookie header pairs into request.cookies.value.");
            case "raw" -> Tooltips.textWithSource(
                    "Raw request Cookie header pair.",
                    "HttpMessageDocSupport.requestCookiesToList() preserves each Cookie pair before splitting name and value.");
            case "ordinal" -> Tooltips.textWithSource(
                    "Zero-based request cookie order in Cookie headers.",
                    "HttpMessageDocSupport.requestCookiesToList() assigns ordinals while parsing Cookie header pairs.");
            case "truncated" -> Tooltips.textWithSource(
                    "True when search/database export prefix-truncated this cookie value/raw to fit the live bulk byte budget.",
                    "SearchBodyPrefixFitter sets truncated when shortening cookie strings under BulkByteBudget pressure.");
            default -> ExportFieldTooltips.genericLeafTooltip("request.cookies." + leaf);
        };
    }

    static String responseCookieFieldTooltip(String leaf) {
        return switch (leaf) {
            case "name" -> Tooltips.textWithSource(
                    "Set-Cookie name.",
                    "HttpMessageDocSupport.responseCookiesToList() uses burp.api.montoya.http.message.Cookie.name().");
            case "value" -> Tooltips.textWithSource(
                    "Set-Cookie value.",
                    "HttpMessageDocSupport.responseCookiesToList() uses Cookie.value().");
            case "domain" -> Tooltips.textWithSource(
                    "Cookie domain attribute.",
                    "HttpMessageDocSupport.responseCookiesToList() uses Cookie.domain().");
            case "path" -> Tooltips.textWithSource(
                    "Cookie path attribute.",
                    "HttpMessageDocSupport.responseCookiesToList() uses Cookie.path().");
            case "expires" -> Tooltips.textWithSource(
                    "Typed cookie expiration helper. Set-Cookie raw remains the authoritative evidence when dates are unusual.",
                    "HttpMessageDocSupport.responseCookiesToList() uses Cookie.expiration() when Montoya exposes it; otherwise"
                            + " it parses Set-Cookie Expires and normalizes recognized browser/HTTP date forms to ISO.");
            case "max_age" -> Tooltips.textWithSource(
                    "Typed Cookie Max-Age helper in seconds. Large values are preserved as long-range numeric helpers.",
                    "HttpMessageDocSupport.responseCookiesToList() preserves the Set-Cookie Max-Age attribute string;"
                            + " Search databases index parseable values as a long.");
            case "secure" -> Tooltips.textWithSource(
                    "Whether the Secure flag was present.",
                    "HttpMessageDocSupport.responseCookiesToList() parses Secure from Set-Cookie.");
            case "http_only" -> Tooltips.textWithSource(
                    "Whether the HttpOnly flag was present.",
                    "HttpMessageDocSupport.responseCookiesToList() parses HttpOnly from Set-Cookie.");
            case "same_site" -> Tooltips.textWithSource(
                    "Cookie SameSite attribute.",
                    "HttpMessageDocSupport.responseCookiesToList() parses SameSite from Set-Cookie.");
            case "partitioned" -> Tooltips.textWithSource(
                    "Whether the Partitioned flag was present.",
                    "HttpMessageDocSupport.responseCookiesToList() parses Partitioned from Set-Cookie.");
            case "raw" -> Tooltips.textWithSource(
                    "Raw Set-Cookie header value; authoritative evidence for cookie attributes.",
                    "HttpMessageDocSupport.responseCookiesToList() preserves the Set-Cookie value before parsing attributes.");
            case "ordinal" -> Tooltips.textWithSource(
                    "Zero-based Set-Cookie order in the response.",
                    "HttpMessageDocSupport.responseCookiesToList() assigns ordinals while preserving duplicate cookie order.");
            case "truncated" -> Tooltips.textWithSource(
                    "True when search/database export prefix-truncated this cookie value/raw to fit the live bulk byte budget.",
                    "SearchBodyPrefixFitter sets truncated when shortening cookie strings under BulkByteBudget pressure.");
            default -> ExportFieldTooltips.genericLeafTooltip("response.cookies." + leaf);
        };
    }
}
