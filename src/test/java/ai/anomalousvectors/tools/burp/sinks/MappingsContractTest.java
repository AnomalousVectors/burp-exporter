package ai.anomalousvectors.tools.burp.sinks;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.config.SearchMappingResources;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Contract tests for the search index mapping resources.
 * Ensures required JSON files are present, parseable, and contain the structure
 * that OpenSearchSink.createIndexFromResource() expects: both "settings" and "mappings"
 * (with non-empty "mappings.properties").
 */
class MappingsContractTest {

    private static final List<String> MAPPING_FILES = List.of(
            "findings.json",
            "exporter.json",
            "settings.json",
            "sitemap.json",
            "traffic.json"
    );

    private static final String RESOURCE_ROOT = SearchMappingResources.DEFAULT_ROOT;
    private static final String HTTP_DATE_FORMAT =
            "EEE, dd MMM yyyy HH:mm:ss zzz||EEE, d MMM yyyy HH:mm:ss zzz||EEE, dd-MMM-yyyy HH:mm:ss zzz"
                    + "||EEE, d-MMM-yyyy HH:mm:ss zzz||EEE, dd-MMM-yy HH:mm:ss zzz"
                    + "||EEE, d-MMM-yy HH:mm:ss zzz||EEE, dd-MMM-yyyy HH:mm:ss 'GMT'Z"
                    + "||EEE, d-MMM-yyyy HH:mm:ss 'GMT'Z||dd MMM yyyy HH:mm:ss zzz"
                    + "||d MMM yyyy HH:mm:ss zzz||strict_date_optional_time||epoch_millis";

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void mappingFiles_exist_parse_andContainRequiredKeys() throws Exception {
        for (String file : MAPPING_FILES) {
            String path = RESOURCE_ROOT + file;

            try (InputStream in = getClass().getResourceAsStream(path)) {
                assertThat(in)
                        .withFailMessage("Resource not found on classpath: %s", path)
                        .isNotNull();

                JsonNode root = mapper.readTree(in);

                // Required by OpenSearchSink: presence of both keys
                assertThat(root.has("settings"))
                        .withFailMessage("Missing 'settings' in %s", file)
                        .isTrue();
                JsonNode settings = root.path("settings");
                assertThat(settings.isObject())
                        .withFailMessage("'settings' must be a JSON object (can be empty) in %s", file)
                        .isTrue();
                assertThat(settings.path("number_of_shards").asInt())
                        .withFailMessage("%s must default newly created indexes to one primary shard", file)
                        .isEqualTo(1);
                assertThat(settings.path("auto_expand_replicas").asText())
                        .withFailMessage("%s must retain one replica only when a second node exists", file)
                        .isEqualTo("0-1");
                assertThat(settings.path("refresh_interval").asText())
                        .withFailMessage("%s must use the conservative refresh default", file)
                        .isEqualTo("5s");

                assertThat(root.has("mappings"))
                        .withFailMessage("Missing 'mappings' in %s", file)
                        .isTrue();
                JsonNode mappings = root.get("mappings");
                assertThat(mappings.isObject())
                        .withFailMessage("'mappings' must be a JSON object in %s", file)
                        .isTrue();

                assertThat(mappings.has("properties"))
                        .withFailMessage("Missing 'mappings.properties' in %s", file)
                        .isTrue();
                JsonNode properties = mappings.get("properties");
                assertThat(properties.isObject())
                        .withFailMessage("'mappings.properties' must be a JSON object in %s", file)
                        .isTrue();
                assertThat(properties.size())
                        .withFailMessage("'mappings.properties' is empty in %s", file)
                        .isGreaterThan(0);
            }
        }
    }

    @Test
    void trafficMapping_containsExpectedWebSocketFields() throws Exception {
        try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + "traffic.json")) {
            assertThat(in).isNotNull();
            JsonNode root = mapper.readTree(in);
            JsonNode props = root.path("mappings").path("properties");
            JsonNode requestProtocol = props.path("request").path("properties").path("protocol").path("properties");
            assertThat(requestProtocol.has("http_version")).isTrue();
            assertThat(requestProtocol.has("scheme")).isFalse();
            assertThat(requestProtocol.has("transport")).isFalse();
            assertThat(requestProtocol.has("host")).isFalse();
            assertThat(requestProtocol.has("port")).isFalse();
            assertThat(props.path("request").path("properties").has("host")).isFalse();
            assertThat(props.path("request").path("properties").has("port")).isFalse();
            JsonNode requestUrl = props.path("request").path("properties").path("url").path("properties");
            assertThat(requestUrl.has("raw")).isTrue();
            assertThat(requestUrl.has("text")).isTrue();
            assertThat(requestUrl.has("scheme")).isTrue();
            assertThat(requestUrl.has("host")).isTrue();
            assertThat(requestUrl.has("port")).isTrue();
            assertThat(requestUrl.path("port").path("ignore_malformed").asBoolean()).isTrue();
            assertThat(requestUrl.has("path")).isTrue();
            assertThat(requestUrl.has("query")).isTrue();
            assertThat(requestUrl.has("fragment")).isTrue();
            assertThat(requestProtocol.has("sub")).isFalse();
            assertThat(requestProtocol.has("application")).isFalse();
            assertThat(props.path("request").path("properties").has("http_version")).isFalse();
            JsonNode responseProtocol = props.path("response").path("properties").path("protocol").path("properties");
            assertThat(responseProtocol.has("http_version")).isTrue();
            assertThat(props.path("response").path("properties").has("http_version")).isFalse();
            JsonNode responseProps = props.path("response").path("properties");
            assertThat(responseProps.path("headers").path("type").asText()).isEqualTo("nested");
            JsonNode responseHeaderAttributes = responseProps.path("header_attributes").path("properties");
            assertThat(responseHeaderAttributes.path("date").path("type").asText()).isEqualTo("date");
            assertThat(responseHeaderAttributes.path("date").path("format").asText()).isEqualTo(HTTP_DATE_FORMAT);
            assertThat(responseHeaderAttributes.path("date").path("ignore_malformed").asBoolean()).isTrue();
            assertThat(responseProps.has("header")).isFalse();
            assertThat(props.path("response").path("properties").has("mime_type")).isTrue();
            assertThat(props.path("response").path("properties").has("stated_mime_type")).isFalse();
            assertThat(props.path("response").path("properties").has("inferred_mime_type")).isFalse();
            JsonNode responseStatus = props.path("response").path("properties").path("status").path("properties");
            assertThat(responseStatus.has("code")).isTrue();
            assertThat(responseStatus.path("code").path("ignore_malformed").asBoolean()).isTrue();
            assertThat(responseStatus.has("code_class")).isTrue();
            assertThat(responseStatus.has("description")).isTrue();
            assertThat(props.path("response").path("properties").has("status_code")).isFalse();
            assertThat(props.path("response").path("properties").has("status_code_class")).isFalse();
            assertThat(props.path("response").path("properties").has("status_description")).isFalse();
            JsonNode requestProps = props.path("request").path("properties");
            assertThat(requestProps.path("headers").path("type").asText()).isEqualTo("nested");
            assertThat(requestProps.has("header")).isFalse();
            JsonNode responseCookies = responseProps.path("cookies").path("properties");
            assertThat(responseCookies.path("expires").path("format").asText()).isEqualTo(HTTP_DATE_FORMAT);
            assertThat(responseCookies.path("expires").path("ignore_malformed").asBoolean()).isTrue();
            assertThat(responseCookies.path("max_age").path("type").asText()).isEqualTo("long");
            assertThat(responseCookies.path("max_age").path("ignore_malformed").asBoolean()).isTrue();
            assertThat(props.path("meta").path("properties").has("export")).isFalse();
            assertThat(props.path("request").path("properties").has("content_type")).isTrue();
            assertThat(props.path("request").path("properties").has("content_type_enum")).isFalse();
            assertThat(props.path("request").path("properties").has("inferred_content_type")).isFalse();
            JsonNode requestPath = props.path("request").path("properties").path("path").path("properties");
            assertThat(requestPath.has("with_query")).isTrue();
            assertThat(requestPath.has("without_query")).isTrue();
            assertThat(requestPath.has("query")).isTrue();
            assertThat(requestPath.has("file_extension")).isTrue();
            assertThat(props.path("request").path("properties").has("path_without_query")).isFalse();
            assertThat(props.path("request").path("properties").has("query")).isFalse();
            assertThat(props.path("request").path("properties").has("file_extension")).isFalse();
            assertThat(props.path("request").path("properties").has("edited")).isFalse();
            assertThat(responseProps.has("header")).isFalse();

            JsonNode burpProxy = props.path("burp").path("properties").path("proxy").path("properties");
            assertThat(burpProxy.has("is_edited")).isFalse();
            assertThat(burpProxy.has("request_is_edited")).isTrue();
            assertThat(burpProxy.has("response_is_edited")).isTrue();
            JsonNode burpTiming = props.path("burp").path("properties").path("timing").path("properties");
            assertThat(burpTiming.has("req_sent")).isTrue();
            assertThat(burpTiming.has("req_sent_to_res_start")).isTrue();
            assertThat(burpTiming.has("req_sent_to_res_end")).isTrue();
            assertThat(burpTiming.has("request_sent")).isFalse();
            assertThat(burpTiming.has("duration_ms")).isFalse();
            assertThat(burpTiming.has("time_to_first_byte_ms")).isFalse();
            assertThat(burpTiming.has("response_start_latency_ms")).isFalse();

            JsonNode websocket = props.path("websocket").path("properties");
            assertThat(websocket.has("direction")).isTrue();
            assertThat(websocket.has("is_edited")).isTrue();
            assertThat(websocket.has("original")).isFalse();
            assertThat(websocket.has("original_payload")).isFalse();
            assertThat(websocket.has("edited_payload")).isFalse();
            assertThat(props.path("request").path("properties").has("original")).isFalse();
            assertThat(props.path("response").path("properties").has("original")).isFalse();
            assertThat(websocket.has("edited")).isFalse();
            assertThat(websocket.has("id")).isTrue();
            assertThat(websocket.has("is_websocket")).isTrue();
            assertThat(websocket.has("message_id")).isTrue();
            assertThat(websocket.has("message_type")).isTrue();
            assertThat(websocket.has("time")).isTrue();
            JsonNode payload = websocket.path("payload").path("properties");
            assertThat(payload.has("b64")).isTrue();
            assertThat(payload.has("length")).isTrue();
            assertThat(payload.has("text")).isTrue();
            assertThat(payload.path("truncated").path("type").asText()).isEqualTo("boolean");
            assertThat(props.has("ws_upgrade_request")).isFalse();
        }
    }

    @Test
    void bodyTruncatedFlag_isBoolean_acrossHttpAndFindingsBodies() throws Exception {
        assertBodyTruncatedBoolean("traffic.json", "request");
        assertBodyTruncatedBoolean("traffic.json", "response");
        assertBodyTruncatedBoolean("sitemap.json", "request");
        assertBodyTruncatedBoolean("sitemap.json", "response");

        try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + "findings.json")) {
            assertThat(in).isNotNull();
            JsonNode root = mapper.readTree(in);
            JsonNode rr = root.path("mappings")
                    .path("properties")
                    .path("requests_responses")
                    .path("properties");
            assertThat(rr.path("request").path("properties").path("body").path("properties")
                    .path("truncated").path("type").asText()).isEqualTo("boolean");
            assertThat(rr.path("response").path("properties").path("body").path("properties")
                    .path("truncated").path("type").asText()).isEqualTo("boolean");
        }
    }

    @Test
    void bodyTextFields_useOffsets_acrossExportedHttpDocs() throws Exception {
        assertTextOffsetsOnRequestAndResponseBodies("traffic.json");
        assertTextOffsetsOnRequestAndResponseBodies("sitemap.json");

        try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + "findings.json")) {
            assertThat(in).isNotNull();
            JsonNode root = mapper.readTree(in);
            JsonNode rr = root.path("mappings")
                    .path("properties")
                    .path("requests_responses")
                    .path("properties");

            assertThat(rr.path("request").path("properties").path("body").path("properties").path("text")
                    .path("index_options").asText()).isEqualTo("offsets");
            assertThat(rr.path("response").path("properties").path("body").path("properties").path("text")
                    .path("index_options").asText()).isEqualTo("offsets");
        }
    }

    @Test
    void responseBodyDerivedFields_areNestedUnderBody_inTrafficAndSitemap() throws Exception {
        assertResponseDerivedFieldsNested("traffic.json");
        assertResponseDerivedFieldsNested("sitemap.json");
    }

    @Test
    void trafficResponse_removesHeaderDuplicatedConvenienceFields() throws Exception {
        try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + "traffic.json")) {
            assertThat(in).isNotNull();
            JsonNode root = mapper.readTree(in);
            JsonNode requestProps = root.path("mappings").path("properties").path("request").path("properties");
            JsonNode responseProps = root.path("mappings").path("properties").path("response").path("properties");

            assertThat(requestProps.has("host")).isFalse();
            assertThat(requestProps.has("content_type")).isTrue();
            assertThat(requestProps.path("headers").path("type").asText()).isEqualTo("nested");
            assertThat(responseProps.has("content_length")).isFalse();
            assertThat(responseProps.path("cookies").path("type").asText()).isEqualTo("nested");
            assertThat(responseProps.path("headers").path("type").asText()).isEqualTo("nested");
            assertThat(responseProps.has("location")).isFalse();
            assertThat(responseProps.has("mime_type")).isTrue();
            assertThat(requestProps.has("header")).isFalse();
            assertThat(responseProps.has("header")).isFalse();
            assertThat(root.path("mappings").has("dynamic_templates")).isFalse();
        }
    }

    @Test
    void sitemap_httpRequestAndResponseMappings_matchTrafficHttpShape() throws Exception {
        JsonNode trafficProps = mappingProperties("traffic.json");
        JsonNode sitemapProps = mappingProperties("sitemap.json");

        assertThat(sitemapProps.path("request")).isEqualTo(trafficProps.path("request"));
        assertThat(sitemapProps.path("response")).isEqualTo(trafficProps.path("response"));
        assertThat(mappingRoot("sitemap.json").path("mappings").has("dynamic_templates")).isFalse();

        JsonNode sitemapBurp = sitemapProps.path("burp").path("properties");
        assertThat(sitemapBurp.has("notes")).isTrue();
        assertThat(sitemapBurp.has("highlight")).isTrue();
        assertThat(sitemapBurp.has("is_in_scope")).isTrue();
        assertThat(sitemapBurp.has("timing")).isTrue();
        assertThat(sitemapBurp.has("reporting_tool")).isFalse();
        assertThat(sitemapBurp.has("proxy")).isFalse();
        assertThat(sitemapBurp.has("repeater")).isFalse();
    }

    @Test
    void findings_evidenceHttpMappings_matchTrafficHttpShape() throws Exception {
        JsonNode trafficProps = mappingProperties("traffic.json");
        JsonNode findingsProps = mappingProperties("findings.json");
        JsonNode evidenceProps = findingsProps.path("requests_responses").path("properties");

        assertThat(evidenceProps.path("request")).isEqualTo(trafficProps.path("request"));
        assertThat(evidenceProps.path("response")).isEqualTo(trafficProps.path("response"));
        assertThat(findingsProps.has("requests_responses")).isTrue();
        assertThat(findingsProps.has("request_responses")).isFalse();
        assertThat(findingsProps.has("request_responses_missing")).isFalse();
        assertThat(mappingRoot("findings.json").path("mappings").has("dynamic_templates")).isFalse();

        JsonNode pairBurp = evidenceProps.path("burp").path("properties");
        assertThat(pairBurp.has("notes")).isTrue();
        assertThat(pairBurp.has("highlight")).isTrue();
        assertThat(pairBurp.path("timing").path("properties").has("req_sent")).isTrue();
        assertThat(pairBurp.path("timing").path("properties").has("req_sent_to_res_start")).isTrue();
        assertThat(pairBurp.path("timing").path("properties").has("req_sent_to_res_end")).isTrue();
        assertThat(pairBurp.path("timing").path("properties").has("end")).isTrue();
        assertThat(evidenceProps.has("annotations")).isFalse();
    }

    @Test
    void findings_collaboratorHttpMappings_matchTrafficHttpShape() throws Exception {
        JsonNode trafficProps = mappingProperties("traffic.json");
        JsonNode collaboratorHttpProps = mappingProperties("findings.json")
                .path("collaborator")
                .path("properties")
                .path("http")
                .path("properties");

        assertThat(collaboratorHttpProps.path("request")).isEqualTo(trafficProps.path("request"));
        assertThat(collaboratorHttpProps.path("response")).isEqualTo(trafficProps.path("response"));
        assertThat(collaboratorHttpProps.has("request_b64")).isTrue();
        assertThat(collaboratorHttpProps.has("response_b64")).isTrue();
    }

    @Test
    void collaboratorMapping_isFindingsOnly_notTraffic() throws Exception {
        JsonNode trafficProps = mappingProperties("traffic.json");
        JsonNode findingsProps = mappingProperties("findings.json");

        assertThat(trafficProps.has("collaborator")).isFalse();
        assertThat(findingsProps.has("collaborator")).isTrue();
    }

    @Test
    void findings_evidencePairs_areNestedUnderPluralRequestsResponses() throws Exception {
        JsonNode findingsProps = mappingProperties("findings.json");
        JsonNode evidence = findingsProps.path("requests_responses");

        assertThat(evidence.path("type").asText()).isEqualTo("nested");
        assertThat(evidence.path("properties").has("request")).isTrue();
        assertThat(evidence.path("properties").has("response")).isTrue();
        assertThat(evidence.path("properties").has("burp")).isTrue();
    }

    @Test
    void findings_rootGroupsIssueTargetAndBurpMetadata() throws Exception {
        JsonNode props = mappingProperties("findings.json");

        assertThat(props.has("burp")).isTrue();
        assertThat(props.has("issue")).isTrue();
        assertThat(props.has("target")).isTrue();
        assertThat(props.has("requests_responses")).isTrue();
        assertThat(props.has("collaborator")).isTrue();
        assertThat(props.has("meta")).isTrue();

        assertThat(props.has("name")).isFalse();
        assertThat(props.has("severity")).isFalse();
        assertThat(props.has("confidence")).isFalse();
        assertThat(props.has("description")).isFalse();
        assertThat(props.has("background")).isFalse();
        assertThat(props.has("remediation_background")).isFalse();
        assertThat(props.has("remediation_detail")).isFalse();
        assertThat(props.has("issue_type_id")).isFalse();
        assertThat(props.has("typical_severity")).isFalse();
        assertThat(props.has("host")).isFalse();
        assertThat(props.has("port")).isFalse();
        assertThat(props.has("url")).isFalse();
        assertThat(props.has("param")).isFalse();
        assertThat(props.has("protocol_transport")).isFalse();
        assertThat(props.has("protocol_application")).isFalse();
        assertThat(props.has("protocol_sub")).isFalse();

        JsonNode issueProps = props.path("issue").path("properties");
        assertThat(issueProps.has("name")).isTrue();
        assertThat(issueProps.has("severity")).isTrue();
        assertThat(issueProps.has("confidence")).isTrue();
        assertThat(issueProps.has("type_id")).isTrue();
        assertThat(issueProps.path("remediation").path("properties").has("detail")).isTrue();
        assertThat(issueProps.path("remediation").path("properties").has("background")).isTrue();

        JsonNode targetProps = props.path("target").path("properties");
        assertThat(targetProps.has("url")).isTrue();
        assertThat(targetProps.has("host")).isTrue();
        assertThat(targetProps.has("port")).isTrue();
        assertThat(targetProps.path("protocol").path("properties").has("scheme")).isTrue();
    }

    @Test
    void findings_nonHttpTypedFields_keepExplicitStrictBoundaries() throws Exception {
        JsonNode props = mappingProperties("findings.json");

        JsonNode collaboratorProps = props.path("collaborator").path("properties");
        assertThat(collaboratorProps.path("client_ip").path("type").asText()).isEqualTo("ip");
        assertThat(collaboratorProps.path("client_ip").has("ignore_malformed")).isFalse();
        assertThat(collaboratorProps.path("client_port").path("type").asText()).isEqualTo("integer");
        assertThat(collaboratorProps.path("client_port").has("ignore_malformed")).isFalse();
        assertThat(collaboratorProps.path("time").path("type").asText()).isEqualTo("date");
        assertThat(collaboratorProps.path("time").has("ignore_malformed")).isFalse();

        JsonNode issueProps = props.path("issue").path("properties");
        assertThat(issueProps.path("type_id").path("type").asText()).isEqualTo("integer");
        assertThat(issueProps.path("type_id").has("ignore_malformed")).isFalse();

        JsonNode targetProps = props.path("target").path("properties");
        assertThat(targetProps.path("port").path("type").asText()).isEqualTo("integer");
        assertThat(targetProps.path("port").has("ignore_malformed")).isFalse();
    }

    @Test
    void settingsAndExporter_keepVariablePayloadsAsOpenObjects() throws Exception {
        JsonNode settingsProps = mappingProperties("settings.json");
        assertThat(settingsProps.path("project").path("type").asText()).isEqualTo("object");
        assertThat(settingsProps.path("project").path("enabled").asBoolean()).isFalse();
        assertThat(settingsProps.path("project").has("properties")).isFalse();
        assertThat(settingsProps.path("user").path("type").asText()).isEqualTo("object");
        assertThat(settingsProps.path("user").path("enabled").asBoolean()).isFalse();
        assertThat(settingsProps.path("user").has("properties")).isFalse();

        JsonNode exporterEventData = mappingProperties("exporter.json")
                .path("event")
                .path("properties")
                .path("data");
        assertThat(exporterEventData.path("type").asText()).isEqualTo("object");
        assertThat(exporterEventData.path("enabled").asBoolean()).isTrue();
        assertThat(exporterEventData.has("properties")).isFalse();
    }

    @Test
    void bodyMetadata_areNestedUnderBody_acrossHttpDocs() throws Exception {
        assertBodyMetadataNested("traffic.json");
        assertBodyMetadataNested("sitemap.json");

        try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + "findings.json")) {
            assertThat(in).isNotNull();
            JsonNode root = mapper.readTree(in);
            JsonNode rr = root.path("mappings")
                    .path("properties")
                    .path("requests_responses")
                    .path("properties");

            JsonNode rrReqProps = rr.path("request").path("properties");
            JsonNode rrReqBodyProps = rrReqProps.path("body").path("properties");
            assertThat(rrReqBodyProps.has("length")).isTrue();
            assertThat(rrReqBodyProps.has("offset")).isTrue();
            assertThat(rrReqProps.has("body_length")).isFalse();
            assertThat(rrReqProps.has("body_offset")).isFalse();

            JsonNode rrRespProps = rr.path("response").path("properties");
            JsonNode rrRespBodyProps = rrRespProps.path("body").path("properties");
            assertThat(rrRespBodyProps.has("length")).isTrue();
            assertThat(rrRespBodyProps.has("offset")).isTrue();
            assertThat(rrRespProps.has("body_length")).isFalse();
            assertThat(rrRespProps.has("body_offset")).isFalse();
        }
    }

    @Test
    void headers_areOrganizedUnderHeadersParent_acrossHttpDocs() throws Exception {
        assertHeadersHierarchy("traffic.json");
        assertHeadersHierarchy("sitemap.json");

        try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + "findings.json")) {
            assertThat(in).isNotNull();
            JsonNode root = mapper.readTree(in);
            JsonNode rr = root.path("mappings")
                    .path("properties")
                    .path("requests_responses")
                    .path("properties");

            JsonNode rrReqProps = rr.path("request").path("properties");
            assertThat(rrReqProps.path("headers").path("type").asText()).isEqualTo("nested");
            assertThat(rrReqProps.has("header")).isFalse();
            assertThat(rr.path("request").path("properties").has("header_names")).isFalse();

            JsonNode rrRespProps = rr.path("response").path("properties");
            assertThat(rrRespProps.path("headers").path("type").asText()).isEqualTo("nested");
            assertThat(rrRespProps.has("header")).isFalse();
            assertThat(rr.path("response").path("properties").has("header_names")).isFalse();
            assertThat(rr.path("response").path("properties").has("etag_header")).isFalse();
            assertThat(rr.path("response").path("properties").has("last_modified_header")).isFalse();
            assertThat(rr.path("response").path("properties").has("content_location")).isFalse();
        }
    }

    private void assertBodyTruncatedBoolean(String mappingFile, String side) throws Exception {
        try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + mappingFile)) {
            assertThat(in).isNotNull();
            JsonNode root = mapper.readTree(in);
            JsonNode bodyProps = root.path("mappings")
                    .path("properties")
                    .path(side)
                    .path("properties")
                    .path("body")
                    .path("properties");
            assertThat(bodyProps.path("truncated").path("type").asText()).isEqualTo("boolean");
        }
    }

    private void assertTextOffsetsOnRequestAndResponseBodies(String mappingFile) throws Exception {
        try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + mappingFile)) {
            assertThat(in).isNotNull();
            JsonNode root = mapper.readTree(in);
            JsonNode props = root.path("mappings").path("properties");

            assertThat(props.path("request").path("properties").path("body").path("properties").path("text")
                    .path("index_options").asText()).isEqualTo("offsets");
            assertThat(props.path("response").path("properties").path("body").path("properties").path("text")
                    .path("index_options").asText()).isEqualTo("offsets");
            JsonNode responseBodyProps = props.path("response").path("properties").path("body").path("properties");
            JsonNode visibleText = isTrafficLikeHttpShape(mappingFile)
                    ? responseBodyProps.path("html").path("properties")
                            .path("text").path("properties").path("visible_text")
                    : responseBodyProps.path("visible_text");
            assertThat(visibleText.path("index_options").asText()).isEqualTo("offsets");
        }
    }

    private void assertResponseDerivedFieldsNested(String mappingFile) throws Exception {
        try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + mappingFile)) {
            assertThat(in).isNotNull();
            JsonNode root = mapper.readTree(in);
            JsonNode responseProps = root.path("mappings").path("properties").path("response").path("properties");
            JsonNode bodyProps = responseProps.path("body").path("properties");
            boolean trafficLikeHttpShape = isTrafficLikeHttpShape(mappingFile);
            if (trafficLikeHttpShape) {
                JsonNode htmlProps = bodyProps.path("html").path("properties");
                JsonNode domProps = htmlProps.path("dom").path("properties");
                JsonNode formsProps = htmlProps.path("forms").path("properties");
                JsonNode linksProps = htmlProps.path("links").path("properties");
                JsonNode textProps = htmlProps.path("text").path("properties");

                assertThat(htmlProps.has("page_title")).isTrue();
                assertThat(htmlProps.has("comments")).isTrue();
                assertThat(textProps.has("visible_text")).isTrue();
                assertThat(textProps.has("visible_word_count")).isTrue();
                assertThat(linksProps.has("anchor_labels")).isTrue();
                assertThat(linksProps.has("canonical_link")).isTrue();
                assertThat(linksProps.has("outbound_edge_count")).isTrue();
                assertThat(linksProps.has("outbound_edge_tag_names")).isTrue();
                assertThat(domProps.has("tag_names")).isTrue();
                assertThat(domProps.has("div_ids")).isTrue();
                assertThat(domProps.has("css_classes")).isTrue();
                assertThat(formsProps.has("button_submit_labels")).isTrue();
                assertThat(formsProps.has("input_image_labels")).isTrue();
                assertThat(formsProps.has("input_submit_labels")).isTrue();
                assertThat(formsProps.has("non_hidden_form_input_types")).isTrue();
                assertThat(bodyProps.has("markers")).isTrue();
            } else {
                assertThat(bodyProps.has("page_title")).isTrue();
                assertThat(bodyProps.has("visible_text")).isTrue();
                assertThat(bodyProps.has("word_count")).isTrue();
                assertThat(bodyProps.has("visible_word_count")).isTrue();
                assertThat(bodyProps.has("line_count")).isTrue();
                assertThat(bodyProps.has("anchor_labels")).isTrue();
                assertThat(bodyProps.has("tag_names")).isTrue();
                assertThat(bodyProps.has("div_ids")).isTrue();
                assertThat(bodyProps.has("css_classes")).isTrue();
            }

            assertThat(responseProps.has("page_title")).isFalse();
            assertThat(responseProps.has("visible_text")).isFalse();
            assertThat(responseProps.has("word_count")).isFalse();
            assertThat(responseProps.has("visible_word_count")).isFalse();
            assertThat(responseProps.has("line_count")).isFalse();
            assertThat(responseProps.has("anchor_labels")).isFalse();
            assertThat(responseProps.has("tag_names")).isFalse();
            assertThat(responseProps.has("div_ids")).isFalse();
            assertThat(responseProps.has("css_classes")).isFalse();
            if (trafficLikeHttpShape) {
                assertThat(bodyProps.has("page_title")).isFalse();
                assertThat(bodyProps.has("visible_text")).isFalse();
                assertThat(bodyProps.has("word_count")).isTrue();
                assertThat(bodyProps.has("visible_word_count")).isFalse();
                assertThat(bodyProps.has("line_count")).isTrue();
                assertThat(bodyProps.has("anchor_labels")).isFalse();
                assertThat(bodyProps.has("tag_names")).isFalse();
                assertThat(bodyProps.has("div_ids")).isFalse();
                assertThat(bodyProps.has("css_classes")).isFalse();
                assertThat(bodyProps.path("html").path("properties").has("visible_text")).isFalse();
                assertThat(bodyProps.path("html").path("properties").has("visible_word_count")).isFalse();
                assertThat(bodyProps.path("html").path("properties").has("anchor_labels")).isFalse();
                assertThat(bodyProps.path("html").path("properties").has("button_submit_labels")).isFalse();
                assertThat(bodyProps.path("html").path("properties").has("tag_names")).isFalse();
                assertThat(responseProps.has("button_submit_labels")).isFalse();
                assertThat(responseProps.has("canonical_link")).isFalse();
                assertThat(responseProps.has("comments")).isFalse();
                assertThat(responseProps.has("input_image_labels")).isFalse();
                assertThat(responseProps.has("input_submit_labels")).isFalse();
                assertThat(responseProps.has("markers")).isFalse();
                assertThat(responseProps.has("non_hidden_form_input_types")).isFalse();
                assertThat(responseProps.has("outbound_edge_count")).isFalse();
                assertThat(responseProps.has("outbound_edge_tag_names")).isFalse();
            }
        }
    }

    @Test
    void trafficRequestMarkers_areNestedUnderRequestBody() throws Exception {
        try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + "traffic.json")) {
            assertThat(in).isNotNull();
            JsonNode root = mapper.readTree(in);
            JsonNode requestProps = root.path("mappings").path("properties").path("request").path("properties");
            JsonNode bodyProps = requestProps.path("body").path("properties");

            assertThat(requestProps.has("markers")).isFalse();
            assertThat(bodyProps.path("markers").path("type").asText()).isEqualTo("nested");
            JsonNode markerProps = bodyProps.path("markers").path("properties");
            assertThat(markerProps.has("start_inclusive")).isTrue();
            assertThat(markerProps.has("end_exclusive")).isTrue();
            assertThat(markerProps.has("start_index_inclusive")).isFalse();
            assertThat(markerProps.has("end_index_exclusive")).isFalse();

            JsonNode responseProps = root.path("mappings").path("properties").path("response").path("properties");
            JsonNode responseBodyProps = responseProps.path("body").path("properties");
            JsonNode responseMarkerProps = responseBodyProps.path("markers").path("properties");
            assertThat(responseProps.has("markers")).isFalse();
            assertThat(responseBodyProps.path("markers").path("type").asText()).isEqualTo("nested");
            assertThat(responseMarkerProps.has("start_inclusive")).isTrue();
            assertThat(responseMarkerProps.has("end_exclusive")).isTrue();
            assertThat(responseMarkerProps.has("start_index_inclusive")).isFalse();
            assertThat(responseMarkerProps.has("end_index_exclusive")).isFalse();
        }
    }

    private void assertHeadersHierarchy(String mappingFile) throws Exception {
        try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + mappingFile)) {
            assertThat(in).isNotNull();
            JsonNode root = mapper.readTree(in);
            JsonNode props = root.path("mappings").path("properties");

            JsonNode requestProps = props.path("request").path("properties");
            JsonNode requestHeaders = requestProps.path("headers").path("properties");
            assertThat(requestProps.path("headers").path("type").asText()).isEqualTo("nested");
            assertThat(requestHeaders.has("name")).isTrue();
            assertThat(requestHeaders.has("raw")).isTrue();
            assertThat(requestHeaders.has("raw_name")).isFalse();
            assertThat(requestHeaders.has("value")).isTrue();
            assertThat(requestHeaders.has("ordinal")).isTrue();
            assertThat(requestHeaders.has("full")).isFalse();
            assertThat(requestProps.has("header")).isFalse();

            JsonNode responseProps = props.path("response").path("properties");
            JsonNode responseHeaders = responseProps.path("headers").path("properties");
            assertThat(responseProps.path("headers").path("type").asText()).isEqualTo("nested");
            assertThat(responseHeaders.has("name")).isTrue();
            assertThat(responseHeaders.has("raw")).isTrue();
            assertThat(responseHeaders.has("raw_name")).isFalse();
            assertThat(responseHeaders.has("value")).isTrue();
            assertThat(responseHeaders.has("ordinal")).isTrue();
            assertThat(responseHeaders.has("full")).isFalse();
            assertThat(responseProps.has("header")).isFalse();
            assertThat(responseHeaders.has("names")).isFalse();
            assertThat(responseHeaders.has("etag")).isFalse();
            assertThat(responseHeaders.has("last_modified")).isFalse();
            assertThat(responseHeaders.has("content_location")).isFalse();

            assertThat(responseProps.has("header_names")).isFalse();
            assertThat(responseProps.has("etag_header")).isFalse();
            assertThat(responseProps.has("last_modified_header")).isFalse();
            assertThat(responseProps.has("content_location")).isFalse();
        }
    }

    private static boolean isTrafficLikeHttpShape(String mappingFile) {
        return "traffic.json".equals(mappingFile) || "sitemap.json".equals(mappingFile);
    }

    private JsonNode mappingRoot(String mappingFile) throws Exception {
        try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + mappingFile)) {
            assertThat(in).isNotNull();
            return mapper.readTree(in);
        }
    }

    private JsonNode mappingProperties(String mappingFile) throws Exception {
        return mappingRoot(mappingFile).path("mappings").path("properties");
    }

    /**
     * Guards the Lucene 32766-byte per-term cap protection added universally across shipped mappings.
     *
     * <p>Every {@code "type": "keyword"} declaration - including {@code fields.raw} subfields under
     * {@code text} parents - must carry {@code "ignore_above": 8191}. The threshold is chosen so the
     * worst-case UTF-8 encoding of a Java-char-counted value ({@code 8191 * 3 = 24573} bytes) stays
     * comfortably under the Lucene cap. Skipping {@code ignore_above} on any keyword field reopens
     * the "Document contains at least one immense term" failure mode observed pre-fix.</p>
     */
    @Test
    void everyKeywordField_hasIgnoreAboveGuard() throws Exception {
        List<String> violations = new ArrayList<>();
        for (String file : MAPPING_FILES) {
            try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + file)) {
                assertThat(in).isNotNull();
                JsonNode root = mapper.readTree(in);
                collectKeywordViolations(file, "", root, violations);
            }
        }
        assertThat(violations)
                .withFailMessage("Every keyword declaration must carry \"ignore_above\": 8191. Violations:%n%s",
                        String.join("\n", violations))
                .isEmpty();
    }

    @Test
    void sitemap_rootKeepsOnlySitemapSpecificFieldsBesideSharedDocumentObjects() throws Exception {
        try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + "sitemap.json")) {
            assertThat(in).isNotNull();
            JsonNode props = mapper.readTree(in).path("mappings").path("properties");
            assertThat(props.has("meta")).isTrue();
            assertThat(props.has("burp")).isTrue();
            assertThat(props.has("request")).isTrue();
            assertThat(props.has("response")).isTrue();
            assertThat(props.has("request_id")).isFalse();
            assertThat(props.has("source")).isFalse();
            assertThat(props.has("sitemap")).isFalse();
            assertThat(props.has("websocket")).isFalse();
            assertThat(props.has("url")).isFalse();
            assertThat(props.has("host")).isFalse();
            assertThat(props.has("port")).isFalse();
            assertThat(props.has("method")).isFalse();
            assertThat(props.has("status")).isFalse();
            assertThat(props.has("reason_phrase")).isFalse();
            assertThat(props.has("mime_type")).isFalse();
            assertThat(props.has("content_length")).isFalse();
            assertThat(props.has("param_names")).isFalse();
            assertThat(props.has("path")).isFalse();
            assertThat(props.has("query_string")).isFalse();
            assertThat(props.has("title")).isFalse();
        }
    }

    /**
     * Guards the project-standard multi-field shape on string fields that benefit from both
     * full-text search on the parent and exact-match/aggregation on a {@code .raw} sub-field.
     *
     * <p>Each entry asserts that the field path resolves to {@code {type: text,
     * fields: {raw: {type: keyword, ignore_above: 8191}}}} in the named mapping. The five
     * fields below were aligned to this shape together; adding or removing entries should be
     * a deliberate schema decision rather than an accidental drift.</p>
     */
    @Test
    void stringFields_haveExactMatchSubfield_whereExpected() throws Exception {
        record FieldShape(String mappingFile, String dottedPath) {}
        List<FieldShape> expected = List.of(
                new FieldShape("sitemap.json",  "request.url.path"),
                new FieldShape("sitemap.json",  "request.url.query"),
                new FieldShape("sitemap.json",  "request.path.query"),
                new FieldShape("sitemap.json",  "response.body.html.comments"),
                new FieldShape("sitemap.json",  "burp.notes"),
                new FieldShape("traffic.json",  "response.body.html.comments"),
                new FieldShape("traffic.json",  "burp.notes"),
                new FieldShape("findings.json", "issue.name"),
                new FieldShape("findings.json", "target.url"),
                new FieldShape("findings.json", "requests_responses.request.url.path"),
                new FieldShape("findings.json", "requests_responses.request.url.query"),
                new FieldShape("findings.json", "requests_responses.response.body.html.comments"),
                new FieldShape("findings.json", "requests_responses.burp.notes"),
                new FieldShape("findings.json", "collaborator.http.request.url.path"),
                new FieldShape("findings.json", "collaborator.http.request.url.query"),
                new FieldShape("findings.json", "collaborator.http.response.body.html.comments")
        );

        List<String> violations = new ArrayList<>();
        for (FieldShape entry : expected) {
            try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + entry.mappingFile())) {
                assertThat(in)
                        .withFailMessage("Resource not found on classpath: %s", entry.mappingFile())
                        .isNotNull();
                JsonNode root = mapper.readTree(in);
                JsonNode field = resolveFieldNode(root, entry.dottedPath());

                if (field == null || field.isMissingNode() || field.isNull()) {
                    violations.add(entry.mappingFile() + " @ " + entry.dottedPath() + " - field not found");
                    continue;
                }
                JsonNode type = field.get("type");
                JsonNode rawType = field.path("fields").path("raw").path("type");
                JsonNode rawIgnoreAbove = field.path("fields").path("raw").path("ignore_above");
                boolean ok = type != null && type.isTextual() && "text".equals(type.asText())
                        && rawType.isTextual() && "keyword".equals(rawType.asText())
                        && rawIgnoreAbove.isNumber() && rawIgnoreAbove.asInt() == 8191;
                if (!ok) {
                    violations.add(entry.mappingFile() + " @ " + entry.dottedPath()
                            + " - expected {type:text, fields.raw:{type:keyword, ignore_above:8191}}, "
                            + "got type=" + type + " fields.raw.type=" + rawType
                            + " fields.raw.ignore_above=" + rawIgnoreAbove);
                }
            }
        }
        assertThat(violations)
                .withFailMessage("Multi-field shape regressions:%n%s", String.join("\n", violations))
                .isEmpty();
    }

    private static JsonNode resolveFieldNode(JsonNode root, String dottedPath) {
        JsonNode node = root.path("mappings").path("properties");
        String[] parts = dottedPath.split("\\.");
        for (int i = 0; i < parts.length; i++) {
            node = node.path(parts[i]);
            if (i < parts.length - 1) {
                node = node.path("properties");
            }
        }
        return node;
    }

    /**
     * Guards the per-index nested-document cap for mappings that declare nested fields.
     *
     * <p>The three HTTP-centric mappings ({@code traffic.json}, {@code findings.json},
     * {@code sitemap.json}) aggregate nested arrays per document (headers, parameters, markers,
     * cookies). With the synthesized-BODY parameter filter (in
     * {@link ai.anomalousvectors.tools.burp.sinks.RequestResponseDocBuilder}) in place, legit
     * per-doc nested counts sit in the low hundreds, well under the OpenSearch default of
     * 10000. Shipping without an override keeps the shipped settings block minimal and lets
     * cluster operators tune if ever needed. If a future regression requires raising the
     * ceiling, add the override and update the plan note that cleared it.</p>
     */
    @Test
    void httpMappings_doNotOverrideNestedObjectsLimit() throws Exception {
        List<String> filesWithNested = List.of("traffic.json", "findings.json", "sitemap.json");
        for (String file : filesWithNested) {
            try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + file)) {
                assertThat(in).isNotNull();
                JsonNode root = mapper.readTree(in);
                JsonNode limit = root.path("settings").path("index.mapping.nested_objects.limit");
                assertThat(limit.isMissingNode() || limit.isNull())
                        .withFailMessage(
                                "%s must not override index.mapping.nested_objects.limit; "
                                        + "the synthesized-BODY parameter filter keeps legit "
                                        + "nested counts under the OpenSearch default",
                                file)
                        .isTrue();
            }
        }
    }

    private static void collectKeywordViolations(String file, String path, JsonNode node, List<String> violations) {
        if (node == null) return;
        if (node.isObject()) {
            JsonNode type = node.get("type");
            if (type != null && type.isTextual() && "keyword".equals(type.asText())) {
                JsonNode ignoreAbove = node.get("ignore_above");
                if (ignoreAbove == null || !ignoreAbove.isNumber() || ignoreAbove.asInt() != 8191) {
                    violations.add(file + " @ " + (path.isEmpty() ? "<root>" : path)
                            + " - expected ignore_above=8191, found " + ignoreAbove);
                }
            }
            for (Map.Entry<String, JsonNode> entry : node.properties()) {
                collectKeywordViolations(file, path.isEmpty() ? entry.getKey() : path + "." + entry.getKey(),
                        entry.getValue(), violations);
            }
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                collectKeywordViolations(file, path + "[" + i + "]", node.get(i), violations);
            }
        }
    }

    private void assertBodyMetadataNested(String mappingFile) throws Exception {
        try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + mappingFile)) {
            assertThat(in).isNotNull();
            JsonNode root = mapper.readTree(in);
            JsonNode props = root.path("mappings").path("properties");

            JsonNode requestProps = props.path("request").path("properties");
            JsonNode requestBody = requestProps.path("body").path("properties");
            assertThat(requestBody.has("length")).isTrue();
            assertThat(requestBody.has("offset")).isTrue();
            assertThat(requestBody.has("decoded")).isFalse();
            assertThat(requestProps.has("body_length")).isFalse();
            assertThat(requestProps.has("body_offset")).isFalse();

            JsonNode responseProps = props.path("response").path("properties");
            JsonNode responseBody = responseProps.path("body").path("properties");
            assertThat(responseBody.has("length")).isTrue();
            assertThat(responseBody.has("offset")).isTrue();
            assertThat(responseBody.has("decoded")).isFalse();
            assertThat(responseProps.has("body_length")).isFalse();
            assertThat(responseProps.has("body_offset")).isFalse();
        }
    }
}
