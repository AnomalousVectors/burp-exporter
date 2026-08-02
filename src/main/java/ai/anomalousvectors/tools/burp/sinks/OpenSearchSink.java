package ai.anomalousvectors.tools.burp.sinks;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.BooleanSupplier;

import jakarta.json.Json;
import jakarta.json.JsonException;
import jakarta.json.JsonReader;
import jakarta.json.JsonObject;
import jakarta.json.JsonWriter;
import jakarta.json.stream.JsonParser;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpHead;
import org.apache.hc.client5.http.classic.methods.HttpPut;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.opensearch.client.json.JsonpMapper;
import org.opensearch.client.json.jackson.JacksonJsonpMapper;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch._types.mapping.TypeMapping;
import org.opensearch.client.opensearch.indices.CreateIndexRequest;
import org.opensearch.client.opensearch.indices.CreateIndexResponse;
import org.opensearch.client.opensearch.indices.IndexSettings;

import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.SearchMappingResources;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchAuth;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchConnector;
import ai.anomalousvectors.tools.burp.utils.search.SearchDeployment;
import ai.anomalousvectors.tools.burp.utils.search.SearchIndexMappingAdapter;

/**
 * Creates search database indices from bundled JSON mapping files.
 *
 * <p>Clients are obtained via {@link OpenSearchConnector} and must not be closed here. Public
 * creation operations perform synchronous network and mapping-compatibility I/O; callers must not
 * invoke them on the EDT. Operational failures are returned as {@link IndexResult} values rather
 * than thrown.</p>
 */
public class OpenSearchSink {

    /**
     * Creates or validates the index for a logical key with runtime mapping and authentication.
     *
     * @param baseUrl search destination base URL
     * @param shortName logical index key and bundled mapping name
     * @return created, compatible-existing, or failed result
     */
    public static IndexResult createIndexFromResource(String baseUrl, String shortName) {
        final String root = SearchMappingResources.configuredRoot();
        return createIndexFromResource(
                baseUrl, shortName, resolvedFullIndexName(shortName), root, (String) null, null);
    }

    /**
     * Creates or validates the index for a logical key from an explicit resource root.
     *
     * @param baseUrl search destination base URL
     * @param shortName logical index key and bundled mapping name
     * @param mappingsResourceRoot classpath resource root; blank uses the configured default
     * @return created, compatible-existing, or failed result
     */
    public static IndexResult createIndexFromResource(String baseUrl, String shortName, String mappingsResourceRoot) {
        return createIndexFromResource(
                baseUrl,
                shortName,
                resolvedFullIndexName(shortName),
                mappingsResourceRoot,
                (String) null,
                null);
    }

    /**
     * Creates or validates the index for a logical key with optional basic authentication.
     *
     * @param baseUrl search destination base URL
     * @param shortName logical index key and bundled mapping name
     * @param mappingsResourceRoot classpath resource root; blank uses the configured default
     * @param username basic-auth username; blank disables basic authentication
     * @param password basic-auth password; blank disables basic authentication
     * @return created, compatible-existing, or failed result
     */
    public static IndexResult createIndexFromResource(String baseUrl, String shortName, String mappingsResourceRoot,
            String username, String password) {
        OpenSearchAuth auth = username == null || username.isBlank() || password == null || password.isBlank()
                ? OpenSearchAuth.none()
                : OpenSearchAuth.basic(username, password);
        return createIndexFromResource(baseUrl, shortName, resolvedFullIndexName(shortName), mappingsResourceRoot, auth);
    }

    /**
     * Creates or validates the index for a logical key with explicit authentication.
     *
     * @param baseUrl search destination base URL
     * @param shortName logical index key and bundled mapping name
     * @param mappingsResourceRoot classpath resource root; blank uses the configured default
     * @param auth authentication strategy
     * @return created, compatible-existing, or failed result
     */
    public static IndexResult createIndexFromResource(String baseUrl, String shortName, String mappingsResourceRoot,
            OpenSearchAuth auth) {
        return createIndexFromResource(baseUrl, shortName, resolvedFullIndexName(shortName), mappingsResourceRoot, auth);
    }

    /**
     * Creates or validates an explicitly named index with optional basic authentication.
     *
     * @param baseUrl search destination base URL
     * @param shortName logical index key and bundled mapping name
     * @param fullIndexName concrete destination index name
     * @param mappingsResourceRoot classpath resource root; blank uses the configured default
     * @param username basic-auth username; blank disables basic authentication
     * @param password basic-auth password; blank disables basic authentication
     * @return created, compatible-existing, or failed result
     */
    public static IndexResult createIndexFromResource(String baseUrl, String shortName, String fullIndexName, String mappingsResourceRoot,
            String username, String password) {
        OpenSearchAuth auth = username == null || username.isBlank() || password == null || password.isBlank()
                ? OpenSearchAuth.none()
                : OpenSearchAuth.basic(username, password);
        return createIndexFromResource(baseUrl, shortName, fullIndexName, mappingsResourceRoot, auth);
    }

    /**
     * Creates or validates an explicitly named index with explicit authentication.
     *
     * @param baseUrl search destination base URL
     * @param shortName logical index key and bundled mapping name
     * @param fullIndexName concrete destination index name
     * @param mappingsResourceRoot classpath resource root; blank uses the configured default
     * @param auth authentication strategy
     * @return created, compatible-existing, or failed result
     */
    public static IndexResult createIndexFromResource(String baseUrl, String shortName, String fullIndexName,
            String mappingsResourceRoot, OpenSearchAuth auth) {
        return createIndexFromResource(
                baseUrl, shortName, fullIndexName, mappingsResourceRoot, auth, null);
    }

    private static IndexResult createIndexFromResource(
            String baseUrl,
            String shortName,
            String fullIndexName,
            String mappingsResourceRoot,
            OpenSearchAuth auth,
            Boolean knownExists) {
        final String defaultRoot = SearchMappingResources.configuredRoot();
        final String resourceRoot = (mappingsResourceRoot == null || mappingsResourceRoot.isBlank())
                ? defaultRoot
                : mappingsResourceRoot;

        String mappingShortName = shortName == null ? "" : shortName.trim().toLowerCase(java.util.Locale.ROOT);
        final String mappingFile = resourceRoot + mappingShortName + ".json";

        String databaseName = RuntimeConfig.searchDestinationDisplayName();
        Logger.logDebug("[" + databaseName + "] Attempting to create index: " + fullIndexName);
        Logger.logDebug("[" + databaseName + "] Using mapping file: " + mappingFile);

        String jsonBody = null;

        try {
            try (InputStream is = OpenSearchSink.class.getResourceAsStream(mappingFile)) {
                if (is == null) {
                    String reason = "Mapping file not found: " + mappingFile;
                    Logger.logErrorPanelOnly("[" + databaseName + "] " + reason);
                    return new IndexResult(shortName, fullIndexName, IndexResult.Status.FAILED, reason);
                }
                jsonBody = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }
            jsonBody = SearchIndexMappingAdapter.adapt(
                    jsonBody,
                    RuntimeConfig.searchDestinationKind(),
                    baseUrl,
                    RuntimeConfig.searchDeploymentType());

            if (RuntimeConfig.searchDestinationKind() == ConfigState.SearchDestination.ELASTICSEARCH
                    || RuntimeConfig.searchDestinationKind() == ConfigState.SearchDestination.OPEN_SEARCH_AMAZON) {
                return createIndexWithRawHttp(
                        baseUrl, shortName, fullIndexName, jsonBody, auth, knownExists);
            }

            OpenSearchClient client = OpenSearchConnector.getClient(baseUrl, auth);

            boolean exists = client.indices().exists(b -> b.index(fullIndexName)).value();
            if (exists) {
                return validateExistingIndexSettings(
                        baseUrl, shortName, fullIndexName, jsonBody, auth, databaseName);
            }

            JsonObject root;
            try (JsonReader reader = Json.createReader(new StringReader(jsonBody))) {
                root = reader.readObject();
            }

            JsonObject settingsJson = root.getJsonObject("settings");
            JsonObject mappingsJson = root.getJsonObject("mappings");

            if (settingsJson == null || mappingsJson == null) {
                String reason = "Mapping JSON must contain both 'settings' and 'mappings'.";
                Logger.logErrorPanelOnly("[" + databaseName + "] " + reason);
                return new IndexResult(shortName, fullIndexName, IndexResult.Status.FAILED, reason);
            }

            // Local mapper for static JSON content (avoid touching client transport).
            JsonpMapper mapper = new JacksonJsonpMapper();

            IndexSettings settings;
            try (JsonParser settingsParser = Json.createParser(new StringReader(settingsJson.toString()))) {
                settings = IndexSettings._DESERIALIZER.deserialize(settingsParser, mapper);
            }

            TypeMapping mappings;
            try (JsonParser mappingsParser = Json.createParser(new StringReader(mappingsJson.toString()))) {
                mappings = TypeMapping._DESERIALIZER.deserialize(mappingsParser, mapper);
            }

            CreateIndexRequest request = new CreateIndexRequest.Builder()
                    .index(fullIndexName)
                    .settings(settings)
                    .mappings(mappings)
                    .build();

            CreateIndexResponse response = client.indices().create(request);

            Logger.logDebug("[" + databaseName + "] Create index " + fullIndexName
                    + " acknowledged=" + response.acknowledged());

            return new IndexResult(
                    shortName,
                    fullIndexName,
                    response.acknowledged() ? IndexResult.Status.CREATED : IndexResult.Status.FAILED,
                    response.acknowledged() ? null : "Create not acknowledged"
            );

        } catch (IOException | RuntimeException e) {
            Logger.logErrorPanelOnly("[" + databaseName + "] Exception while creating index: " + fullIndexName);
            if (jsonBody != null) Logger.logErrorPanelOnly("[" + databaseName + "] Mapping JSON: " + compactJson(jsonBody));
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            Logger.logErrorPanelOnly(sw.toString().stripTrailing());
            String reason = conciseRootCause(e);
            return new IndexResult(shortName, fullIndexName, IndexResult.Status.FAILED, reason);
        }
    }

    private static IndexResult createIndexWithRawHttp(
            String baseUrl,
            String shortName,
            String fullIndexName,
            String jsonBody,
            OpenSearchAuth auth,
            Boolean knownExists) {
        try {
            String databaseName = RuntimeConfig.searchDestinationDisplayName();
            HttpHost host = ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClassicHttpSupport
                    .hostForBaseUrl(baseUrl);
            var client = OpenSearchConnector.getClassicHttpClient(baseUrl, auth);
            Boolean exists = knownExists == null
                    ? indexExistsWithHead(baseUrl, fullIndexName, auth, host, client)
                    : knownExists;
            if (Boolean.TRUE.equals(exists)) {
                return validateExistingIndexSettings(
                        baseUrl, shortName, fullIndexName, jsonBody, auth, databaseName);
            }

            HttpPut put = new HttpPut("/" + fullIndexName);
            auth.applyTo(put);
            byte[] body = jsonBody.getBytes(StandardCharsets.UTF_8);
            put.setEntity(new StringEntity(jsonBody, ContentType.APPLICATION_JSON));
            if (ai.anomalousvectors.tools.burp.utils.opensearch.AmazonOpenSearchSigV4.isEnabledForRuntime()) {
                ai.anomalousvectors.tools.burp.utils.opensearch.AmazonOpenSearchSigV4.sign(
                        put, "PUT", baseUrl, "/" + fullIndexName, body);
            }
            return client.execute(host, put, response -> {
                int status = response.getCode();
                String responseBody;
                try {
                    responseBody = response.getEntity() == null
                            ? ""
                            : EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
                } catch (ParseException e) {
                    throw new IOException("Failed to parse index creation response.", e);
                }
                if (status >= 200 && status < 300) {
                    Logger.logDebug("[" + databaseName + "] Create index " + fullIndexName + " returned HTTP " + status);
                    return new IndexResult(shortName, fullIndexName, IndexResult.Status.CREATED, null);
                }
                String reason = responseBody == null || responseBody.isBlank()
                        ? "HTTP " + status
                        : "HTTP " + status + ": " + responseBody;
                return new IndexResult(shortName, fullIndexName, IndexResult.Status.FAILED, conciseDetail(reason));
            });
        } catch (IOException | RuntimeException e) {
            Logger.logErrorPanelOnly("[" + RuntimeConfig.searchDestinationDisplayName()
                    + "] Exception while creating index: " + fullIndexName);
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            Logger.logErrorPanelOnly(sw.toString().stripTrailing());
            return new IndexResult(shortName, fullIndexName, IndexResult.Status.FAILED, conciseRootCause(e));
        }
    }

    private static Boolean indexExistsWithHead(
            String baseUrl,
            String fullIndexName,
            OpenSearchAuth auth,
            HttpHost host,
            org.apache.hc.client5.http.impl.classic.CloseableHttpClient client) throws IOException {
        HttpHead head = new HttpHead("/" + fullIndexName);
        auth.applyTo(head);
        if (ai.anomalousvectors.tools.burp.utils.opensearch.AmazonOpenSearchSigV4.isEnabledForRuntime()) {
            ai.anomalousvectors.tools.burp.utils.opensearch.AmazonOpenSearchSigV4.sign(
                    head, "HEAD", baseUrl, "/" + fullIndexName, new byte[0]);
        }
        return client.execute(host, head, response -> {
            int status = response.getCode();
            if (status == 200) {
                return true;
            }
            if (status == 404) {
                return false;
            }
            throw new IOException("Index existence check failed: HTTP " + status);
        });
    }

    static Set<String> listExistingIndexNames(
            String baseUrl,
            OpenSearchAuth auth) throws IOException {
        String path = "/_cat/indices?format=json&h=index";
        HttpHost host = ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClassicHttpSupport
                .hostForBaseUrl(baseUrl);
        var client = OpenSearchConnector.getClassicHttpClient(baseUrl, auth);
        HttpGet get = new HttpGet(path);
        auth.applyTo(get);
        if (ai.anomalousvectors.tools.burp.utils.opensearch.AmazonOpenSearchSigV4.isEnabledForRuntime()) {
            ai.anomalousvectors.tools.burp.utils.opensearch.AmazonOpenSearchSigV4.sign(
                    get, "GET", baseUrl, path, new byte[0]);
        }
        String body = client.execute(host, get, response -> {
            int status = response.getCode();
            String responseBody;
            try {
                responseBody = response.getEntity() == null
                        ? ""
                        : EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            } catch (ParseException e) {
                throw new IOException("Failed to parse index-list response.", e);
            }
            if (status < 200 || status >= 300) {
                throw new IOException("Index-list request failed: HTTP " + status);
            }
            return responseBody;
        });
        try (JsonReader reader = Json.createReader(new StringReader(body))) {
            Set<String> names = new LinkedHashSet<>();
            reader.readArray().forEach(value -> {
                if (value instanceof JsonObject object) {
                    String name = object.getString("index", "").trim();
                    if (!name.isEmpty()) {
                        names.add(name);
                    }
                }
            });
            return names;
        } catch (JsonException e) {
            throw new IOException("Index-list response was not valid JSON.", e);
        }
    }

    static IndexResult validateExistingIndexSettings(
            String baseUrl,
            String shortName,
            String fullIndexName,
            String expectedMappingJson,
            OpenSearchAuth auth,
            String databaseName) throws IOException {
        HttpHost host = ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClassicHttpSupport
                .hostForBaseUrl(baseUrl);
        var client = OpenSearchConnector.getClassicHttpClient(baseUrl, auth);
        String path = "/" + fullIndexName + "/_settings?flat_settings=true";
        HttpGet get = new HttpGet(path);
        auth.applyTo(get);
        if (ai.anomalousvectors.tools.burp.utils.opensearch.AmazonOpenSearchSigV4.isEnabledForRuntime()) {
            ai.anomalousvectors.tools.burp.utils.opensearch.AmazonOpenSearchSigV4.sign(
                    get, "GET", baseUrl, path, new byte[0]);
        }
        ExistingSettingsResponse settingsResponse = client.execute(host, get, response -> {
            int status = response.getCode();
            String body;
            try {
                body = response.getEntity() == null
                        ? ""
                        : EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            } catch (ParseException e) {
                throw new IOException("Failed to parse existing index settings response.", e);
            }
            return new ExistingSettingsResponse(status, body);
        });
        boolean settingsReadDenied = SearchIndexSettingsCompatibility.isSettingsReadPermissionDenied(
                settingsResponse.status());
        if (settingsReadDenied) {
            Logger.logWarnPanelOnly("[" + databaseName + "] Existing index settings could not be verified for "
                    + fullIndexName
                    + " because the configured principal lacks settings-read permission (HTTP "
                    + settingsResponse.status()
                    + "); continuing to the mapping compatibility check.");
        } else if (settingsResponse.status() < 200 || settingsResponse.status() >= 300) {
            String detail = "Existing index settings check failed: HTTP " + settingsResponse.status();
            Logger.logErrorPanelOnly("[" + databaseName + "] " + fullIndexName + ": " + detail);
            return new IndexResult(shortName, fullIndexName, IndexResult.Status.FAILED, detail);
        } else {
            String incompatibility = SearchIndexSettingsCompatibility.incompatibilityDetail(
                    expectedMappingJson, settingsResponse.body(), fullIndexName);
            if (incompatibility != null) {
                String detail = conciseDetail(incompatibility);
                Logger.logErrorPanelOnly("[" + databaseName + "] " + fullIndexName + ": " + detail);
                return new IndexResult(shortName, fullIndexName, IndexResult.Status.FAILED, detail);
            }
        }

        String mappingPath = "/" + fullIndexName + "/_mapping";
        HttpGet mappingGet = new HttpGet(mappingPath);
        auth.applyTo(mappingGet);
        if (ai.anomalousvectors.tools.burp.utils.opensearch.AmazonOpenSearchSigV4.isEnabledForRuntime()) {
            ai.anomalousvectors.tools.burp.utils.opensearch.AmazonOpenSearchSigV4.sign(
                    mappingGet, "GET", baseUrl, mappingPath, new byte[0]);
        }
        ExistingSettingsResponse mappingResponse = client.execute(host, mappingGet, response -> {
            int status = response.getCode();
            String body;
            try {
                body = response.getEntity() == null
                        ? ""
                        : EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            } catch (ParseException e) {
                throw new IOException("Failed to parse existing index mapping response.", e);
            }
            return new ExistingSettingsResponse(status, body);
        });
        if (SearchIndexSettingsCompatibility.isSettingsReadPermissionDenied(mappingResponse.status())) {
            Logger.logWarnPanelOnly("[" + databaseName + "] Existing index mapping could not be verified for "
                    + fullIndexName
                    + " because the configured principal lacks mapping-read permission (HTTP "
                    + mappingResponse.status()
                    + "); continuing without the compatibility check.");
            return new IndexResult(shortName, fullIndexName, IndexResult.Status.EXISTS, null);
        }
        if (mappingResponse.status() < 200 || mappingResponse.status() >= 300) {
            String detail = "Existing index mapping check failed: HTTP " + mappingResponse.status();
            Logger.logErrorPanelOnly("[" + databaseName + "] " + fullIndexName + ": " + detail);
            return new IndexResult(shortName, fullIndexName, IndexResult.Status.FAILED, detail);
        }
        String mappingIncompatibility = SearchIndexMappingCompatibility.incompatibilityDetail(
                expectedMappingJson, mappingResponse.body(), fullIndexName);
        if (mappingIncompatibility != null) {
            String detail = conciseDetail(mappingIncompatibility);
            Logger.logErrorPanelOnly("[" + databaseName + "] " + fullIndexName + ": " + detail);
            return new IndexResult(shortName, fullIndexName, IndexResult.Status.FAILED, detail);
        }
        Logger.logDebug("[" + databaseName + "] Index already exists with compatible settings and mapping: "
                + fullIndexName);
        return new IndexResult(shortName, fullIndexName, IndexResult.Status.EXISTS, null);
    }

    private record ExistingSettingsResponse(int status, String body) {
    }

    /**
     * Creates all indices required by the selected sources.
     *
     * <p>Only source keys recognized by {@link IndexNaming#computeIndexBaseNames(List)} produce
     * indices. For example, the Exporter index is created only when the {@code exporter} source is
     * selected.</p>
     *
     * @param baseUrl search destination base URL
     * @param selectedSources configured source keys
     * @return ordered creation/validation results for recognized selected indices
     */
    public static List<IndexResult> createSelectedIndexes(String baseUrl, List<String> selectedSources) {
        return createSelectedIndexes(baseUrl, selectedSources, (String) null, null);
    }

    /**
     * Creates all indices required by the selected sources with optional basic auth.
     *
     * @param baseUrl search destination base URL
     * @param selectedSources configured source keys
     * @param username basic-auth username; blank disables basic authentication
     * @param password basic-auth password; blank disables basic authentication
     * @return ordered creation/validation results for recognized selected indices
     */
    public static List<IndexResult> createSelectedIndexes(String baseUrl, List<String> selectedSources,
            String username, String password) {
        return createSelectedIndexes(baseUrl, selectedSources, username, password, () -> true);
    }

    /**
     * Creates all indices required by the selected sources with optional basic auth.
     *
     * <p>The continuation signal is checked before inventory and between index operations. A
     * cancellation returns the results completed so far.</p>
     *
     * @param baseUrl search destination base URL
     * @param selectedSources configured source keys
     * @param username basic-auth username; blank disables basic authentication
     * @param password basic-auth password; blank disables basic authentication
     * @param shouldContinue continuation signal; {@code null} means continue
     * @return ordered results completed before success, failure, or cancellation
     */
    public static List<IndexResult> createSelectedIndexes(String baseUrl, List<String> selectedSources,
            String username, String password, BooleanSupplier shouldContinue) {
        OpenSearchAuth auth = username == null || username.isBlank() || password == null || password.isBlank()
                ? OpenSearchAuth.none()
                : OpenSearchAuth.basic(username, password);
        return createSelectedIndexes(baseUrl, selectedSources, auth, shouldContinue);
    }

    /**
     * Creates all selected indices with explicit authentication and cancellation.
     *
     * <p>Serverless deployments may inventory existing names once before per-index validation.
     * Inventory failure falls back to individual existence checks and is logged.</p>
     *
     * @param baseUrl search destination base URL
     * @param selectedSources configured source keys
     * @param auth authentication strategy
     * @param shouldContinue continuation signal; {@code null} means continue
     * @return ordered results completed before success, failure, or cancellation
     */
    public static List<IndexResult> createSelectedIndexes(String baseUrl, List<String> selectedSources,
            OpenSearchAuth auth, BooleanSupplier shouldContinue) {
        String databaseName = RuntimeConfig.searchDestinationDisplayName();
        Logger.logDebug("[" + databaseName + "] createSelectedIndexes sources=" + selectedSources);

        LinkedHashSet<String> shortNames = new LinkedHashSet<>(IndexNaming.computeSelectedIndexKeys(selectedSources));
        boolean mayContinue = shouldContinue == null || shouldContinue.getAsBoolean();
        Set<String> existingIndexNames = mayContinue && !shortNames.isEmpty()
                ? existingServerlessIndexNames(baseUrl, auth, databaseName)
                : null;

        List<IndexResult> results = new ArrayList<>();
        for (String shortName : shortNames) {
            if (shouldContinue != null && !shouldContinue.getAsBoolean()) {
                break;
            }
            String displayName = IndexNaming.displayNameForIndexKey(shortName);
            String fullIndexName = RuntimeConfig.indexNameForKey(shortName);
            Logger.logInfoPanelOnly("[" + databaseName + "] Creating index for " + displayName + ".");
            IndexResult result = createIndexFromResource(
                    baseUrl,
                    shortName,
                    fullIndexName,
                    null,
                    auth,
                    existingIndexNames == null ? null : existingIndexNames.contains(fullIndexName));
            Logger.logInfoPanelOnly("[" + databaseName + "] Index result for " + displayName + ": " + result.status() + ".");
            results.add(result);
        }
        return results;
    }

    private static Set<String> existingServerlessIndexNames(
            String baseUrl,
            OpenSearchAuth auth,
            String databaseName) {
        if (!usesServerlessIndexListing(
                RuntimeConfig.searchDestinationKind(),
                RuntimeConfig.searchDeploymentType(),
                baseUrl)) {
            return null;
        }
        try {
            Set<String> names = listExistingIndexNames(baseUrl, auth);
            Logger.logDebug("[" + databaseName + "] Serverless index inventory returned "
                    + names.size() + " existing index(es).");
            return names;
        } catch (IOException | RuntimeException e) {
            Logger.logWarnPanelOnly("[" + databaseName + "] Serverless index inventory failed; "
                    + "falling back to per-index existence checks: " + conciseRootCause(e));
            return null;
        }
    }

    static boolean usesServerlessIndexListing(
            ConfigState.SearchDestination destination,
            String deploymentType,
            String baseUrl) {
        if (destination != ConfigState.SearchDestination.OPEN_SEARCH_AMAZON) {
            return false;
        }
        String resolved = ConfigState.normalizeDeploymentType(deploymentType);
        if (ConfigState.DEPLOYMENT_AUTO.equals(resolved)) {
            resolved = SearchDeployment.detectAmazonOpenSearchDeploymentType(baseUrl);
        }
        return ConfigState.DEPLOYMENT_SERVERLESS.equals(resolved);
    }

    /** Serializes mapping JSON to a single line so error logs do not clutter. */
    private static String compactJson(String json) {
        if (json == null || json.isBlank()) return json;
        try (JsonReader reader = Json.createReader(new StringReader(json));
             StringWriter sw = new StringWriter();
             JsonWriter writer = Json.createWriter(sw)) {
            writer.write(reader.read());
            return sw.toString();
        } catch (Exception e) {
            return json;
        }
    }

    /** Compact root-cause message, capped for UI status. */
    private static String conciseRootCause(Throwable t) {
        Throwable c = t;
        while (c.getCause() != null) c = c.getCause();
        String msg = c.getMessage();
        if (msg == null || msg.isBlank()) msg = c.getClass().getSimpleName();
        return conciseDetail(msg);
    }

    private static String conciseDetail(String detail) {
        String msg = detail == null || detail.isBlank() ? "unknown error" : detail;
        msg = msg.replaceAll("[\\r\\n]+", " ").trim();
        if (msg.length() > 300) {
            msg = msg.substring(0, 300);
        }
        return msg;
    }

    /**
     * Result of an index creation attempt.
     *
     * @param shortName logical name used to select the mapping file
     * @param fullName  fully-qualified index name
     * @param status    CREATED, EXISTS, or FAILED
     * @param error     concise reason when {@code status == FAILED}; otherwise {@code null}
     */
    public record IndexResult(String shortName, String fullName, Status status, String error) {
        /** Outcome category for one index creation or compatibility check. */
        public enum Status {
            /** The destination index was created. */
            CREATED,
            /** The destination index already existed and was accepted as compatible. */
            EXISTS,
            /** Creation or compatibility validation failed. */
            FAILED
        }
    }

    private static String resolvedFullIndexName(String shortName) {
        String normalized = shortName == null ? "" : shortName.trim().toLowerCase(java.util.Locale.ROOT);
        if (IndexNaming.indexKeys().contains(normalized)) {
            return RuntimeConfig.indexNameForKey(normalized);
        }
        return IndexNaming.normalizeBaseTemplate(RuntimeConfig.getState().indexNameBaseTemplate()) + "-" + normalized;
    }

}
