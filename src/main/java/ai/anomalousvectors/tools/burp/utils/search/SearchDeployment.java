package ai.anomalousvectors.tools.burp.utils.search;

import java.net.URI;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

import ai.anomalousvectors.tools.burp.utils.config.ConfigState;

/**
 * Detects hosted/serverless/self-hosted deployment hints from search endpoint hostnames.
 *
 * <p>Stateless and thread-safe. Endpoint detection is conservative: null, blank, malformed, or
 * unrecognized URLs return the destination's unresolved value rather than throwing.</p>
 */
public final class SearchDeployment {

    private static final List<String> AMAZON_HOSTED_AUTH_TYPES = List.of(
            ConfigState.OPEN_SEARCH_AMAZON_AUTH_PROFILE,
            ConfigState.OPEN_SEARCH_AMAZON_AUTH_STATIC,
            "Basic",
            "None");
    private static final List<String> AMAZON_SERVERLESS_AUTH_TYPES = List.of(
            ConfigState.OPEN_SEARCH_AMAZON_AUTH_PROFILE,
            ConfigState.OPEN_SEARCH_AMAZON_AUTH_STATIC);
    private static final List<String> ELASTICSEARCH_STANDARD_AUTH_TYPES = List.of(
            "API key", "Bearer token", "Certificate", "Basic", "None");
    private static final List<String> ELASTICSEARCH_SERVERLESS_AUTH_TYPES = List.of(
            "API key", "Bearer token");

    private SearchDeployment() {
        throw new AssertionError("No instances");
    }

    /**
     * Returns the detected Amazon OpenSearch deployment type.
     *
     * @param baseUrl endpoint URL; null, blank, or malformed input is unresolved
     * @return {@code hosted}, {@code serverless}, or {@code auto} when unresolved
     */
    public static String detectAmazonOpenSearchDeploymentType(String baseUrl) {
        String host = host(baseUrl);
        if (host.isBlank()) {
            return ConfigState.DEPLOYMENT_AUTO;
        }
        if (host.contains(".aoss.")) {
            return ConfigState.DEPLOYMENT_SERVERLESS;
        }
        if (host.contains(".es.")) {
            return ConfigState.DEPLOYMENT_HOSTED;
        }
        return ConfigState.DEPLOYMENT_AUTO;
    }

    /**
     * Returns the AWS region embedded in a known Amazon OpenSearch hostname, or blank when unknown.
     *
     * <p>Hosted domains use {@code search-&lt;domain&gt;-&lt;id&gt;.&lt;region&gt;.es.amazonaws.com}.
     * Serverless collections use {@code &lt;id&gt;.&lt;region&gt;.aoss.amazonaws.com}.</p>
     *
     * @param baseUrl endpoint URL; null, blank, malformed, or unknown input returns empty
     * @return lowercase AWS region, or empty when unavailable
     */
    public static String detectAmazonOpenSearchRegion(String baseUrl) {
        String host = host(baseUrl);
        if (host.isBlank()) {
            return "";
        }
        String marker = null;
        if (host.contains(".aoss.amazonaws.com")) {
            marker = ".aoss.amazonaws.com";
        } else if (host.contains(".es.amazonaws.com")) {
            marker = ".es.amazonaws.com";
        }
        if (marker == null) {
            return "";
        }
        String prefix = host.substring(0, host.length() - marker.length());
        int lastDot = prefix.lastIndexOf('.');
        if (lastDot < 0 || lastDot == prefix.length() - 1) {
            return "";
        }
        String region = prefix.substring(lastDot + 1).trim();
        return region.matches("[a-z0-9-]+") ? region : "";
    }

    /**
     * Returns the CloudWatch {@code DomainName} for a hosted Amazon OpenSearch endpoint, or blank.
     *
     * <p>Hosted public endpoints look like
     * {@code search-&lt;domain&gt;-&lt;uniqueId&gt;.&lt;region&gt;.es.amazonaws.com}. Serverless
     * collection hosts do not use this dimension and return blank.</p>
     *
     * @param baseUrl Amazon OpenSearch URL; null, blank, malformed, or non-hosted input returns
     *                empty
     * @return domain name suitable for CloudWatch {@code AWS/ES} {@code DomainName}, or blank
     */
    public static String detectAmazonOpenSearchDomainName(String baseUrl) {
        String host = host(baseUrl);
        String region = detectAmazonOpenSearchRegion(baseUrl);
        if (host.isBlank() || region.isBlank() || !host.contains(".es.amazonaws.com")) {
            return "";
        }
        if (!host.startsWith("search-")) {
            return "";
        }
        String withoutSearch = host.substring("search-".length());
        String regionMarker = "." + region + ".";
        int regionAt = withoutSearch.indexOf(regionMarker);
        if (regionAt <= 0) {
            return "";
        }
        String nameAndId = withoutSearch.substring(0, regionAt);
        int lastDash = nameAndId.lastIndexOf('-');
        if (lastDash <= 0) {
            return "";
        }
        return nameAndId.substring(0, lastDash);
    }

    /**
     * Returns the AWS SigV4 signing service for a resolved Amazon deployment type.
     *
     * @param deploymentType deployment type; null or unknown values normalize to hosted semantics
     * @return {@code aoss} for serverless, otherwise {@code es}
     */
    public static String amazonSigningService(String deploymentType) {
        return ConfigState.DEPLOYMENT_SERVERLESS.equals(ConfigState.normalizeDeploymentType(deploymentType))
                ? "aoss"
                : "es";
    }

    /**
     * Returns the default shared AWS credentials file path for the current user.
     *
     * <p>On Windows this is typically {@code C:\Users\<user>\.aws\credentials}.</p>
     *
     * @return platform path under the {@code user.home} system property
     * @throws NullPointerException if {@code user.home} is unavailable
     * @throws java.nio.file.InvalidPathException if the home value is not a valid platform path
     * @throws SecurityException if access to {@code user.home} is denied
     */
    public static String defaultAwsCredentialsFilePath() {
        return Path.of(System.getProperty("user.home"), ".aws", "credentials").toString();
    }

    /**
     * Returns the default shared AWS config file path for the current user.
     *
     * <p>On Windows this is typically {@code C:\Users\<user>\.aws\config}.</p>
     *
     * @return platform path under the {@code user.home} system property
     * @throws NullPointerException if {@code user.home} is unavailable
     * @throws java.nio.file.InvalidPathException if the home value is not a valid platform path
     * @throws SecurityException if access to {@code user.home} is denied
     */
    public static String defaultAwsConfigFilePath() {
        return Path.of(System.getProperty("user.home"), ".aws", "config").toString();
    }

    /**
     * Returns the detected Elasticsearch deployment type.
     *
     * @param baseUrl endpoint URL; null, blank, or malformed input is unresolved
     * @return hosted, serverless, self-hosted, or {@code auto} when unresolved
     */
    public static String detectElasticsearchDeploymentType(String baseUrl) {
        String host = host(baseUrl);
        if (host.isBlank()) {
            return ConfigState.DEPLOYMENT_AUTO;
        }
        if (host.contains(".elastic-cloud.com") || host.contains(".found.io")) {
            return ConfigState.DEPLOYMENT_HOSTED;
        }
        if (host.contains(".aws.elastic.cloud")) {
            return ConfigState.DEPLOYMENT_SERVERLESS;
        }
        if (host.equals("localhost")
                || host.equals("127.0.0.1")
                || host.startsWith("10.")
                || host.startsWith("192.168.")
                || host.matches("172\\.(1[6-9]|2\\d|3[0-1])\\..*")) {
            return ConfigState.DEPLOYMENT_SELF_HOSTED;
        }
        return ConfigState.DEPLOYMENT_AUTO;
    }

    /**
     * Returns Amazon OpenSearch auth types that apply for the given endpoint and deployment.
     *
     * <p>Serverless collections only support IAM SigV4 (Profile / Static). Hosted and unresolved
     * endpoints also offer Basic and None. Prefer {@code resolvedDeploymentType} when the UI has
     * an explicit Hosted/Serverless selection; otherwise detection uses {@code baseUrl}.</p>
     *
     * @param baseUrl Amazon OpenSearch URL
     * @param resolvedDeploymentType {@link ConfigState#DEPLOYMENT_HOSTED},
     *        {@link ConfigState#DEPLOYMENT_SERVERLESS}, or {@link ConfigState#DEPLOYMENT_AUTO}
     * @return immutable auth-type labels for the combo model; unresolved input uses the hosted set
     */
    public static List<String> amazonOpenSearchAuthTypesForUrl(String baseUrl, String resolvedDeploymentType) {
        String deployment = ConfigState.normalizeDeploymentType(resolvedDeploymentType);
        if (ConfigState.DEPLOYMENT_AUTO.equals(deployment)) {
            deployment = detectAmazonOpenSearchDeploymentType(baseUrl);
        }
        if (ConfigState.DEPLOYMENT_SERVERLESS.equals(deployment)) {
            return AMAZON_SERVERLESS_AUTH_TYPES;
        }
        return AMAZON_HOSTED_AUTH_TYPES;
    }

    /**
     * Returns Elasticsearch auth types that apply for the given endpoint.
     *
     * <p>Elastic Cloud Serverless projects expose API-key / bearer workflows; Certificate, Basic,
     * and None are omitted there. Other endpoints keep the full set.</p>
     *
     * @param baseUrl Elasticsearch URL; null, blank, malformed, or unknown input uses the standard
     *                set
     * @return immutable applicable auth-type labels
     */
    public static List<String> elasticsearchAuthTypesForUrl(String baseUrl) {
        if (ConfigState.DEPLOYMENT_SERVERLESS.equals(detectElasticsearchDeploymentType(baseUrl))) {
            return ELASTICSEARCH_SERVERLESS_AUTH_TYPES;
        }
        return ELASTICSEARCH_STANDARD_AUTH_TYPES;
    }

    private static String host(String baseUrl) {
        if (baseUrl == null || baseUrl.isBlank()) {
            return "";
        }
        try {
            URI uri = URI.create(baseUrl.trim());
            String host = uri.getHost();
            return host == null ? "" : host.toLowerCase(Locale.ROOT);
        } catch (RuntimeException e) {
            return "";
        }
    }
}
