package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.io.ByteArrayInputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.hc.core5.http.HttpRequest;

import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.SecureCredentialStore;
import ai.anomalousvectors.tools.burp.utils.search.SearchDeployment;

/**
 * Applies AWS Signature Version 4 headers to Amazon OpenSearch HTTP requests.
 *
 * <p>Uses the AWS SDK via reflection against public interfaces so the IDE classpath and the
 * Burp runtime can load signing without compile-time AWS imports.</p>
 *
 * <p>Each {@link #sign} call resolves credentials from a fresh provider. Profile mode therefore
 * reloads shared-config / SSO / role credentials on the AWS SDK schedule; static access keys and
 * session tokens remain fixed until the operator updates Config.</p>
 *
 * <p>Stateless and safe for concurrent callers. Credential-provider implementations supplied by
 * the AWS SDK retain their own synchronization and refresh behavior.</p>
 */
public final class AmazonOpenSearchSigV4 {

    private AmazonOpenSearchSigV4() {
        throw new AssertionError("No instances");
    }

    /**
     * Returns whether the current runtime selection needs SigV4 request signing.
     *
     * @return {@code true} for Amazon OpenSearch static-IAM or profile authentication
     */
    public static boolean isEnabledForRuntime() {
        ConfigState.State state = RuntimeConfig.getState();
        if (state == null || state.sinks() == null
                || state.sinks().searchDestinationKind() != ConfigState.SearchDestination.OPEN_SEARCH_AMAZON) {
            return false;
        }
        String authType = state.sinks().openSearchAmazonOptions().authType();
        return ConfigState.OPEN_SEARCH_AMAZON_AUTH_STATIC.equals(authType)
                || ConfigState.OPEN_SEARCH_AMAZON_AUTH_PROFILE.equals(authType);
    }

    /**
     * Returns a validation message for current SigV4 settings.
     *
     * <p>Validation may load configured profile files and resolve credentials. Runtime failures are
     * converted to a concise, single-line message and are not thrown.</p>
     *
     * @param baseUrl Amazon OpenSearch endpoint used to infer region and deployment type
     * @return blank when signing can proceed; otherwise a concise validation failure
     */
    public static String validationMessage(String baseUrl) {
        try {
            resolveSigningContext(baseUrl);
            return "";
        } catch (RuntimeException e) {
            return rootMessage(e);
        }
    }

    /**
     * Applies SigV4 headers to a request using the current runtime Amazon settings.
     *
     * <p>The method signs the supplied body bytes exactly and mutates {@code request} by replacing
     * signer-produced headers. It returns without mutation when SigV4 is not enabled. Credential
     * resolution and profile loading may block on the calling transport thread.</p>
     *
     * @param request mutable HTTP request that receives signed headers
     * @param method HTTP method sent on the wire
     * @param baseUrl Amazon OpenSearch endpoint
     * @param path encoded request path and optional query string
     * @param body exact wire payload; {@code null} is treated as an empty body
     * @throws IllegalArgumentException if the endpoint or request target is not a valid URI
     * @throws IllegalStateException if settings, credentials, SDK linkage, or signing fail
     */
    public static void sign(
            HttpRequest request,
            String method,
            String baseUrl,
            String path,
            byte[] body) {
        if (!isEnabledForRuntime()) {
            return;
        }
        SigningContext context = resolveSigningContext(baseUrl);
        byte[] payload = body == null ? new byte[0] : body.clone();
        URI endpoint = URI.create((baseUrl == null ? "" : baseUrl.trim()).replaceAll("/+$", ""));
        try {
            Object unsigned = buildSdkRequest(method, path, endpoint, payload);
            Object signedRequest = signSdkRequest(unsigned, context, payload);
            Object headerMap = invoke(signedRequest, "headers");
            if (headerMap instanceof Map<?, ?> headers) {
                for (Map.Entry<?, ?> header : headers.entrySet()) {
                    if (header.getKey() instanceof String name
                            && header.getValue() instanceof List<?> values
                            && !values.isEmpty()) {
                        request.setHeader(name, joinHeaderValues(values));
                    }
                }
            }
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Failed to sign Amazon OpenSearch request: " + rootMessage(e), e);
        }
    }

    /**
     * Returns the redacted Authorization label used in logs for signed Amazon requests.
     *
     * <p>The result never contains access keys, session tokens, signatures, or credential scope.</p>
     *
     * @return redacted SigV4 scheme label, or blank when SigV4 is disabled
     */
    public static String redactedAuthorizationForLog() {
        return isEnabledForRuntime() ? "AWS4-HMAC-SHA256 ***" : "";
    }

    private static SigningContext resolveSigningContext(String baseUrl) {
        ConfigState.State state = RuntimeConfig.getState();
        ConfigState.OpenSearchAmazonOptions options = state == null || state.sinks() == null
                ? ConfigState.defaultOpenSearchAmazonOptions()
                : state.sinks().openSearchAmazonOptions();
        String region = resolvedRegion(baseUrl, options);
        if (region.isBlank()) {
            throw new IllegalStateException(
                    "AWS region could not be detected from the endpoint. Enter the region to continue.");
        }
        String deploymentType = resolvedDeploymentType(baseUrl, options);
        if (ConfigState.DEPLOYMENT_AUTO.equals(deploymentType)) {
            throw new IllegalStateException(
                    "Deployment type could not be detected from the endpoint. Select Hosted or Serverless to continue.");
        }
        return new SigningContext(
                region,
                SearchDeployment.amazonSigningService(deploymentType),
                credentialsProvider(options));
    }

    private static String resolvedRegion(String baseUrl, ConfigState.OpenSearchAmazonOptions options) {
        if (options.region() != null && !options.region().isBlank()) {
            return options.region().trim();
        }
        return SearchDeployment.detectAmazonOpenSearchRegion(baseUrl);
    }

    private static String resolvedDeploymentType(String baseUrl, ConfigState.OpenSearchAmazonOptions options) {
        String selected = ConfigState.normalizeDeploymentType(options.deploymentType());
        if (!ConfigState.DEPLOYMENT_AUTO.equals(selected)) {
            return selected;
        }
        return SearchDeployment.detectAmazonOpenSearchDeploymentType(baseUrl);
    }

    private static Object credentialsProvider(ConfigState.OpenSearchAmazonOptions options) {
        return switch (options.authType()) {
            case ConfigState.OPEN_SEARCH_AMAZON_AUTH_STATIC -> staticCredentialsProvider();
            case ConfigState.OPEN_SEARCH_AMAZON_AUTH_PROFILE -> profileCredentialsProvider(options);
            default -> throw new IllegalStateException("SigV4 signing requires an IAM auth type.");
        };
    }

    private static Object staticCredentialsProvider() {
        SecureCredentialStore.AwsStaticCredentials stored =
                SecureCredentialStore.loadAwsStaticCredentials(
                        ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey());
        if (stored.accessKeyId().isBlank() || stored.secretAccessKey().isBlank()) {
            throw new IllegalStateException("IAM SigV4 static credentials require access key ID and secret access key.");
        }
        try {
            Object credentials = stored.sessionToken().isBlank()
                    ? Class.forName("software.amazon.awssdk.auth.credentials.AwsBasicCredentials")
                            .getMethod("create", String.class, String.class)
                            .invoke(null, stored.accessKeyId(), stored.secretAccessKey())
                    : Class.forName("software.amazon.awssdk.auth.credentials.AwsSessionCredentials")
                            .getMethod("create", String.class, String.class, String.class)
                            .invoke(null, stored.accessKeyId(), stored.secretAccessKey(), stored.sessionToken());
            return Class.forName("software.amazon.awssdk.auth.credentials.StaticCredentialsProvider")
                    .getMethod("create", Class.forName("software.amazon.awssdk.auth.credentials.AwsCredentials"))
                    .invoke(null, credentials);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Failed to build AWS static credentials provider: " + rootMessage(e), e);
        }
    }

    private static Object profileCredentialsProvider(ConfigState.OpenSearchAmazonOptions options) {
        try {
            Object builder = Class.forName("software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider")
                    .getMethod("builder")
                    .invoke(null);
            Class<?> builderType = Class.forName(
                    "software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider$Builder");
            if (!options.profile().isBlank()) {
                invokeOn(builderType, builder, "profileName", String.class, options.profile());
            }
            Object profileFile = resolveProfileFile(options);
            if (profileFile != null) {
                invokeOn(
                        builderType,
                        builder,
                        "profileFile",
                        Class.forName("software.amazon.awssdk.profiles.ProfileFile"),
                        profileFile);
            }
            return invokeOn(builderType, builder, "build");
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Failed to build AWS profile credentials provider: " + rootMessage(e), e);
        }
    }

    /**
     * Builds a {@code ProfileFile} from configured paths.
     *
     * <p>When both credentials and config paths are set, both files are aggregated so SSO /
     * assume-role profiles in {@code config} still resolve. When neither path is set, returns
     * {@code null} so the SDK uses its default shared files.</p>
     */
    private static Object resolveProfileFile(ConfigState.OpenSearchAmazonOptions options)
            throws ReflectiveOperationException {
        boolean hasCredentials = !options.credentialsFilePath().isBlank();
        boolean hasConfig = !options.configFilePath().isBlank();
        if (!hasCredentials && !hasConfig) {
            return null;
        }
        if (hasCredentials && hasConfig) {
            Object aggregator = Class.forName("software.amazon.awssdk.profiles.ProfileFile")
                    .getMethod("aggregator")
                    .invoke(null);
            Class<?> aggregatorType = Class.forName("software.amazon.awssdk.profiles.ProfileFile$Aggregator");
            Class<?> profileFileType = Class.forName("software.amazon.awssdk.profiles.ProfileFile");
            invokeOn(
                    aggregatorType,
                    aggregator,
                    "addFile",
                    profileFileType,
                    profileFile(options.credentialsFilePath(), "CREDENTIALS"));
            invokeOn(
                    aggregatorType,
                    aggregator,
                    "addFile",
                    profileFileType,
                    profileFile(options.configFilePath(), "CONFIGURATION"));
            return invokeOn(aggregatorType, aggregator, "build");
        }
        if (hasCredentials) {
            return profileFile(options.credentialsFilePath(), "CREDENTIALS");
        }
        return profileFile(options.configFilePath(), "CONFIGURATION");
    }

    static Object buildSdkRequest(String method, String path, URI endpoint, byte[] payload)
            throws ReflectiveOperationException {
        Class<?> requestClass = Class.forName("software.amazon.awssdk.http.SdkHttpFullRequest");
        Class<?> builderType = Class.forName("software.amazon.awssdk.http.SdkHttpFullRequest$Builder");
        Object builder = requestClass.getMethod("builder").invoke(null);
        Object sdkMethod = Class.forName("software.amazon.awssdk.http.SdkHttpMethod")
                .getMethod("fromValue", String.class)
                .invoke(null, method);
        String requestTarget = path == null || path.isBlank() ? "/" : path;
        URI requestUri = endpoint.resolve(requestTarget);
        invokeOn(builderType, builder, "method", Class.forName("software.amazon.awssdk.http.SdkHttpMethod"), sdkMethod);
        // Supplying the complete URI lets the SDK retain the encoded path while extracting raw
        // query parameters for SigV4's separately canonicalized query string.
        invokeOn(builderType, builder, "uri", URI.class, requestUri);
        invokeOn(
                builderType,
                builder,
                "contentStreamProvider",
                Class.forName("software.amazon.awssdk.http.ContentStreamProvider"),
                contentStreamProvider(payload));
        String hostHeader = endpoint.getPort() < 0
                ? endpoint.getHost()
                : endpoint.getHost() + ":" + endpoint.getPort();
        invokeOn(builderType, builder, "putHeader", String.class, String.class, "host", hostHeader);
        return invokeOn(builderType, builder, "build");
    }

    private static Object signSdkRequest(Object unsigned, SigningContext context, byte[] payload)
            throws ReflectiveOperationException {
        Object credentials = invoke(context.provider(), "resolveCredentials");
        if (credentials == null) {
            throw new IllegalStateException("AWS credentials provider returned no credentials.");
        }
        Class<?> signerClass = Class.forName("software.amazon.awssdk.http.auth.aws.signer.AwsV4HttpSigner");
        Object signer = signerClass.getMethod("create").invoke(null);
        Object regionProperty = signerClass.getField("REGION_NAME").get(null);
        Object serviceProperty = Class.forName("software.amazon.awssdk.http.auth.aws.signer.AwsV4FamilyHttpSigner")
                .getField("SERVICE_SIGNING_NAME")
                .get(null);

        Class<?> defaultSignRequest = Class.forName(
                "software.amazon.awssdk.http.auth.spi.internal.signer.DefaultSignRequest");
        Object signRequestBuilder = defaultSignRequest.getMethod("builder").invoke(null);
        Class<?> builderType = Class.forName("software.amazon.awssdk.http.auth.spi.signer.SignRequest$Builder");
        invokeOn(
                builderType,
                signRequestBuilder,
                "identity",
                Class.forName("software.amazon.awssdk.identity.spi.Identity"),
                credentials);
        invokeOn(
                builderType,
                signRequestBuilder,
                "request",
                Class.forName("software.amazon.awssdk.http.SdkHttpRequest"),
                unsigned);
        invokeOn(
                builderType,
                signRequestBuilder,
                "payload",
                Object.class,
                contentStreamProvider(payload));
        Method putProperty = builderType.getMethod(
                "putProperty",
                Class.forName("software.amazon.awssdk.http.auth.spi.signer.SignerProperty"),
                Object.class);
        putProperty.invoke(signRequestBuilder, serviceProperty, context.signingService());
        putProperty.invoke(signRequestBuilder, regionProperty, context.region());
        Object signRequest = invokeOn(builderType, signRequestBuilder, "build");
        Object signed = signerClass
                .getMethod("sign", Class.forName("software.amazon.awssdk.http.auth.spi.signer.SignRequest"))
                .invoke(signer, signRequest);
        return invoke(signed, "request");
    }

    private static Object contentStreamProvider(byte[] payload) throws ReflectiveOperationException {
        Class<?> providerClass = Class.forName("software.amazon.awssdk.http.ContentStreamProvider");
        return Proxy.newProxyInstance(
                providerClass.getClassLoader(),
                new Class<?>[] { providerClass },
                (proxy, method, args) -> {
                    if ("newStream".equals(method.getName())) {
                        return new ByteArrayInputStream(payload);
                    }
                    if ("toString".equals(method.getName())) {
                        return "AmazonOpenSearchSigV4ContentStreamProvider";
                    }
                    if ("hashCode".equals(method.getName())) {
                        return System.identityHashCode(proxy);
                    }
                    if ("equals".equals(method.getName())) {
                        return proxy == args[0];
                    }
                    return null;
                });
    }

    private static Object profileFile(String path, String type) throws ReflectiveOperationException {
        Class<?> profileFileClass = Class.forName("software.amazon.awssdk.profiles.ProfileFile");
        Class<?> builderType = Class.forName("software.amazon.awssdk.profiles.ProfileFile$Builder");
        Object builder = profileFileClass.getMethod("builder").invoke(null);
        invokeOn(builderType, builder, "content", java.nio.file.Path.class, java.nio.file.Path.of(path));
        Class<?> typeClass = Class.forName("software.amazon.awssdk.profiles.ProfileFile$Type");
        Object typeValue = null;
        for (Object candidate : typeClass.getEnumConstants()) {
            if (type.equals(String.valueOf(candidate))) {
                typeValue = candidate;
                break;
            }
        }
        if (typeValue == null) {
            throw new IllegalArgumentException("Unknown AWS profile file type: " + type);
        }
        invokeOn(builderType, builder, "type", typeClass, typeValue);
        return invokeOn(builderType, builder, "build");
    }

    private static Object invoke(Object target, String methodName) throws ReflectiveOperationException {
        return findMethod(target.getClass(), methodName).invoke(target);
    }

    private static Object invokeOn(Class<?> type, Object target, String methodName)
            throws ReflectiveOperationException {
        return findMethod(type, methodName).invoke(target);
    }

    private static Object invokeOn(
            Class<?> type,
            Object target,
            String methodName,
            Class<?> parameterType,
            Object argument) throws ReflectiveOperationException {
        return findMethod(type, methodName, parameterType).invoke(target, argument);
    }

    private static Object invokeOn(
            Class<?> type,
            Object target,
            String methodName,
            Class<?> firstParameterType,
            Class<?> secondParameterType,
            Object firstArgument,
            Object secondArgument) throws ReflectiveOperationException {
        return findMethod(type, methodName, firstParameterType, secondParameterType)
                .invoke(target, firstArgument, secondArgument);
    }

    private static Method findMethod(Class<?> type, String methodName, Class<?>... parameterTypes)
            throws NoSuchMethodException {
        Class<?> current = type;
        while (current != null) {
            try {
                Method method = current.getMethod(methodName, parameterTypes);
                method.setAccessible(true);
                return method;
            } catch (NoSuchMethodException ignored) {
                current = current.getSuperclass();
            }
        }
        for (Class<?> iface : type.getInterfaces()) {
            try {
                Method method = iface.getMethod(methodName, parameterTypes);
                method.setAccessible(true);
                return method;
            } catch (NoSuchMethodException ignored) {
                // keep searching
            }
        }
        throw new NoSuchMethodException(type.getName() + "#" + methodName);
    }

    private static String joinHeaderValues(List<?> values) {
        return values.stream().map(String::valueOf).collect(Collectors.joining(","));
    }

    private static String rootMessage(Throwable t) {
        Throwable c = t;
        if (c instanceof InvocationTargetException invocation && invocation.getCause() != null) {
            c = invocation.getCause();
        }
        while (c.getCause() != null && c.getCause() != c) {
            c = c.getCause();
        }
        String message = c.getMessage();
        if (message == null || message.isBlank() || looksLikeObjectIdentity(message)) {
            String type = c.getClass().getSimpleName();
            return type.isBlank() ? "AWS signing failed" : type;
        }
        return message.replaceAll("[\\r\\n]+", " ").trim();
    }

    private static boolean looksLikeObjectIdentity(String message) {
        // e.g. software.amazon...BuilderImpl@6d06d69c — not useful as an operator detail.
        return message.indexOf('@') > 0 && message.contains(".");
    }

    private record SigningContext(String region, String signingService, Object provider) {
    }
}
