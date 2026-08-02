package ai.anomalousvectors.tools.burp.ui;

import java.util.Optional;

import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.SecureCredentialStore;

/**
 * Operator advisories for short-lived pasted credentials that the exporter does not renew.
 *
 * <p>Covers Amazon Static IAM session tokens and OpenSearch/Elasticsearch bearer tokens. Advisories
 * are non-blocking guidance for long export runs; they do not abort Start.</p>
 */
public final class TemporaryCredentialAdvisory {

    /** Inline UI warning when an Amazon Static session token is present. */
    public static final String SESSION_TOKEN_UI_WARNING = """
            Elevated risk: AWS session tokens expire and are not renewed.
            For long runs prefer IAM Profile, or Static keys with Session Token blank.""";

    /** Inline UI warning when a bearer token is present. */
    public static final String BEARER_UI_WARNING = """
            Elevated risk: bearer tokens often expire and are not renewed.
            For long runs prefer API key (when available) or Basic.""";

    private TemporaryCredentialAdvisory() {
        throw new AssertionError("No instances");
    }

    /**
     * Kind of temporary credential that triggered an advisory.
     */
    public enum Kind {
        /** Amazon Static IAM session token. */
        AWS_SESSION_TOKEN,
        /** OpenSearch or Elasticsearch bearer token. */
        BEARER_TOKEN
    }

    /**
     * Active advisory text for UI and log surfaces.
     *
     * @param kind credential kind
     * @param uiText short inline UI warning
     * @param logMessage single-line WARN text for Log panel / control status
     */
    public record Active(Kind kind, String uiText, String logMessage) {
    }

    /**
     * Returns an advisory when Amazon Static auth currently has a non-blank session token in the UI.
     *
     * @param authType selected Amazon auth type
     * @param sessionToken session token field text; {@code null} treated as empty
     * @return advisory when applicable
     */
    public static Optional<Active> forAmazonSessionToken(String authType, String sessionToken) {
        if (!ConfigState.OPEN_SEARCH_AMAZON_AUTH_STATIC.equals(authType)) {
            return Optional.empty();
        }
        if (sessionToken == null || sessionToken.isBlank()) {
            return Optional.empty();
        }
        return Optional.of(new Active(
                Kind.AWS_SESSION_TOKEN,
                SESSION_TOKEN_UI_WARNING,
                "[Amazon OpenSearch] Elevated auth-failure risk: AWS session token is set and will not be "
                        + "renewed. Prefer IAM Profile, or Static long-term keys with Session Token blank."));
    }

    /**
     * Returns an advisory when Bearer token auth is selected.
     *
     * <p>The UI warning appears as soon as auth type is {@code Bearer token}, even when the token
     * field is still empty, so operators see the risk before pasting a credential. The token field
     * value is unused for this check.</p>
     *
     * @param destinationDisplayName operator-facing destination name
     * @param authType selected auth type
     * @param bearerToken unused; retained for call-site compatibility
     * @return advisory when Bearer auth is selected
     */
    public static Optional<Active> forBearerToken(
            String destinationDisplayName,
            String authType,
            String bearerToken) {
        if (!"Bearer token".equals(authType)) {
            return Optional.empty();
        }
        String destination = destinationDisplayName == null || destinationDisplayName.isBlank()
                ? "Database"
                : destinationDisplayName;
        return Optional.of(new Active(
                Kind.BEARER_TOKEN,
                BEARER_UI_WARNING,
                "[" + destination + "] Elevated auth-failure risk: Bearer token auth is selected and "
                        + "tokens are not renewed. Prefer API key (when available) or Basic for long runs."));
    }

    /**
     * Returns the advisory for the currently selected database destination from runtime state.
     *
     * <p>Reads auth type from {@link RuntimeConfig} and secrets from {@link SecureCredentialStore}.
     * Call after UI secrets have been synced into the store.</p>
     *
     * @return advisory when the active destination uses a temporary pasted credential
     */
    public static Optional<Active> forRuntimeSelection() {
        ConfigState.State state = RuntimeConfig.getState();
        if (state == null || state.sinks() == null || !state.sinks().databaseEnabled()) {
            return Optional.empty();
        }
        ConfigState.SearchDestination destination = state.sinks().searchDestinationKind();
        return switch (destination) {
            case OPEN_SEARCH_AMAZON -> forAmazonSessionToken(
                    state.sinks().openSearchAmazonOptions().authType(),
                    SecureCredentialStore.loadAwsStaticCredentials(destination.configKey()).sessionToken());
            case OPEN_SEARCH -> forBearerToken(
                    destination.displayName(),
                    state.sinks().openSearchOptions().authType(),
                    SecureCredentialStore.loadJwtCredentials(destination.configKey()).token());
            case ELASTICSEARCH -> forBearerToken(
                    destination.displayName(),
                    state.sinks().elasticSearchOptions().authType(),
                    SecureCredentialStore.loadJwtCredentials(destination.configKey()).token());
        };
    }
}
