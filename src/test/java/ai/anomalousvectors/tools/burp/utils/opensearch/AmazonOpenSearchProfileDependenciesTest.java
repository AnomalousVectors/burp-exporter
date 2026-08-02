package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThatCode;

import org.junit.jupiter.api.Test;

class AmazonOpenSearchProfileDependenciesTest {

    @Test
    void profileCredentialFactoriesAndSsoOidcClientAreAvailable() {
        assertThatCode(() -> Class.forName(
                        "software.amazon.awssdk.services.sts.internal.StsProfileCredentialsProviderFactory")
                .getConstructor()
                .newInstance())
                .doesNotThrowAnyException();
        assertThatCode(() -> Class.forName(
                        "software.amazon.awssdk.services.sso.auth.SsoProfileCredentialsProviderFactory")
                .getConstructor()
                .newInstance())
                .doesNotThrowAnyException();
        assertThatCode(() -> Class.forName(
                "software.amazon.awssdk.services.ssooidc.SsoOidcClient"))
                .doesNotThrowAnyException();
    }
}
