package ai.anomalousvectors.tools.burp.utils.search;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchAuth;

class SearchConnectionTesterAmazonTest {

    @Test
    void amazonProbePath_usesCatIndicesForServerlessAndRootForHosted() {
        assertThat(SearchConnectionTester.amazonProbePath(ConfigState.DEPLOYMENT_SERVERLESS))
                .isEqualTo("/_cat/indices");
        assertThat(SearchConnectionTester.amazonProbePath(ConfigState.DEPLOYMENT_HOSTED))
                .isEqualTo("/");
        assertThat(SearchConnectionTester.amazonProbePath(ConfigState.DEPLOYMENT_AUTO))
                .isEqualTo("/");
    }

    @Test
    void resolvedAmazonDeployment_prefersExplicitSelectionThenHostDetection() {
        ConfigState.OpenSearchAmazonOptions auto = amazonOptions(ConfigState.DEPLOYMENT_AUTO);
        assertThat(SearchConnectionTester.resolvedAmazonDeployment(
                "https://abc123.us-east-1.aoss.amazonaws.com", auto))
                .isEqualTo(ConfigState.DEPLOYMENT_SERVERLESS);
        assertThat(SearchConnectionTester.resolvedAmazonDeployment(
                "https://search-example.us-east-1.es.amazonaws.com", auto))
                .isEqualTo(ConfigState.DEPLOYMENT_HOSTED);

        ConfigState.OpenSearchAmazonOptions forcedHosted = amazonOptions(ConfigState.DEPLOYMENT_HOSTED);
        assertThat(SearchConnectionTester.resolvedAmazonDeployment(
                "https://abc123.us-east-1.aoss.amazonaws.com", forcedHosted))
                .isEqualTo(ConfigState.DEPLOYMENT_HOSTED);
    }

    @Test
    void amazonAuthStatus_doesNotReportNotUsedWhenSigV4WasAttempted() {
        OpenSearchAuth none = OpenSearchAuth.none();
        assertThat(SearchConnectionTester.amazonAuthStatus(none, true, 404, false))
                .isEqualTo("Attempted");
        assertThat(SearchConnectionTester.amazonAuthStatus(none, true, 403, false))
                .isEqualTo("Failed");
        assertThat(SearchConnectionTester.amazonAuthStatus(none, true, 200, true))
                .isEqualTo("Successful");
        assertThat(SearchConnectionTester.amazonAuthStatus(none, false, 404, false))
                .isEqualTo("Not used");
        assertThat(SearchConnectionTester.amazonAuthStatus(OpenSearchAuth.basic("u", "p"), false, 401, false))
                .isEqualTo("Failed");
    }

    @Test
    void clusterUuidFromBody_readsStableRootIdentity() {
        assertThat(SearchConnectionTester.clusterUuidFromBody(
                "{\"cluster_uuid\":\"cluster-a\",\"version\":{\"number\":\"3.5.0\"}}"))
                .isEqualTo("cluster-a");
        assertThat(SearchConnectionTester.clusterUuidFromBody("{\"version\":{}}"))
                .isEmpty();
        assertThat(SearchConnectionTester.clusterUuidFromBody("not-json"))
                .isEmpty();
    }

    private static ConfigState.OpenSearchAmazonOptions amazonOptions(String deploymentType) {
        return new ConfigState.OpenSearchAmazonOptions(
                ConfigState.OPEN_SEARCH_AMAZON_AUTH_PROFILE,
                "",
                "us-east-1",
                "burp-test",
                "",
                "",
                deploymentType,
                ConfigState.OPEN_SEARCH_TLS_VERIFY,
                "",
                "",
                "");
    }
}
