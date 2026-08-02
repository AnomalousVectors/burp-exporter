package ai.anomalousvectors.tools.burp.utils.search;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.config.ConfigState;

class SearchDeploymentTest {

    @Test
    void detectAmazonOpenSearchDeploymentType_distinguishesHostedAndServerless() {
        assertThat(SearchDeployment.detectAmazonOpenSearchDeploymentType(
                "https://search-example.us-east-1.es.amazonaws.com"))
                .isEqualTo(ConfigState.DEPLOYMENT_HOSTED);
        assertThat(SearchDeployment.detectAmazonOpenSearchDeploymentType(
                "https://00000000000000abc123.us-east-1.aoss.amazonaws.com"))
                .isEqualTo(ConfigState.DEPLOYMENT_SERVERLESS);
        assertThat(SearchDeployment.detectAmazonOpenSearchDeploymentType("https://opensearch.example.internal"))
                .isEqualTo(ConfigState.DEPLOYMENT_AUTO);
    }

    @Test
    void detectAmazonOpenSearchRegion_readsRegionFromHostedAndServerlessHosts() {
        assertThat(SearchDeployment.detectAmazonOpenSearchRegion(
                "https://search-burp-exporter-hosted-test-5hqzhar4lworl3rku2oyrp2pau.us-east-1.es.amazonaws.com"))
                .isEqualTo("us-east-1");
        assertThat(SearchDeployment.detectAmazonOpenSearchRegion(
                "https://00000000000000abc123.us-west-2.aoss.amazonaws.com"))
                .isEqualTo("us-west-2");
        assertThat(SearchDeployment.detectAmazonOpenSearchRegion("https://opensearch.example.internal"))
                .isBlank();
    }

    @Test
    void detectAmazonOpenSearchDomainName_stripsSearchPrefixAndUniqueId() {
        assertThat(SearchDeployment.detectAmazonOpenSearchDomainName(
                "https://search-burp-exporter-hosted-test-5hqzhar4lworl3rku2oyrp2pau.us-east-1.es.amazonaws.com"))
                .isEqualTo("burp-exporter-hosted-test");
        assertThat(SearchDeployment.detectAmazonOpenSearchDomainName(
                "https://00000000000000abc123.us-east-1.aoss.amazonaws.com"))
                .isBlank();
    }

    @Test
    void amazonSigningService_mapsDeploymentTypeToAwsServiceName() {
        assertThat(SearchDeployment.amazonSigningService(ConfigState.DEPLOYMENT_HOSTED)).isEqualTo("es");
        assertThat(SearchDeployment.amazonSigningService(ConfigState.DEPLOYMENT_SERVERLESS)).isEqualTo("aoss");
    }

    @Test
    void defaultAwsSharedFilePaths_useUserHomeDotAws() {
        assertThat(SearchDeployment.defaultAwsCredentialsFilePath())
                .endsWith(".aws" + java.io.File.separator + "credentials");
        assertThat(SearchDeployment.defaultAwsConfigFilePath())
                .endsWith(".aws" + java.io.File.separator + "config");
    }

    @Test
    void amazonOpenSearchAuthTypesForUrl_hidesBasicForServerless() {
        assertThat(SearchDeployment.amazonOpenSearchAuthTypesForUrl(
                "https://00000000000000abc123.us-east-1.aoss.amazonaws.com",
                ConfigState.DEPLOYMENT_AUTO))
                .containsExactly(
                        ConfigState.OPEN_SEARCH_AMAZON_AUTH_PROFILE,
                        ConfigState.OPEN_SEARCH_AMAZON_AUTH_STATIC)
                .doesNotContain("Basic");
        assertThat(SearchDeployment.amazonOpenSearchAuthTypesForUrl(
                "https://search-example.us-east-1.es.amazonaws.com",
                ConfigState.DEPLOYMENT_AUTO))
                .contains("Basic", "None");
        assertThat(SearchDeployment.amazonOpenSearchAuthTypesForUrl(
                "https://vpc-opensearch.example.internal",
                ConfigState.DEPLOYMENT_SERVERLESS))
                .containsExactly(
                        ConfigState.OPEN_SEARCH_AMAZON_AUTH_PROFILE,
                        ConfigState.OPEN_SEARCH_AMAZON_AUTH_STATIC);
    }

    @Test
    void elasticsearchAuthTypesForUrl_hidesCertificateAndBasicForServerless() {
        assertThat(SearchDeployment.elasticsearchAuthTypesForUrl(
                "https://my-serverless-elasticsearch-project.es.us-east-1.aws.elastic.cloud"))
                .containsExactly("API key", "Bearer token");
        assertThat(SearchDeployment.elasticsearchAuthTypesForUrl("http://localhost:9201"))
                .contains("Certificate", "Basic", "None");
    }

    @Test
    void detectElasticsearchDeploymentType_isInformationalForKnownEndpointStyles() {
        assertThat(SearchDeployment.detectElasticsearchDeploymentType(
                "https://00000000000000000000000000abc123.us-east4.gcp.elastic-cloud.com"))
                .isEqualTo(ConfigState.DEPLOYMENT_HOSTED);
        assertThat(SearchDeployment.detectElasticsearchDeploymentType(
                "https://my-serverless-elasticsearch-project.es.us-east-1.aws.elastic.cloud"))
                .isEqualTo(ConfigState.DEPLOYMENT_SERVERLESS);
        assertThat(SearchDeployment.detectElasticsearchDeploymentType("http://localhost:9201"))
                .isEqualTo(ConfigState.DEPLOYMENT_SELF_HOSTED);
    }

}
