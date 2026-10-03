package ai.anomalousvectors.tools.burp.utils.search;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import ai.anomalousvectors.tools.burp.utils.config.ConfigState;

class SearchConnectionTesterEndpointTest {

    @ParameterizedTest
    @EnumSource(ConfigState.SearchDestination.class)
    void safeTestConnection_rejectsNonRootEndpointsBeforeDestinationSpecificWork(
            ConfigState.SearchDestination destination) {
        SearchConnectionStatus status = SearchConnectionTester.safeTestConnection(
                destination, "https://example.com/reverse-proxy");

        assertThat(status.success()).isFalse();
        assertThat(status.productName()).isEqualTo(destination.displayName());
        assertThat(status.message()).isEqualTo("Base URL must identify the database root without a path.");
        assertThat(status.authenticationStatus()).isEqualTo("Not tested");
        assertThat(status.trustStatus()).isEqualTo("Not tested");
    }
}
