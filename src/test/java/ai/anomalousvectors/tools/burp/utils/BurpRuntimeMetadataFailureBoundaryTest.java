package ai.anomalousvectors.tools.burp.utils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import burp.api.montoya.MontoyaApi;

class BurpRuntimeMetadataFailureBoundaryTest {

    @AfterEach
    void clearMetadata() {
        BurpRuntimeMetadata.clear();
    }

    @Test
    void prime_fallsBackForRuntimeLifecycleFailures() {
        MontoyaApi api = mock(MontoyaApi.class);
        when(api.burpSuite()).thenThrow(new IllegalStateException("startup transition"));
        when(api.project()).thenThrow(new IllegalStateException("startup transition"));

        assertThatCode(() -> BurpRuntimeMetadata.prime(api)).doesNotThrowAnyException();
        assertThat(BurpRuntimeMetadata.burpVersion()).isNull();
        assertThat(BurpRuntimeMetadata.projectId()).isNull();
    }

    @Test
    void prime_doesNotSwallowErrors() {
        MontoyaApi api = mock(MontoyaApi.class);
        AssertionError failure = new AssertionError("fatal host failure");
        when(api.burpSuite()).thenThrow(failure);

        assertThatThrownBy(() -> BurpRuntimeMetadata.prime(api)).isSameAs(failure);
    }
}
