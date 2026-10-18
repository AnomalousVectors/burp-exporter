package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;

import java.util.List;
import java.util.ServiceLoader;

import org.junit.jupiter.api.Test;
import org.junit.platform.engine.TestEngine;
import org.junit.platform.engine.TestTag;
import org.junit.platform.engine.support.descriptor.MethodSource;
import org.junit.platform.launcher.TagFilter;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;

/** Proves single-pass integration discovery and tag exclusion without executing cluster tests. */
class OpenSearchTestDiscoveryTest {

    private static final List<Class<?>> CLASSES = List.of(
            OpenSearchSinkIT.class, OpenSearchSinkFreshCreateIT.class, OpenSearchSinkConcurrencyIT.class,
            OpenSearchSinkMappingsIT.class, OpenSearchSinkSubsetIT.class, OpenSearchSinkExporterOnlyIT.class,
            OpenSearchCleanupIT.class);

    @Test
    void sinkTests_areDiscoveredOnceAndCarryIntegrationTag() {
        TestPlan plan = discover(false);
        List<TestIdentifier> tests = tests(plan);
        assertThat(tests).hasSize(8).allSatisfy(test -> {
            assertThat(test.getTags()).contains(TestTag.create("integration"));
            assertThat(test.getSource()).hasValueSatisfying(source -> assertThat(source).isInstanceOf(MethodSource.class));
        });
        assertThat(tests.stream().map(test -> test.getSource().orElseThrow()).toList()).doesNotHaveDuplicates();
    }

    @Test
    void integrationExclusion_removesEverySelectedSinkTestWithoutExecution() {
        assertThat(tests(discover(true))).isEmpty();
    }

    @Test
    void runtime_usesOnlyJupiterInsteadOfDuplicateSuiteDiscovery() {
        assertThat(ServiceLoader.load(TestEngine.class).stream().map(provider -> provider.get().getId()).toList())
                .containsExactly("junit-jupiter");
    }

    private static TestPlan discover(boolean excludeIntegration) {
        var request = LauncherDiscoveryRequestBuilder.request()
                .selectors(CLASSES.stream().map(type -> selectClass(type)).toList());
        if (excludeIntegration) {
            request.filters(TagFilter.excludeTags("integration"));
        }
        try (var session = LauncherFactory.openSession()) {
            return session.getLauncher().discover(request.build());
        }
    }

    private static List<TestIdentifier> tests(TestPlan plan) {
        return plan.getRoots().stream().flatMap(root -> plan.getDescendants(root).stream())
                .filter(test -> test.isTest()).toList();
    }
}
