package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;

/** Verifies root ownership, deferred invocation, and fail-closed cleanup configuration. */
class OpenSearchCleanupExtensionTest {

    @Test
    void multipleClassContexts_registerOneDeferredRootResource() throws Exception {
        var calls = new AtomicInteger();
        var root = mock(ExtensionContext.class);
        var store = mock(ExtensionContext.Store.class);
        when(root.getStore(any())).thenReturn(store);
        Map<Object, AutoCloseable> owners = new HashMap<>();
        doAnswer(invocation -> {
            Object key = invocation.getArgument(0);
            Function<Object, AutoCloseable> factory = invocation.getArgument(1);
            return owners.computeIfAbsent(key, factory);
        }).when(store).computeIfAbsent(any(), any(), any());
        var extension = new OpenSearchCleanupExtension(calls::incrementAndGet);
        for (int i = 0; i < 3; i++) {
            var child = mock(ExtensionContext.class);
            when(child.getRoot()).thenReturn(root);
            extension.beforeAll(child);
        }
        assertThat(owners).hasSize(1);
        assertThat(calls).hasValue(0);
        owners.values().iterator().next().close();
        assertThat(calls).hasValue(1);
    }

    @Test
    void explicitlyDisabledAutomaticClosure_failsBeforeRegistration() {
        var context = mock(ExtensionContext.class);
        when(context.getConfigurationParameter(
                eq("junit.jupiter.extensions.store.close.autocloseable.enabled"), any()))
                .thenReturn(Optional.of(false));
        var calls = new AtomicInteger();
        assertThatThrownBy(() -> new OpenSearchCleanupExtension(calls::incrementAndGet).beforeAll(context))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("automatic root-store closure");
        assertThat(calls).hasValue(0);
    }

    @Test
    void registration_usesRootStoreInsteadOfClassStore() {
        var context = mock(ExtensionContext.class);
        var root = mock(ExtensionContext.class);
        var rootStore = mock(ExtensionContext.Store.class);
        var childStore = mock(ExtensionContext.Store.class);
        when(context.getRoot()).thenReturn(root);
        when(context.getStore(any())).thenReturn(childStore);
        when(root.getStore(any())).thenReturn(rootStore);
        new OpenSearchCleanupExtension(() -> {}).beforeAll(context);
        verifyNoInteractions(childStore);
    }
}
