package ai.anomalousvectors.tools.burp.sinks;

import java.util.Objects;

import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * Registers one integration cleanup owner for the complete Jupiter execution root.
 *
 * <p>The root store outlives every selected test class, including aborted or failed classes.
 * Cleanup therefore does not depend on class names, selector order, or a second suite engine.
 * Registration itself performs no network or cleanup work. The fixed exporter test-index prefix
 * and the central helper's best-effort cleanup policy remain unchanged.</p>
 */
public final class OpenSearchCleanupExtension implements BeforeAllCallback {

    private static final ExtensionContext.Namespace NAMESPACE =
            ExtensionContext.Namespace.create(OpenSearchCleanupExtension.class);
    private static final String AUTO_CLOSE = "junit.jupiter.extensions.store.close.autocloseable.enabled";
    private final Runnable cleanup;

    /** Creates an extension whose root owner invokes the central exporter-index cleanup helper. */
    public OpenSearchCleanupExtension() {
        this(OpenSearchCleanupIT::deleteExporterIndexesNow);
    }

    OpenSearchCleanupExtension(Runnable cleanup) {
        this.cleanup = Objects.requireNonNull(cleanup);
    }

    /**
     * Registers the cleanup resource atomically in the root store before a participating class.
     *
     * @param context Jupiter's current class context
     * @throws IllegalStateException if automatic resource closure was explicitly disabled
     */
    @Override
    public void beforeAll(ExtensionContext context) {
        if (!context.getConfigurationParameter(AUTO_CLOSE, Boolean::parseBoolean).orElse(true)) {
            throw new IllegalStateException("OpenSearch integration cleanup requires automatic root-store closure");
        }
        context.getRoot().getStore(NAMESPACE)
                .computeIfAbsent(CleanupAction.class, key -> new CleanupAction(cleanup), CleanupAction.class);
    }

    private record CleanupAction(Runnable cleanup) implements AutoCloseable {
        @Override
        public void close() {
            cleanup.run();
        }
    }
}
