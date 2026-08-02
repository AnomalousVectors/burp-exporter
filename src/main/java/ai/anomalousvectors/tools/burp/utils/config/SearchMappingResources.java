package ai.anomalousvectors.tools.burp.utils.config;

/**
 * Resource locations for bundled search-index mappings.
 */
public final class SearchMappingResources {

    /** Classpath root for mapping JSON shared by all search database destinations. */
    public static final String DEFAULT_ROOT = "/search/mappings/";

    /** System property that overrides the mapping resource root in tests. */
    public static final String ROOT_PROPERTY = "burp.exporter.search.mappings.root";

    private SearchMappingResources() {
        throw new AssertionError("No instances");
    }

    /**
     * Returns the configured resource root for bundled search mappings.
     *
     * <p>The default ends in {@code /}. A system-property override is returned unchanged; callers
     * that append resource names must provide any required separator in the override.</p>
     *
     * @return configured resource root, never {@code null}
     */
    public static String configuredRoot() {
        return System.getProperty(ROOT_PROPERTY, DEFAULT_ROOT);
    }
}
