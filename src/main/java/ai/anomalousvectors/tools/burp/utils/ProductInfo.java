package ai.anomalousvectors.tools.burp.utils;

/**
 * Centralizes public product labels and links.
 *
 * <p>Runtime identifiers such as thread names, log sources, and index names intentionally live
 * near the systems that emit them. This class is for operator-facing names and URLs that appear
 * in Burp UI or public project metadata.</p>
 */
public final class ProductInfo {
    /** Burp extension name registered with Montoya. */
    public static final String EXTENSION_NAME = "Burp Exporter";
    /** Suite tab title shown in Burp. */
    public static final String SUITE_TAB_TITLE = "Exporter";
    /** Label for the extension repository link. */
    public static final String REPOSITORY_LABEL = "Burp Exporter:";
    /** Public extension repository URL. */
    public static final String REPOSITORY_URL = "https://github.com/AnomalousVectors/burp-exporter";
    /** Label for the parent framework/OpenSearch project link. */
    public static final String FRAMEWORK_OPENSEARCH_LABEL = "OpenSearch:";
    /** Public parent framework/OpenSearch project URL. */
    public static final String FRAMEWORK_OPENSEARCH_URL = "https://github.com/AnomalousVectors/opensearch";

    private ProductInfo() {}
}
