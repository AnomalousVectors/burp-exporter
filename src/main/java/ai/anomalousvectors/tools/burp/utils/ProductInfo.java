package ai.anomalousvectors.tools.burp.utils;

/**
 * Centralizes public product labels and links.
 *
 * <p>Runtime identifiers such as thread names, log sources, and index names intentionally live
 * near the systems that emit them. This class is for operator-facing names and URLs that appear
 * in Burp UI or public project metadata.</p>
 */
public final class ProductInfo {
    /** Operator-facing organization / brand name. */
    public static final String ORGANIZATION_NAME = "Anomalous Vectors";
    /** Short organization tagline shown on the About brand row (no terminal punctuation). */
    public static final String ORGANIZATION_TAGLINE = "Engineering offensive intelligence";
    /** Burp extension name registered with Montoya. */
    public static final String EXTENSION_NAME = "Burp Exporter";
    /** Suite tab title shown in Burp. */
    public static final String SUITE_TAB_TITLE = "Exporter";
    /** Label for the Get Latest releases link on the About tab. */
    public static final String REPOSITORY_LABEL = "Get Latest:";
    /** Public GitHub Releases URL for the extension. */
    public static final String REPOSITORY_URL = "https://github.com/AnomalousVectors/burp-exporter/releases";

    private ProductInfo() {}
}
