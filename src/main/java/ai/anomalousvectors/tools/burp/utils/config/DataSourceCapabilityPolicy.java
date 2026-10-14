package ai.anomalousvectors.tools.burp.utils.config;

import java.util.Locale;

/** Defines edition availability for top-level export data sources. */
public final class DataSourceCapabilityPolicy {

    private DataSourceCapabilityPolicy() { }

    /**
     * Returns whether a data source is available in the requested Burp edition.
     *
     * <p>Findings rely on Professional-only APIs. Other identifiers are unaffected by this
     * capability rule; allowlist validation remains with the caller that owns it.</p>
     *
     * @param source data-source configuration identifier
     * @param communityEdition whether the active edition is Community
     * @return {@code true} when the source is not excluded by the edition capability rule
     */
    public static boolean isAvailableInEdition(String source, boolean communityEdition) {
        if (source == null || source.isBlank()) {
            return false;
        }
        String normalized = source.trim().toLowerCase(Locale.ROOT);
        return !communityEdition || !ConfigKeys.SRC_FINDINGS.equals(normalized);
    }
}
