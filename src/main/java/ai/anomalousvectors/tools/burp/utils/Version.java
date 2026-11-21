package ai.anomalousvectors.tools.burp.utils;

/**
 * Centralized version accessor.
 *
 * <p>Production reads {@code Implementation-Version} from the JAR manifest. Tests may set
 * {@code burp.exporter.version} as a JVM system property to run without a packaged manifest.</p>
 */
public final class Version {
    private Version() {}

    /**
     * Returns the explicit test override or packaged implementation version.
     *
     * @return trimmed non-blank override, or manifest implementation version
     * @throws IllegalStateException if neither source provides a version
     */
    public static String get() {
        String override = System.getProperty("burp.exporter.version");
        if (override != null && !override.isBlank()) {
            return override.trim();
        }
        Package p = Version.class.getPackage();
        String mv = (p != null) ? p.getImplementationVersion() : null;
        if (mv == null || mv.isBlank()) {
            throw new IllegalStateException(
                    "Implementation-Version not found in manifest. " +
                            "Set -Dburp.exporter.version for tests or run from the packaged JAR."
            );
        }
        return mv;
    }
}
