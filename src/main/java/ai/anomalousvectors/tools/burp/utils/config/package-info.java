/**
 * Defines persisted configuration, session credentials, and runtime export state.
 *
 * <p>Includes JSON mapping helpers
 * ({@link ai.anomalousvectors.tools.burp.utils.config.ConfigJsonMapper}), config key constants,
 * immutable configuration snapshots, session-only credential storage, and
 * {@link ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig} lifecycle coordination.
 * Runtime-state listeners execute synchronously on the thread that changes or registers state.
 * Individual APIs document any stronger thread or EDT requirement.</p>
 *
 * <p>Filesystem concerns remain in {@link ai.anomalousvectors.tools.burp.utils.FileUtil} to keep
 * configuration boundaries clear.</p>
 */
package ai.anomalousvectors.tools.burp.utils.config;
