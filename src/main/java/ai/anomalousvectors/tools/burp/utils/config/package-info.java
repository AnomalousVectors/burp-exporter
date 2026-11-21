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
 * <p>Import catalogs validate supported keys and edition capabilities. Field catalogs and
 * registries define selectable document paths; {@link ExportFieldFilter} applies those choices
 * before delivery. {@link SearchMappingResources} locates bundled database mappings; deployment
 * adaptation belongs to {@link ai.anomalousvectors.tools.burp.utils.search}.</p>
 *
 * <p>Configuration snapshots are immutable, but reports and mutable builders have separate
 * ownership contracts. {@link SecureCredentialStore} owns session credentials; saved/exported
 * configuration uses the JSON mapper's secret-handling rules. UI and file-dialog work remain
 * outside this package.</p>
 */
package ai.anomalousvectors.tools.burp.utils.config;
