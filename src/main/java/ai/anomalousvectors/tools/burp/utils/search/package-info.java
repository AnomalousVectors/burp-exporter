/**
 * Provides destination-neutral search deployment, mapping, and connection-test support.
 *
 * <p>Utilities detect hosted, serverless, and self-hosted endpoints; adapt bundled mapping
 * settings to deployment constraints; and normalize connection-test results for Config UI
 * surfaces. Connection tests perform blocking network and credential-provider work and must run
 * off the EDT. Pure detection and mapping helpers are stateless and thread-safe.</p>
 */
package ai.anomalousvectors.tools.burp.utils.search;
