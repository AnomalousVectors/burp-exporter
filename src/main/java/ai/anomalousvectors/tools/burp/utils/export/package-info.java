/**
 * Prepares stable, sink-neutral export operations and line-oriented encodings.
 *
 * <p>Documents are filtered once, assigned a stable operation identifier, and serialized for
 * retries, spill persistence, file output, and search bulk requests. Search-only fitting may
 * derive a smaller representation while preserving that identity; file sinks retain the original
 * prepared source. Prepared maps and byte arrays are caller-owned and must not be mutated after
 * publication.</p>
 */
package ai.anomalousvectors.tools.burp.utils.export;
