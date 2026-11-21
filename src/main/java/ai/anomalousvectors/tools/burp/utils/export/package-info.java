/**
 * Prepares stable, sink-neutral export operations and line-oriented encodings.
 *
 * <p>Prepared documents carry filtered fields and a stable operation identifier for retries,
 * spill persistence, file output, and search bulk requests. {@link ExportLineCodec} supplies
 * the JSONL and bulk NDJSON encodings. Search-only fitting may
 * derive a smaller representation while preserving that identity; file sinks retain the original
 * prepared source. Streaming operations also carry a separate database identity and increasing
 * version, allowing ordered replacement without changing per-snapshot bookkeeping or file append
 * behavior. {@link SearchDocumentRevision} defines that replacement contract, while
 * {@link BulkPushOutcome} and {@link BulkOutcomeBreakdown} describe delivery outcomes.</p>
 *
 * <p>This package prepares data; destination I/O belongs to the sink and transport packages.
 * {@link PreparedExportDocument} does not defensively copy its map or byte array. Callers must
 * treat prepared data as immutable after publication, including while it is queued or retried.</p>
 */
package ai.anomalousvectors.tools.burp.utils.export;
