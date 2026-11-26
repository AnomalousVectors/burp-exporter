/**
 * Captures Burp sources and delivers prepared documents to database and file destinations.
 *
 * <p>The main responsibilities are:</p>
 * <ul>
 *   <li>Live HTTP and WebSocket capture, explicit Proxy History export, retained streaming
 *       response observation, and startup Repeater-tab capture for the {@code traffic} index.</li>
 *   <li>Settings, Sitemap, Findings, and Exporter reporters for their respective indexes.</li>
 *   <li>Shared HTTP document construction, body decoding and omission policies, parameter
 *       integrity diagnostics, and source-attributed delivery accounting.</li>
 *   <li>Bounded traffic queuing and spill, file append integrity, and database index validation
 *       and snapshot replay through {@link SearchRecoveryBootstrap}.</li>
 * </ul>
 *
 * <p>Native Proxy callbacks capture live Proxy traffic with its own listener metadata; general HTTP
 * callbacks capture other tools. Both use the initiating sent request and original server response.
 * Native Proxy and general HTTP message IDs are separate namespaces, neither a UI History row ID.
 * Shared payload-free request receipts have a count cap. Old receipts are reclaimed only under
 * capacity pressure after request-only handling finishes; otherwise new capture is rejected
 * without waiting for space. Retained receipts still allow late responses after the orphan timeout.
 * Live export does not join callbacks to History. {@link StreamingProxyRecovery} independently
 * observes retained streaming responses and publishes snapshots identified by their exact History
 * row. Its bounded observation window is not proof of HTTP completion. Database revisions replace
 * that capture's document; file sinks append observations. Explicit Proxy History exports use each
 * row's own ID, {@code finalRequest()}, and received server response. Notes and highlights remain
 * read-only metadata on every path.</p>
 *
 * <p>One-shot snapshot backlogs (Proxy History, Sitemap initial, Findings backlog, Proxy WebSocket
 * historic) run in cooperative slices through
 * {@link ai.anomalousvectors.tools.burp.utils.concurrent.StartupSnapshotCoordinator} and use
 * {@link ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotExportEngine} with
 * prepared bulk delivery. Live traffic uses {@link TrafficExportQueue}; incremental reporters
 * prepare their own batches. {@link FileExportService} protects file appends through run-scoped
 * directory ownership and artifact identity/size checks. Queued exporter logs and periodic
 * reporters carry their originating run context through delivery and accounting. Seen keys,
 * successful Settings hashes and reporter activity remain generation-owned so late work cannot
 * suppress or overwrite a later run's state. Public source acquisition stays outside startup
 * backlog locks, allowing Stop to retire ownership even when Burp does not honor cancellation.</p>
 *
 * <p>Destination writes, History reads, and snapshot work belong off the EDT. Queue admission
 * for live HTTP captures Montoya metadata and parameter provenance synchronously, then retains
 * owned compact body inputs. A bounded run-owned worker completes body representations and spill
 * admission. Pending captures, preparation and prepared delivery share a byte budget through
 * {@link ai.anomalousvectors.tools.burp.utils.ExportAdmissionController}; capacity exhaustion is
 * reported without waiting or trimming accepted payloads. Other prepared producers may perform
 * synchronous queue/spill admission, but no path waits for destination HTTP completion during
 * admission. {@link ExportReporterLifecycle} coordinates Stop and unload.</p>
 */
package ai.anomalousvectors.tools.burp.sinks;
