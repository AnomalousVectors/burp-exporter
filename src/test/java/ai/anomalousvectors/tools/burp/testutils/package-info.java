/**
 * Supplies shared fixtures, ownership boundaries, and conventions for exporter tests.
 *
 * <p>Helpers centralize reflection and Montoya mocks, snapshot synchronization, test-owned paths,
 * and integration-test destination configuration. {@link TestPathSupport} confines file cleanup
 * to test-owned storage. {@link OpenSearchTestIndex} bounds a bare-client scenario's disposable
 * index, while {@link OpenSearchReachable} caches destination availability.</p>
 *
 * <p>Some helpers perform filesystem, network, or local certificate-stack work. Tests must honor
 * their setup/cleanup contracts and resource locks; shared runtime state and UI fixtures are not
 * generally safe for concurrent mutation. These helpers are test-only and are not packaged in
 * the extension.</p>
 */
package ai.anomalousvectors.tools.burp.testutils;
