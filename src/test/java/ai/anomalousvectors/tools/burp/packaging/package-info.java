/**
 * Verifies the distributable's isolated runtime, resources, and dependency attribution.
 *
 * <p>Tests inspect the built JAR rather than assuming that the test classpath represents its
 * contents. Isolated classloaders exercise shipped providers and dependencies;
 * {@link PackagedRuntimeProbe} supplies a JUnit-independent harness for those checks. Other
 * checks reconcile packaged legal materials and provenance with the resolved runtime artifacts.</p>
 *
 * <p>Tests own and close their classloaders, loopback fixtures, and temporary clients. Swing
 * initialization runs on the EDT. This package belongs only to the test source set and is not
 * shipped with the extension.</p>
 */
package ai.anomalousvectors.tools.burp.packaging;
