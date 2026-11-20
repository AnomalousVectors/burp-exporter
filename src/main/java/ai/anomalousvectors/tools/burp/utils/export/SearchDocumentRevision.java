package ai.anomalousvectors.tools.burp.utils.export;

/**
 * Trusted replacement identity for one run-owned streaming capture in a search destination.
 *
 * <p>Assigned by the producer, never inferred from field-filtered document content. Strict
 * external versions reject equal or older deliveries, including late retries. Independent
 * captures must use different document IDs, even when their HTTP bytes are identical.</p>
 *
 * @param documentId non-blank capture identity, shared by all its revisions
 * @param version positive, increasing observation revision
 */
public record SearchDocumentRevision(String documentId, long version) {
    /**
     * Validates immutable action metadata before it can enter a destination queue.
     *
     * @throws IllegalArgumentException if the identity is blank or the version is not positive
     */
    public SearchDocumentRevision {
        if (documentId == null || documentId.isBlank() || version <= 0L) {
            throw new IllegalArgumentException("Search replacement requires an ID and positive version");
        }
    }
}
