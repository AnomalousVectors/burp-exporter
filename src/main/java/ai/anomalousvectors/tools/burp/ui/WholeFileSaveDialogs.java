package ai.anomalousvectors.tools.burp.ui;

import java.awt.Component;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import javax.swing.JOptionPane;

import ai.anomalousvectors.tools.burp.utils.WholeFileSave;

/** Overwrite confirmation for explicit Config whole-file exports. */
final class WholeFileSaveDialogs {

    private WholeFileSaveDialogs() { }

    /**
     * Resolves the replacement policy after validating and, when needed, confirming the target.
     *
     * <p>Caller must invoke on the EDT. A missing target needs no prompt. Existing non-regular
     * targets are rejected, and declining replacement returns an empty result.</p>
     *
     * @param parent parent component for dialogs
     * @param target resolved final target, including any required extension
     * @return replacement policy, or empty when saving should not proceed
     */
    static Optional<WholeFileSave.Replacement> confirmReplacement(Component parent, Path target) {
        if (!Files.exists(target)) {
            return Optional.of(WholeFileSave.Replacement.CREATE_NEW);
        }
        if (!Files.isRegularFile(target)) {
            JOptionPane.showMessageDialog(
                    parent,
                    "The selected target is not a regular file:\n" + target,
                    "Cannot Save",
                    JOptionPane.ERROR_MESSAGE);
            return Optional.empty();
        }
        int choice = JOptionPane.showConfirmDialog(
                parent,
                "Replace the existing file?\n" + target,
                "Confirm Replace",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);
        return choice == JOptionPane.YES_OPTION
                ? Optional.of(WholeFileSave.Replacement.REPLACE_EXISTING)
                : Optional.empty();
    }
}
