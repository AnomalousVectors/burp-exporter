/**
 * Provides reusable Swing controls, layout helpers, and input bindings.
 *
 * <ul>
 *   <li>{@link AutoSizingTextField} and {@link AutoSizingPasswordField} size input controls.</li>
 *   <li>{@link TriStateCheckBox} represents selected, deselected, and partial selections.</li>
 *   <li>{@link ScopeGrid} edits ordered custom-scope rows.</li>
 *   <li>{@link TextFieldUndo}, {@link ButtonStyles}, {@link StatusViews}, {@link ScrollPanes},
 *       and {@link ThickSeparator} supply shared interaction and presentation behavior.</li>
 * </ul>
 *
 * <p>These components do not perform destination I/O or own export lifecycle work. Caller must
 * construct and mutate Swing components on the EDT. Serializable controls document how their
 * transient listeners and bindings are restored.</p>
 */
package ai.anomalousvectors.tools.burp.ui.primitives;
