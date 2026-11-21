/**
 * Describes text queries and finds regex or substring match ranges without Swing dependencies.
 *
 * <ul>
 *   <li>{@link TextQuery} carries immutable query text and case, regex, and multiline choices.</li>
 *   <li>{@link TextSearchEngine} computes match ranges for callers to render or inspect.</li>
 * </ul>
 *
 * <p>Search operations are stateless and safe for concurrent callers. Invalid regular
 * expressions propagate as {@link java.util.regex.PatternSyntaxException}; UI validation and
 * highlighting belong to {@link ai.anomalousvectors.tools.burp.ui.text}.</p>
 */
package ai.anomalousvectors.tools.burp.utils.text;
