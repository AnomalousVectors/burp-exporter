package ai.anomalousvectors.tools.burp.ui;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.awt.Component;
import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JToolTip;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.ui.primitives.TriStateCheckBox;
import ai.anomalousvectors.tools.burp.ui.text.ExportFieldSectionTooltips;
import ai.anomalousvectors.tools.burp.utils.config.ExportFieldRegistry;
import ai.anomalousvectors.tools.burp.utils.config.SearchMappingResources;

class ConfigPanelFieldTooltipsHeadlessTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void fieldSection_components_have_expected_tooltips() throws Exception {
        ConfigPanel panel = newPanelOnEdt();

        JLabel header = (JLabel) findLabelByText(panel, "Index Fields");
        JLabel settingsLabel = (JLabel) findLabelByTextAndTooltipPrefix(panel, "Settings", "<html><b>Settings fields</b>");
        JLabel findingsLabel = (JLabel) findLabelByText(panel, "Findings");
        JButton settingsExpand = findByName(panel, "fields.settings.expand", JButton.class);
        JButton findingsExpand = findByName(panel, "fields.findings.expand", JButton.class);
        javax.swing.JTextField baseTemplateField = findByName(panel, "indexNaming.baseTemplate", javax.swing.JTextField.class);
        JCheckBox settingsProjectId = findByName(panel, "fields.settings.burp.project_id", JCheckBox.class);
        JCheckBox sitemapUrl = findByName(panel, "fields.sitemap.request.url.raw", JCheckBox.class);
        JCheckBox findingsSeverity = findByName(panel, "fields.findings.issue.severity", JCheckBox.class);
        JCheckBox trafficUrl = findByName(panel, "fields.traffic.request.url.raw", JCheckBox.class);
        JCheckBox trafficBurpInScope = findByName(panel, "fields.traffic.burp.is_in_scope", JCheckBox.class);
        JCheckBox trafficResponseStatusCode = findByName(panel, "fields.traffic.response.status.code", JCheckBox.class);
        JCheckBox trafficResponseStatusDescription = findByName(panel, "fields.traffic.response.status.description", JCheckBox.class);
        JCheckBox trafficRepeaterTabGroup = findByName(panel, "fields.traffic.burp.repeater.tab_group", JCheckBox.class);
        JLabel trafficMetaSectionLabel = findByName(panel, "fields.traffic.section.meta", JLabel.class);
        TriStateCheckBox trafficMetaSectionCheckbox =
                findByName(panel, "fields.traffic.section.meta", TriStateCheckBox.class);

        runEdt(() -> {
            assertThat(header).isNotNull();
            assertThat(settingsLabel).isNotNull();
            assertThat(findingsLabel).isNotNull();
            assertThat(settingsExpand).isNotNull();
            assertThat(findingsExpand).isNotNull();
            assertThat(baseTemplateField).isNotNull();
            assertThat(settingsProjectId).isNotNull();
            assertThat(sitemapUrl).isNotNull();
            assertThat(findingsSeverity).isNotNull();
            assertThat(trafficUrl).isNotNull();
            assertThat(trafficBurpInScope).isNotNull();
            assertThat(trafficResponseStatusCode).isNotNull();
            assertThat(trafficResponseStatusDescription).isNotNull();
            assertThat(trafficRepeaterTabGroup).isNotNull();
            assertThat(trafficMetaSectionLabel).isNotNull();
            assertThat(trafficMetaSectionLabel.isEnabled()).isFalse();
            assertThat(trafficMetaSectionCheckbox).isNull();
            assertThat(trafficMetaSectionLabel.getToolTipText())
                    .isEqualTo("<html>Required document metadata (always exported as a whole). Expand to see sub-fields; "
                            + "individual meta leaves are shown for visibility only and cannot be disabled.</html>");
            assertThat(header.getToolTipText()).isEqualTo("<html>Configure index naming and which mapped fields each exported document includes.<br>Naming controls affect index creation and file basenames.<br>Field toggles affect document contents.</html>");
            assertThat(settingsLabel.getToolTipText())
                    .isEqualTo("<html><b>Settings fields</b><br>Configure fields exported to the Settings index.<br>The index name can be customized from the Index Base Name field.<br>Use these toggles to trim the settings document payload.</html>");
            assertThat(settingsExpand.getToolTipText()).isEqualTo("<html>Show or hide Settings field options.</html>");
            assertThat(findingsLabel.getToolTipText())
                    .isEqualTo("<html><b>Findings fields</b><br>Configure fields exported to the Findings index.<br>The index name can be customized from the Index Base Name field.<br>These fields cover Burp findings (aka issues) documents.</html>");
            assertThat(findingsExpand.getToolTipText()).isEqualTo("<html>Show or hide Findings field options.</html>");
            assertThat(baseTemplateField.getToolTipText()).contains("Shared base used to derive all OpenSearch index names");
            assertThat(baseTemplateField.getToolTipText()).contains("Enter only the shared base");
            assertThat(baseTemplateField.getToolTipText()).contains("${now:yyyyMMdd}");
            assertThat(baseTemplateField.getToolTipText()).contains("{NOW}");
            assertThat(baseTemplateField.getToolTipText()).contains("remain fixed for that full run");
            assertThat(settingsProjectId.getText()).isEqualTo("Project id");
            assertThat(settingsProjectId.getToolTipText())
                    .contains("Field:</b> burp.project_id")
                    .contains("Burp project identifier.")
                    .contains("<b>Source")
                    .contains("SettingsIndexReporter uses MontoyaApi.project().id()");
            assertThat(sitemapUrl.getText()).isEqualTo("Raw");
            assertThat(sitemapUrl.getToolTipText()).contains("Field:</b> request.url.raw");
            assertThat(sitemapUrl.getToolTipText())
                    .contains("Field:</b> request.url.raw")
                    .contains("Full request URL for the sitemap item.")
                    .contains("SitemapIndexReporter.buildSitemapDoc()");
            assertThat(findingsSeverity.getText()).isEqualTo("Severity");
            assertThat(findingsSeverity.getToolTipText()).contains("Field:</b> issue.severity");
            assertThat(findingsSeverity.getToolTipText())
                    .contains("Field:</b> issue.severity")
                    .contains("Issue severity")
                    .contains("informational maps to INFORMATION")
                    .contains("AuditIssue.severity()");
            assertThat(trafficUrl.getText()).isEqualTo("Raw");
            assertThat(trafficUrl.getToolTipText())
                    .contains("Field:</b> request.url.raw")
                    .contains("<b>Description:</b>")
                    .contains("Full request URL.")
                    .contains("<b>Source")
                    .contains("Traffic producers use RequestResponseDocBuilder.buildBestEffortUrl()");
            assertThat(trafficBurpInScope.getText()).isEqualTo("Is in scope");
            assertThat(trafficBurpInScope.getToolTipText())
                    .contains("Field:</b> burp.is_in_scope")
                    .contains("<b>Description:</b>")
                    .contains("Raw Burp Suite scope flag, not the extension's export-scope decision.")
                    .contains("<b>Source")
                    .contains("TrafficHttpHandler uses request.isInScope()")
                    .contains("ProxyHistoryIndexReporter uses MontoyaApi.scope().isInScope(url)")
                    .contains("ProxyWebSocketIndexReporter uses MontoyaApi.scope().isInScope(url) via safeBurpInScope().");
            assertThat(trafficResponseStatusCode.getText()).isEqualTo("Code");
            assertThat(trafficResponseStatusCode.getToolTipText())
                    .contains("<b>Description:</b>")
                    .contains("Obtain the HTTP status code contained in the response.")
                    .contains("<b>Source")
                    .contains("HttpResponse.statusCode()")
                    .contains("orphan docs use sentinel response.status.code=0");
            assertThat(trafficResponseStatusDescription.getText()).isEqualTo("Description");
            assertThat(trafficResponseStatusDescription.getToolTipText())
                    .contains("<b>Description:</b>")
                    .contains("Obtain the HTTP reason phrase contained in the response")
                    .contains("<b>Source")
                    .contains("HttpResponse.reasonPhrase()");
            assertThat(trafficRepeaterTabGroup.getText()).isEqualTo("Tab group");
            assertThat(trafficRepeaterTabGroup.getToolTipText())
                    .contains("Field:</b> burp.repeater.tab_group")
                    .contains("<b>Description:</b>")
                    .contains("Best-effort Repeater tab-group name")
                    .contains("<b>Source")
                    .contains(
                            "RepeaterTabsIndexReporter infers the value from the selected Repeater tab-header component during startup capture.")
                    .contains("TrafficHttpHandler uses short-lived correlation from Repeater editor rebinds for live Repeater traffic.");
        });
    }

    @Test
    void required_fields_render_as_disabled_labels_with_tooltip_only_no_visible_suffix() throws Exception {
        ConfigPanel panel = newPanelOnEdt();

        JCheckBox exporterEventLevel = findByName(panel, "fields.exporter.event.level", JCheckBox.class);
        JCheckBox exporterEventSource = findByName(panel, "fields.exporter.event.source", JCheckBox.class);
        JCheckBox exporterEventThread = findByName(panel, "fields.exporter.event.thread", JCheckBox.class);
        JCheckBox exporterEventType = findByName(panel, "fields.exporter.event.type", JCheckBox.class);
        JLabel removedFindingsReqResMissing = findByName(panel, "fields.findings.request_responses_missing.required", JLabel.class);
        JLabel settingsSchemaVersion = findByName(panel, "fields.settings.meta.schema_version.required", JLabel.class);
        JLabel sitemapExtensionVersion = findByName(panel, "fields.sitemap.meta.extension_version.required", JLabel.class);
        JLabel trafficIndexedAt = findByName(panel, "fields.traffic.meta.indexed_at.required", JLabel.class);
        JLabel trafficSchemaVersion = findByName(panel, "fields.traffic.meta.schema_version.required", JLabel.class);

        // Parent containers (request, response, requests_responses, meta) are intentionally
        // not surfaced as required labels - children carry the meaningful info and meta is
        // dynamically mapped now. These lookups must return null.
        JLabel droppedTrafficRequest = findByName(panel, "fields.traffic.request.required", JLabel.class);
        JLabel droppedTrafficResponse = findByName(panel, "fields.traffic.response.required", JLabel.class);
        JLabel droppedTrafficDocMeta = findByName(panel, "fields.traffic.meta.required", JLabel.class);
        JLabel droppedSitemapRequest = findByName(panel, "fields.sitemap.request.required", JLabel.class);
        JLabel droppedSitemapResponse = findByName(panel, "fields.sitemap.response.required", JLabel.class);
        JLabel droppedFindingsReqRes = findByName(panel, "fields.findings.requests_responses.required", JLabel.class);
        JLabel droppedFindingsDocMeta = findByName(panel, "fields.findings.meta.required", JLabel.class);
        JLabel droppedSettingsDocMeta = findByName(panel, "fields.settings.meta.required", JLabel.class);
        JLabel droppedExporterEvent = findByName(panel, "fields.exporter.event.required", JLabel.class);
        JLabel droppedExporterEventLevel = findByName(panel, "fields.exporter.event.level.required", JLabel.class);
        JLabel droppedExporterEventSource = findByName(panel, "fields.exporter.event.source.required", JLabel.class);
        JLabel droppedExporterEventThread = findByName(panel, "fields.exporter.event.thread.required", JLabel.class);
        JLabel droppedExporterEventType = findByName(panel, "fields.exporter.event.type.required", JLabel.class);

        runEdt(() -> {
            assertThat(exporterEventLevel).isNotNull();
            assertThat(exporterEventSource).isNotNull();
            assertThat(exporterEventThread).isNotNull();
            assertThat(exporterEventType).isNotNull();
            assertThat(removedFindingsReqResMissing).isNull();
            assertThat(settingsSchemaVersion).isNotNull();
            assertThat(sitemapExtensionVersion).isNotNull();
            assertThat(trafficIndexedAt).isNotNull();
            assertThat(trafficSchemaVersion).isNotNull();

            assertThat(droppedTrafficRequest).isNull();
            assertThat(droppedTrafficResponse).isNull();
            assertThat(droppedTrafficDocMeta).isNull();
            assertThat(droppedSitemapRequest).isNull();
            assertThat(droppedSitemapResponse).isNull();
            assertThat(droppedFindingsReqRes).isNull();
            assertThat(droppedFindingsDocMeta).isNull();
            assertThat(droppedSettingsDocMeta).isNull();
            assertThat(droppedExporterEvent).isNull();
            assertThat(droppedExporterEventLevel).isNull();
            assertThat(droppedExporterEventSource).isNull();
            assertThat(droppedExporterEventThread).isNull();
            assertThat(droppedExporterEventType).isNull();

            assertThat(settingsSchemaVersion.isEnabled()).isFalse();
            assertThat(settingsSchemaVersion.getText()).isEqualTo("Schema version");
            assertThat(settingsSchemaVersion.getInsets().left)
                    .as("required-label text should align with checkbox text, not checkbox icon")
                    .isGreaterThan(0)
                    .isEqualTo(sitemapExtensionVersion.getInsets().left)
                    .isEqualTo(trafficIndexedAt.getInsets().left)
                    .isEqualTo(trafficSchemaVersion.getInsets().left);
            assertThat(settingsSchemaVersion.getToolTipText())
                    .contains("<b>Note:</b> Always exported (view-only; cannot be disabled in the Fields panel)")
                    .contains("Export schema version for this document.")
                    .contains("meta.schema_version");

            assertThat(sitemapExtensionVersion.isEnabled()).isFalse();
            assertThat(sitemapExtensionVersion.getText()).isEqualTo("Extension version");
            assertThat(sitemapExtensionVersion.getToolTipText())
                    .contains("<b>Note:</b> Always exported (view-only; cannot be disabled in the Fields panel)")
                    .contains("Burp Exporter extension version")
                    .contains("cached loaded extension version");

            assertThat(trafficIndexedAt.isEnabled()).isFalse();
            assertThat(trafficIndexedAt.getText()).isEqualTo("Indexed at");
            assertThat(trafficIndexedAt.getToolTipText())
                    .contains("<b>Note:</b> Always exported (view-only; cannot be disabled in the Fields panel)")
                    .contains("canonical cross-index time field")
                    .contains("Instant.now().toString()");

            assertThat(trafficSchemaVersion.isEnabled()).isFalse();
            assertThat(trafficSchemaVersion.getText()).isEqualTo("Schema version");
            assertThat(trafficSchemaVersion.getToolTipText())
                    .contains("<b>Note:</b> Always exported (view-only; cannot be disabled in the Fields panel)")
                    .contains("Export schema version for this document.")
                    .contains("meta.schema_version");

            assertThat(exporterEventLevel.getText()).isEqualTo("Level").doesNotContain("always included");
            assertThat(exporterEventSource.getText()).isEqualTo("Source").doesNotContain("always included");
            assertThat(exporterEventThread.getText()).isEqualTo("Thread").doesNotContain("always included");
            assertThat(exporterEventType.getText()).isEqualTo("Type").doesNotContain("always included");
            assertThat(exporterEventLevel.getToolTipText())
                    .contains("Exporter event severity or verbosity level.")
                    .contains("ExporterIndexLogForwarder forwards Logger levels");
            assertThat(exporterEventType.getToolTipText())
                    .contains("Exporter event category.")
                    .contains("Source")
                    .contains("ExporterIndexLogForwarder writes log")
                    .contains("parameter_integrity_detail");
            assertThat(exporterEventSource.getToolTipText())
                    .contains("Exporter event source label.")
                    .contains("Source")
                    .contains("assign the component/source that produced the event");
            assertThat(exporterEventThread.getToolTipText())
                    .contains("Java producer thread name")
                    .contains("AWT-EventQueue-0")
                    .contains("burp-exporter-stats")
                    .contains("Thread.currentThread().getName()");
        });
    }

    @Test
    void every_mapping_leaf_is_rendered_in_fields_panel() throws Exception {
        ConfigPanel panel = newPanelOnEdt();

        runEdt(() -> {
            for (String index : ExportFieldRegistry.INDEX_ORDER) {
                List<String> missing = new ArrayList<>();
                for (String field : mappingLeafPaths(index)) {
                    String baseName = "fields." + index + "." + field;
                    boolean checkboxPresent = findByName(panel, baseName, JCheckBox.class) != null;
                    boolean requiredLabelPresent = findByName(panel, baseName + ".required", JLabel.class) != null;
                    if (!checkboxPresent && !requiredLabelPresent) {
                        missing.add(field);
                    }
                }
                assertThat(missing)
                        .as("%s mapping fields missing from Config Fields panel", index)
                        .isEmpty();
            }
        });
    }

    @Test
    void every_mapping_directory_parent_has_section_tooltip() throws Exception {
        ConfigPanel panel = newPanelOnEdt();

        runEdt(() -> {
            for (String index : ExportFieldRegistry.INDEX_ORDER) {
                for (String sectionPath : mappingDirectoryPaths(index)) {
                    String componentName = "fields." + index + ".section." + sectionPath;
                    TriStateCheckBox triState = findByName(panel, componentName, TriStateCheckBox.class);
                    JLabel requiredSection = findByName(panel, componentName, JLabel.class);
                    String tooltip = triState != null
                            ? triState.getToolTipText()
                            : requiredSection != null ? requiredSection.getToolTipText() : null;
                    assertThat(tooltip)
                            .as("%s section %s tooltip", index, sectionPath)
                            .isNotNull()
                            .startsWith("<html>")
                            .endsWith("</html>")
                            .doesNotContain("<b>Section:</b>")
                            .doesNotContain("<b>Description:</b>")
                            .doesNotContain("<b>Montoya:</b>")
                            .isEqualTo(ExportFieldSectionTooltips.sectionTooltipFor(index, sectionPath));
                }
            }
        });
    }

    @Test
    void every_mapping_leaf_tooltip_uses_standard_fields_panel_format() throws Exception {
        ConfigPanel panel = newPanelOnEdt();

        runEdt(() -> {
            for (String index : ExportFieldRegistry.INDEX_ORDER) {
                for (String field : mappingLeafPaths(index)) {
                    String baseName = "fields." + index + "." + field;
                    JCheckBox checkbox = findByName(panel, baseName, JCheckBox.class);
                    JLabel requiredLabel = findByName(panel, baseName + ".required", JLabel.class);
                    String tooltip = checkbox != null ? checkbox.getToolTipText() : requiredLabel.getToolTipText();
                    assertThat(tooltip)
                            .as("%s.%s tooltip", index, field)
                            .startsWith("<html><b>Field:</b> " + field)
                            .contains("<b>Description:")
                            .contains("<b>Source:");
                    if (requiredLabel != null) {
                        assertThat(tooltip)
                                .as("%s.%s required tooltip", index, field)
                                .contains("<b>Note:</b> Always exported (view-only; cannot be disabled in the Fields panel)");
                    } else {
                        assertThat(tooltip)
                                .as("%s.%s toggleable tooltip", index, field)
                                .doesNotContain("Always exported");
                    }
                }
            }
        });
    }

    @Test
    void traffic_burpSectionParent_togglesChildCheckboxes() throws Exception {
        ConfigPanel panel = newPanelOnEdt();
        JButton trafficExpand = findByName(panel, "fields.traffic.expand", JButton.class);
        TriStateCheckBox burpSection = findByName(panel, "fields.traffic.section.burp", TriStateCheckBox.class);
        TriStateCheckBox proxySection = findByName(panel, "fields.traffic.section.burp.proxy", TriStateCheckBox.class);
        JCheckBox inScope = findByName(panel, "fields.traffic.burp.is_in_scope", JCheckBox.class);
        JCheckBox notes = findByName(panel, "fields.traffic.burp.notes", JCheckBox.class);
        JCheckBox proxyHistoryId = findByName(panel, "fields.traffic.burp.proxy.history_id", JCheckBox.class);

        runEdt(() -> {
            assertThat(trafficExpand).isNotNull();
            assertThat(burpSection).isNotNull();
            assertThat(proxySection).isNotNull();
            assertThat(inScope).isNotNull();
            assertThat(notes).isNotNull();
            assertThat(proxyHistoryId).isNotNull();
            trafficExpand.doClick();
            assertThat(burpSection.getText()).isEqualTo("Burp");
            assertThat(inScope.getText()).isEqualTo("Is in scope");

            assertThat(burpSection.getToolTipText())
                    .isEqualTo(
                            "<html>Burp tool attribution, scope, message correlation, user annotations, and nested proxy, repeater, and timing groups.</html>");

            performTriStateClick(burpSection);
            assertThat(inScope.isSelected()).isFalse();
            assertThat(notes.isSelected()).isFalse();
            assertThat(burpSection.getState()).isEqualTo(TriStateCheckBox.State.DESELECTED);

            performTriStateClick(burpSection);
            assertThat(inScope.isSelected()).isTrue();
            assertThat(notes.isSelected()).isTrue();
            assertThat(burpSection.getState()).isEqualTo(TriStateCheckBox.State.SELECTED);

            performTriStateClick(proxySection);
            assertThat(proxyHistoryId.isSelected()).isFalse();
            assertThat(notes.isSelected()).isTrue();
            assertThat(proxySection.getState()).isEqualTo(TriStateCheckBox.State.DESELECTED);
            assertThat(burpSection.getState()).isEqualTo(TriStateCheckBox.State.INDETERMINATE);
        });
    }

    @Test
    void traffic_nestedHtmlSection_reflectsSelectedDomSubsectionAsPartial() throws Exception {
        ConfigPanel panel = newPanelOnEdt();
        TriStateCheckBox responseSection = findByName(panel, "fields.traffic.section.response", TriStateCheckBox.class);
        TriStateCheckBox bodySection = findByName(panel, "fields.traffic.section.response.body", TriStateCheckBox.class);
        TriStateCheckBox htmlSection = findByName(panel, "fields.traffic.section.response.body.html", TriStateCheckBox.class);
        TriStateCheckBox domSection = findByName(panel, "fields.traffic.section.response.body.html.dom", TriStateCheckBox.class);
        JCheckBox comments = findByName(panel, "fields.traffic.response.body.html.comments", JCheckBox.class);
        JCheckBox cssClasses = findByName(panel, "fields.traffic.response.body.html.dom.css_classes", JCheckBox.class);
        JCheckBox divIds = findByName(panel, "fields.traffic.response.body.html.dom.div_ids", JCheckBox.class);
        JCheckBox tagNames = findByName(panel, "fields.traffic.response.body.html.dom.tag_names", JCheckBox.class);

        runEdt(() -> {
            assertThat(responseSection).isNotNull();
            assertThat(bodySection).isNotNull();
            assertThat(htmlSection).isNotNull();
            assertThat(domSection).isNotNull();
            assertThat(comments).isNotNull();
            assertThat(cssClasses).isNotNull();
            assertThat(divIds).isNotNull();
            assertThat(tagNames).isNotNull();

            performTriStateClick(htmlSection);
            assertThat(htmlSection.getState()).isEqualTo(TriStateCheckBox.State.DESELECTED);
            assertThat(domSection.getState()).isEqualTo(TriStateCheckBox.State.DESELECTED);

            performTriStateClick(domSection);

            assertThat(cssClasses.isSelected()).isTrue();
            assertThat(divIds.isSelected()).isTrue();
            assertThat(tagNames.isSelected()).isTrue();
            assertThat(comments.isSelected()).isFalse();
            assertThat(domSection.getState()).isEqualTo(TriStateCheckBox.State.SELECTED);
            assertThat(htmlSection.getState()).isEqualTo(TriStateCheckBox.State.INDETERMINATE);
            assertThat(bodySection.getState()).isEqualTo(TriStateCheckBox.State.INDETERMINATE);
            assertThat(responseSection.getState()).isEqualTo(TriStateCheckBox.State.INDETERMINATE);
        });
    }

    @Test
    void traffic_nestedHtmlSection_singleClickFromPartialSelectsAllDescendants() throws Exception {
        ConfigPanel panel = newPanelOnEdt();
        TriStateCheckBox htmlSection = findByName(panel, "fields.traffic.section.response.body.html", TriStateCheckBox.class);
        TriStateCheckBox domSection = findByName(panel, "fields.traffic.section.response.body.html.dom", TriStateCheckBox.class);
        JCheckBox comments = findByName(panel, "fields.traffic.response.body.html.comments", JCheckBox.class);
        JCheckBox cssClasses = findByName(panel, "fields.traffic.response.body.html.dom.css_classes", JCheckBox.class);
        JCheckBox divIds = findByName(panel, "fields.traffic.response.body.html.dom.div_ids", JCheckBox.class);
        JCheckBox tagNames = findByName(panel, "fields.traffic.response.body.html.dom.tag_names", JCheckBox.class);

        runEdt(() -> {
            performTriStateClick(htmlSection);
            cssClasses.setSelected(true);

            assertThat(domSection.getState()).isEqualTo(TriStateCheckBox.State.INDETERMINATE);
            assertThat(htmlSection.getState()).isEqualTo(TriStateCheckBox.State.INDETERMINATE);

            performTriStateClick(htmlSection);

            assertThat(comments.isSelected()).isTrue();
            assertThat(cssClasses.isSelected()).isTrue();
            assertThat(divIds.isSelected()).isTrue();
            assertThat(tagNames.isSelected()).isTrue();
            assertThat(domSection.getState()).isEqualTo(TriStateCheckBox.State.SELECTED);
            assertThat(htmlSection.getState()).isEqualTo(TriStateCheckBox.State.SELECTED);
        });
    }

    private static void performTriStateClick(TriStateCheckBox box) {
        TriStateCheckBox.State next = box.getState() == TriStateCheckBox.State.SELECTED
                ? TriStateCheckBox.State.DESELECTED
                : TriStateCheckBox.State.SELECTED;
        box.setState(next);
        ActionEvent event = new ActionEvent(box, ActionEvent.ACTION_PERFORMED, box.getText());
        for (ActionListener listener : box.getActionListeners()) {
            listener.actionPerformed(event);
        }
    }

    @Test
    void findings_collaborator_checkbox_is_rendered_with_tooltip() throws Exception {
        ConfigPanel panel = newPanelOnEdt();
        JCheckBox cb = findByName(panel, "fields.findings.collaborator.id", JCheckBox.class);

        runEdt(() -> {
            assertThat(cb).isNotNull();
            assertThat(cb.getText()).isEqualTo("Id");
            String tooltip = cb.getToolTipText();
            assertThat(tooltip).contains("Field:</b> collaborator.id");
            assertThat(tooltip)
                    .contains("Burp Collaborator interaction identifier")
                    .contains("FindingsIndexReporter.buildCollaboratorInteractionsList() uses Interaction.id()");
        });
    }

    @Test
    void field_checkbox_tooltip_owner_creates_html_enabled_tooltip() throws Exception {
        ConfigPanel panel = newPanelOnEdt();
        JCheckBox trafficUrl = findByName(panel, "fields.traffic.request.url.raw", JCheckBox.class);

        runEdt(() -> {
            assertThat(trafficUrl).isNotNull();
            JToolTip toolTip = trafficUrl.createToolTip();
            assertThat(toolTip.getComponent()).isSameAs(trafficUrl);
            assertThat(toolTip.getClientProperty("html.disable")).isEqualTo(Boolean.FALSE);
        });
    }

    private static ConfigPanel newPanelOnEdt() throws Exception {
        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ConfigPanel panel = new ConfigPanel();
            panel.setSize(1000, 700);
            panel.doLayout();
            ref.set(panel);
        });
        return ref.get();
    }

    private static void runEdt(Runnable runnable) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            runnable.run();
        } else {
            SwingUtilities.invokeAndWait(runnable);
        }
    }

    private static Component findLabelByText(Container root, String text) {
        for (Component component : root.getComponents()) {
            if (component instanceof JLabel label && text.equals(label.getText())) {
                return label;
            }
            if (component instanceof Container child) {
                Component nested = findLabelByText(child, text);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }

    private static Component findLabelByTextAndTooltipPrefix(Container root, String text, String tooltipPrefix) {
        for (Component component : root.getComponents()) {
            if (component instanceof JLabel label
                    && text.equals(label.getText())
                    && label.getToolTipText() != null
                    && label.getToolTipText().startsWith(tooltipPrefix)) {
                return label;
            }
            if (component instanceof Container child) {
                Component nested = findLabelByTextAndTooltipPrefix(child, text, tooltipPrefix);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }

    private static <T extends Component> T findByName(Container root, String name, Class<T> type) {
        for (Component component : root.getComponents()) {
            String componentName = component.getName();
            if (type.isInstance(component) && componentName != null && name.equals(componentName)) {
                return type.cast(component);
            }
            if (component instanceof Container child) {
                T nested = findByName(child, name, type);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }

    private static List<String> mappingDirectoryPaths(String index) {
        String resource = SearchMappingResources.DEFAULT_ROOT + index + ".json";
        try (InputStream is = ConfigPanelFieldTooltipsHeadlessTest.class.getResourceAsStream(resource)) {
            assertThat(is)
                    .as("mapping resource %s", resource)
                    .isNotNull();
            JsonNode properties = MAPPER.readTree(is).path("mappings").path("properties");
            List<String> out = new ArrayList<>();
            collectMappingDirectoryPaths("", properties, out);
            return out;
        } catch (IOException e) {
            throw new AssertionError("Could not read mapping resource " + resource, e);
        }
    }

    private static void collectMappingDirectoryPaths(String prefix, JsonNode properties, List<String> out) {
        for (var entry : properties.properties()) {
            String path = prefix.isEmpty() ? entry.getKey() : prefix + "." + entry.getKey();
            JsonNode field = entry.getValue();
            JsonNode children = field.path("properties");
            if (children.isObject() && !children.isEmpty()) {
                out.add(path);
                collectMappingDirectoryPaths(path, children, out);
            }
        }
    }

    private static List<String> mappingLeafPaths(String index) {
        String resource = SearchMappingResources.DEFAULT_ROOT + index + ".json";
        try (InputStream is = ConfigPanelFieldTooltipsHeadlessTest.class.getResourceAsStream(resource)) {
            assertThat(is)
                    .as("mapping resource %s", resource)
                    .isNotNull();
            JsonNode properties = MAPPER.readTree(is).path("mappings").path("properties");
            List<String> out = new ArrayList<>();
            collectMappingLeafPaths("", properties, out);
            return out;
        } catch (IOException e) {
            throw new AssertionError("Could not read mapping resource " + resource, e);
        }
    }

    private static void collectMappingLeafPaths(String prefix, JsonNode properties, List<String> out) {
        for (var entry : properties.properties()) {
            String path = prefix.isEmpty() ? entry.getKey() : prefix + "." + entry.getKey();
            JsonNode field = entry.getValue();
            JsonNode children = field.path("properties");
            if (children.isObject() && !children.isEmpty()) {
                collectMappingLeafPaths(path, children, out);
            } else if (field.has("type")) {
                out.add(path);
            }
        }
    }
}
