package ai.anomalousvectors.tools.burp.utils.config;

import tools.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Hierarchical catalog of export fields for the Index Fields panel.
 *
 * <p>Nodes with children are directories (sub-section headers in the UI). Leaf nodes without
 * children are export data fields (checkboxes or required labels). This mirrors the OpenSearch
 * mapping shape: {@code burp} is a directory; {@code burp.reporting_tool} is a leaf.</p>
 */
public final class ExportFieldCatalog {

    /** Node role in the catalog tree. */
    public enum Kind {
        /** Structural grouping only; never exported as a scalar at this path. */
        DIRECTORY,
        /** User-toggleable mapped leaf field. */
        TOGGLEABLE_LEAF,
        /** Always exported; shown as a disabled label in the UI. */
        REQUIRED_LEAF
    }

    /** Immutable tree node for one segment of a dotted field path. */
    public static final class Node {
        private final String segment;
        private final String path;
        private final Kind kind;
        private final List<Node> children;

        private Node(String segment, String path, Kind kind, List<Node> children) {
            this.segment = segment;
            this.path = path;
            this.kind = kind;
            this.children = List.copyOf(children);
        }

        /** Root directory containing all top-level mapping fields for an index. */
        public static Node root() {
            return new Node("", "", Kind.DIRECTORY, new ArrayList<>());
        }

        public String segment() {
            return segment;
        }

        /** Full dotted export path; empty for the synthetic root. */
        public String path() {
            return path;
        }

        public Kind kind() {
            return kind;
        }

        public List<Node> children() {
            return children;
        }

        public boolean isDirectory() {
            return kind == Kind.DIRECTORY;
        }

        /** Human-readable sub-section title for directory nodes. */
        public String displayTitle() {
            return FieldSegmentLabels.titleFor(segment);
        }

        private Node withChild(Node child) {
            List<Node> next = new ArrayList<>(children.size() + 1);
            next.addAll(children);
            next.add(child);
            return new Node(segment, path, kind, next);
        }
    }

    private ExportFieldCatalog() { }

    /** Builds the field catalog tree for the index from its mapping resource. */
    public static Node catalogForIndex(String indexShortName) {
        Node root = Node.root();
        JsonNode properties = MappingFieldCatalog.readMappingProperties(indexShortName);
        if (properties != null) {
            root = appendMappingProperties(root, "", properties, indexShortName);
        }
        return root;
    }

    private static Node appendMappingProperties(Node parent, String prefix, JsonNode propertiesNode, String indexShortName) {
        Node current = parent;
        for (Map.Entry<String, JsonNode> entry : propertiesNode.properties()) {
            String name = entry.getKey();
            String path = prefix.isEmpty() ? name : prefix + "." + name;
            JsonNode field = entry.getValue();
            if (MappingFieldCatalog.isMappingDirectory(field)) {
                Node directory = new Node(name, path, Kind.DIRECTORY, List.of());
                Node populated = appendMappingProperties(directory, path, field.path("properties"), indexShortName);
                current = current.withChild(populated);
            } else if (MappingFieldCatalog.isMappingLeaf(field)) {
                Kind kind = ExportFieldRegistry.isRequiredLeafPath(path)
                        ? Kind.REQUIRED_LEAF
                        : Kind.TOGGLEABLE_LEAF;
                current = current.withChild(new Node(name, path, kind, List.of()));
            }
        }
        return current;
    }

    /** Display labels for mapping segment names used as UI sub-section headers. */
    static final class FieldSegmentLabels {
        private FieldSegmentLabels() { }

        static String titleFor(String segment) {
            if (segment == null || segment.isEmpty()) {
                return "";
            }
            return switch (segment) {
                case "burp" -> "Burp";
                case "meta" -> "Meta";
                case "request" -> "Request";
                case "response" -> "Response";
                case "protocol" -> "Protocol";
                case "websocket" -> "WebSocket";
                case "event" -> "Event";
                case "repeater" -> "Repeater";
                case "requests_responses" -> "Requests / responses";
                case "collaborator" -> "Collaborator";
                case "annotations" -> "Annotations";
                case "body" -> "Body";
                case "headers" -> "Headers";
                case "timing" -> "Timing";
                case "proxy" -> "Proxy";
                case "payload" -> "Payload";
                case "parameters" -> "Parameters";
                case "markers" -> "Markers";
                case "cookies" -> "Cookies";
                case "dns" -> "DNS";
                case "http" -> "HTTP";
                case "smtp" -> "SMTP";
                default -> toTitleWords(segment);
            };
        }

        private static String toTitleWords(String segment) {
            String[] parts = segment.split("_");
            StringBuilder sb = new StringBuilder();
            for (String part : parts) {
                if (part.isEmpty()) {
                    continue;
                }
                if (sb.length() > 0) {
                    sb.append(' ');
                }
                sb.append(Character.toUpperCase(part.charAt(0)));
                if (part.length() > 1) {
                    sb.append(part.substring(1));
                }
            }
            return sb.toString();
        }
    }
}
