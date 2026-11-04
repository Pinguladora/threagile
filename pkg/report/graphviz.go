package report

import (
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Pinguladora/threagile/pkg/types"
)

func WriteDataFlowDiagramGraphvizDOT(parsedModel *types.Model,
	diagramFilenameDOT string, dpi int, addModelTitle bool, addLegend bool,
	progressReporter progressReporter,
) (*os.File, error) {
	progressReporter.Info("Writing data flow diagram input")

	var dotContent strings.Builder
	dotContent.WriteString("digraph generatedModel { concentrate=false \n")

	if addLegend {
		writeDataFlowLegend(&dotContent)
	}

	graphAttributes, drawSpaceLines, err := dataFlowGraphAttributes(parsedModel, dpi, addModelTitle)
	if err != nil {
		return nil, err
	}
	dotContent.WriteString(graphAttributes)

	dotContent.WriteString(trustBoundarySubgraphs(parsedModel, dpi, drawSpaceLines))

	// Technical Assets ===============================================================================
	// first create them in memory (see the link replacement below for nested trust boundaries) - otherwise in Go
	// ranging over map is random order
	// range over them in sorted (hence re-producible) way:
	// Convert map to slice of values:
	var techAssets []*types.TechnicalAsset
	for _, techAsset := range parsedModel.TechnicalAssets {
		techAssets = append(techAssets, techAsset)
	}
	sort.Sort(types.ByOrderAndIdSort(techAssets))
	for _, technicalAsset := range techAssets {
		dotContent.WriteString(makeTechAssetNode(parsedModel, technicalAsset, false))
		dotContent.WriteString("\n")
	}

	// Data Flows (Technical Communication Links) =========================================================================
	for _, technicalAsset := range techAssets {
		for _, dataFlow := range technicalAsset.CommunicationLinks {
			dotContent.WriteString(dataFlowEdge(parsedModel, technicalAsset, dataFlow))
		}
	}

	diagramInvisibleConnectionsTweaks, err := makeDiagramInvisibleConnectionsTweaks(parsedModel)
	if err != nil {
		return nil, fmt.Errorf("error while making diagram invisible connections tweaks: %w", err)
	}
	dotContent.WriteString(diagramInvisibleConnectionsTweaks)

	diagramSameRankNodeTweaks, err := makeDiagramSameRankNodeTweaks(parsedModel)
	if err != nil {
		return nil, fmt.Errorf("error while making diagram same-rank node tweaks: %w", err)
	}
	dotContent.WriteString(diagramSameRankNodeTweaks)
	dotContent.WriteString("}")

	return writeDOTFile(diagramFilenameDOT, dotContent.String())
}

// writeDOTFile writes the DOT source of a diagram into a file and returns the closed file.
func writeDOTFile(diagramFilenameDOT string, dotContent string) (*os.File, error) {
	// Write the DOT file
	file, err := os.Create(filepath.Clean(diagramFilenameDOT))
	if err != nil {
		return nil, fmt.Errorf("error creating %s: %w", diagramFilenameDOT, err)
	}
	defer func() { _ = file.Close() }()
	_, err = fmt.Fprintln(file, dotContent)
	if err != nil {
		return nil, fmt.Errorf("error writing %s: %w", diagramFilenameDOT, err)
	}
	return file, nil
}

// writeLegendCluster writes a legend cluster of the data-flow diagram with its entries.
func writeLegendCluster(dotContent *strings.Builder, name string, label string, entries ...string) {
	dotContent.WriteString("subgraph " + name + " { \n")
	dotContent.WriteString("  label=\"" + label + "\"; \n")
	dotContent.WriteString("  color=\"lightgrey\"; \n")
	dotContent.WriteString("  style=\"dashed\"; \n")
	for _, entry := range entries {
		dotContent.WriteString(entry)
	}
	dotContent.WriteString("} \n")
}

// writeDataFlowLegend writes the legend clusters of the data-flow diagram.
func writeDataFlowLegend(dotContent *strings.Builder) {
	writeLegendCluster(dotContent, "cluster_shape_legend", "Shape legend",
		makeLegendNode("external_entity_item", "External Entity",
			"0", "black", "box", "solid", "2.0", VeryLightGray, Black),
		makeLegendNode("process_item", "Process",
			"0", "black", "ellipse", "solid", "2.0", VeryLightGray, Black),
		makeLegendNode("datastore_item", "Datastore",
			"0", "black", "cylinder", "solid", "2.0", VeryLightGray, Black),
		makeLegendNode("used_as_client_item", "Used as client",
			"0", "black", "octagon", "solid", "2.0", VeryLightGray, Black),
	)

	writeLegendCluster(dotContent, "cluster_tenant_legend", "Tenant legend",
		makeLegendNode("single_tenant", "Single tenant",
			"0", "black", "box", "solid", "2.0", VeryLightGray, Black),
		makeLegendNode("multi_tenant", "Multitenant",
			"1", "black", "box", "solid", "2.0", VeryLightGray, Black),
	)

	writeAssetColorLegends(dotContent)

	writeLegendCluster(dotContent, "cluster_fill_legend",
		"Shape fill legend (darker for physical machines, brighter for containers and even brighter for serverless)",
		makeLegendNode("invalid_item",
			"No data processed or stored, or using unknown technology, or no communication links",
			"0", "black", "box", "solid", "2.0", LightPink, Black),
		makeLegendNode("internet", "Asset used over the internet",
			"0", "black", "box", "solid", "2.0", ExtremeLightBlue, Black),
		makeLegendNode("out_of_scope", "Out of scope",
			"0", "black", "box", "solid", "2.0", OutOfScopeFancy, Black),
		makeLegendNode("custom_developed_part", "Custom developed part",
			"0", "black", "box", "solid", "2.0", CustomDevelopedParts, Black),
		makeLegendNode("other_assets", "Other assets",
			"0", "black", "box", "solid", "2.0", VeryLightGray, Black),
	)

	writeLegendCluster(dotContent, "cluster_arrow_legend", "Arrow legend"+
		" (an arrow points from the asset that initiates the connection to its target)",
		makeLegendArrow("read_write_link", "Filled arrowhead at the target: read/write link",
			&types.CommunicationLink{DataAssetsSent: []string{"sent"}}),
		makeLegendArrow("readonly_link", "Hollow arrowhead at the target: read-only link",
			&types.CommunicationLink{Readonly: true, DataAssetsReceived: []string{"received"}}),
		makeLegendArrow("bidirectional_link",
			"Double hollow arrowhead at the initiator: data is also received back",
			&types.CommunicationLink{DataAssetsSent: []string{"sent"}, DataAssetsReceived: []string{"received"}}),
	)
}

// writeAssetColorLegends writes the legend clusters of the label colors, border colors and border lines of the
// technical assets.
func writeAssetColorLegends(dotContent *strings.Builder) {
	writeLegendCluster(dotContent, "cluster_label_legend", "Label color legend (integrity)",
		makeLegendNode("mission_critical", "Mission-critical integrity",
			"0", Red, "box", "solid", "2.0", VeryLightGray, Black),
		makeLegendNode("critical", "Critical integrity",
			"0", Amber, "box", "solid", "2.0", VeryLightGray, Black),
		makeLegendNode("other", "Important and lower integrity",
			"0", Black, "box", "solid", "2.0", VeryLightGray, Black),
	)

	writeLegendCluster(dotContent, "cluster_border_color_legend", "Border color legend (confidentiality)",
		makeLegendNode("strictly_confidential", "Strictly confidential",
			"0", Black, "box", "solid", "3.0", VeryLightGray, Red),
		makeLegendNode("confidential", "Confidential",
			"0", Black, "box", "solid", "3.0", VeryLightGray, Amber),
		makeLegendNode("restricted_and_lower", "Restricted and lower",
			"0", Black, "box", "solid", "2.0", VeryLightGray, Black),
	)

	writeLegendCluster(dotContent, "cluster_border_line_legend", "Border line legend",
		makeLegendNode("dotted", "No data processed (model forgery attempt), or out of scope",
			"0", Black, "box", "dotted", "2.0", VeryLightGray, Black),
		makeLegendNode("solid", "Normal", "0", Black, "box", "solid", "2.0", VeryLightGray, Black),
	)
}

// dataFlowGraphAttributes returns the graph, node and edge attributes of the data-flow diagram,
// and whether to draw space lines around the trust boundaries, which depends on the edge layout.
func dataFlowGraphAttributes(parsedModel *types.Model, dpi int, addModelTitle bool) (string, bool, error) {
	// Metadata init ===============================================================================
	tweaks := ""
	if parsedModel.DiagramTweakNodesep > 0 {
		tweaks += "\n		nodesep=\"" + strconv.Itoa(parsedModel.DiagramTweakNodesep) + "\""
	}
	if parsedModel.DiagramTweakRanksep > 0 {
		tweaks += "\n		ranksep=\"" + strconv.Itoa(parsedModel.DiagramTweakRanksep) + "\""
	}
	drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks := true
	splines := "ortho"
	if len(parsedModel.DiagramTweakEdgeLayout) > 0 {
		switch parsedModel.DiagramTweakEdgeLayout {
		case "spline", "polyline", "curved", "false":
			splines = parsedModel.DiagramTweakEdgeLayout
			drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks = false
		case "ortho":
			// the default
		default:
			return "", false, fmt.Errorf("unknown value for diagram_tweak_suppress_edge_labels "+
				"(spline, polyline, ortho, curved, false): %s", parsedModel.DiagramTweakEdgeLayout)
		}
	}
	rankdir := "TB"
	if parsedModel.DiagramTweakLayoutLeftToRight {
		rankdir = "LR"
	}
	modelTitle := ""
	if addModelTitle {
		modelTitle = `label="` + quote(parsedModel.Title) + `"`
	}
	return `	graph [ ` + modelTitle + `
		labelloc=t
		fontname="Verdana"
		fontsize=40
        outputorder="nodesfirst"
		dpi=` + strconv.Itoa(dpi) + `
		splines=` + splines + `
		rankdir="` + rankdir + `"
` + tweaks + `
	];
	node [
		fontname="Verdana"
		fontsize="20"
	];
	edge [
		shape="none"
		fontname="Verdana"
		fontsize="18"
	];
`, drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks, nil
}

// trustBoundarySubgraphs returns the clusters of the trust boundaries in the data-flow diagram,
// the nested ones inside their parents.
func trustBoundarySubgraphs(parsedModel *types.Model, dpi int,
	drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks bool,
) string {
	var subgraphs strings.Builder
	// Trust Boundaries ===============================================================================
	subgraphSnippetsById := make(map[string]string)
	// first create them in memory (see the link replacement below for nested trust boundaries) - otherwise in Go
	// ranging over map is random order
	// range over them in sorted (hence re-producible) way:
	keys := make([]string, 0, len(parsedModel.TrustBoundaries))
	for k := range parsedModel.TrustBoundaries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		trustBoundary := parsedModel.TrustBoundaries[key]
		subgraphSnippetsById[hash(trustBoundary.Id)] = trustBoundarySnippet(parsedModel, trustBoundary, dpi,
			drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks)
	}
	// here replace links and remove from map after replacement (i.e. move snippet into nested)
	for i := range subgraphSnippetsById {
		re := regexp.MustCompile(`LINK-NEEDS-REPLACED-BY-cluster_([0-9]*);`)
		for {
			matches := re.FindStringSubmatch(subgraphSnippetsById[i])
			if len(matches) > 0 {
				embeddedSnippet := " //nested:" + subgraphSnippetsById[matches[1]]
				subgraphSnippetsById[i] = strings.ReplaceAll(subgraphSnippetsById[i], matches[0], embeddedSnippet)
				subgraphSnippetsById[matches[1]] = "" // to something like remove it
			} else {
				break
			}
		}
	}
	// now write them all
	keys = make([]string, 0, len(subgraphSnippetsById))
	for k := range subgraphSnippetsById {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		snippet := subgraphSnippetsById[key]
		subgraphs.WriteString(snippet)
	}
	return subgraphs.String()
}

// trustBoundarySnippet returns the cluster of a trust boundary in the data-flow diagram, with a
// placeholder link for each nested trust boundary.
func trustBoundarySnippet(parsedModel *types.Model, trustBoundary *types.TrustBoundary, dpi int,
	drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks bool,
) string {
	var snippet strings.Builder
	if len(trustBoundary.TechnicalAssetsInside) > 0 || len(trustBoundary.TrustBoundariesNested) > 0 {
		if drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks {
			snippet.WriteString(spaceBoundaryForLayout(trustBoundary, dpi))
		}
		snippet.WriteString("\n subgraph cluster_" + hash(trustBoundary.Id) + " {\n")
		snippet.WriteString(trustBoundaryGraphAttributes(parsedModel, trustBoundary, dpi))
		snippet.WriteString("\n")
		keys := trustBoundary.TechnicalAssetsInside
		sort.Strings(keys)
		for _, technicalAssetInside := range keys {
			// log.Println("About to add technical asset link to trust boundary: ", technicalAssetInside)
			technicalAsset := parsedModel.TechnicalAssets[technicalAssetInside]
			snippet.WriteString(hash(technicalAsset.Id))
			snippet.WriteString(";\n")
		}
		keys = trustBoundary.TrustBoundariesNested
		sort.Strings(keys)
		for _, trustBoundaryNested := range keys {
			// log.Println("About to add nested trust boundary to trust boundary: ", trustBoundaryNested)
			trustBoundaryNested := parsedModel.TrustBoundaries[trustBoundaryNested]
			snippet.WriteString("LINK-NEEDS-REPLACED-BY-cluster_" + hash(trustBoundaryNested.Id))
			snippet.WriteString(";\n")
		}
		snippet.WriteString(" }\n\n")
		if drawSpaceLinesForLayoutUnfortunatelyFurtherSeparatesAllRanks {
			snippet.WriteString(" }\n\n")
		}
	}
	return snippet.String()
}

// spaceBoundaryForLayout returns the opening of the invisible cluster around a trust boundary
// that adds space between the clusters of the data-flow diagram.
func spaceBoundaryForLayout(trustBoundary *types.TrustBoundary, dpi int) string {
	var snippet strings.Builder
	// see https://stackoverflow.com/questions/17247455/how-do-i-add-extra-space-between-clusters?noredirect=1&lq=1
	snippet.WriteString("\n subgraph cluster_space_boundary_for_layout_only_1" + hash(trustBoundary.Id) + " {\n")
	snippet.WriteString(`	graph [
                                              dpi=` + strconv.Itoa(dpi) + `
											  label=<<table border="0" cellborder="0" cellpadding="0" bgcolor="#FFFFFF55"><tr><td><b> ` +
		`</b></td></tr></table>>
											  fontsize="21"
											  style="invis"
											  color="green"
											  fontcolor="green"
											  margin="50.0"
											  penwidth="6.5"
                                              outputorder="nodesfirst"
											];`)
	return snippet.String()
}

// trustBoundaryGraphAttributes returns the graph attributes of the cluster of a trust boundary.
func trustBoundaryGraphAttributes(parsedModel *types.Model, trustBoundary *types.TrustBoundary, dpi int) string {
	color, fontColor, bgColor, style, fontname := rgbHexColorTwilight(), rgbHexColorTwilight() /*"#550E0C"*/, "#FAFAFA",
		"dashed", "Verdana"
	penWidth := 4.5
	if len(trustBoundary.TrustBoundariesNested) > 0 {
		penWidth = 5.5
	}
	if parsedModel.FindParentTrustBoundary(trustBoundary) != nil {
		bgColor = "#F1F1F1"
	}
	if trustBoundary.Type == types.NetworkPolicyNamespaceIsolation {
		fontColor, bgColor = "#222222", "#DFF4FF"
	}
	if trustBoundary.Type == types.ExecutionEnvironment {
		fontColor, bgColor, style = "#555555", "#FFFFF0", lineStyleDotted
	}
	return `	graph [
      dpi=` + strconv.Itoa(dpi) + `
      label=<<table border="0" cellborder="0" cellpadding="0"><tr><td><b>` +
		encode(trustBoundary.Title) + `</b> (` + trustBoundary.Type.String() + `)</td></tr></table>>
      fontsize="21"
      style="` + style + `"
      color="` + color + `"
      bgcolor="` + bgColor + `"
      fontcolor="` + fontColor + `"
      fontname="` + fontname + `"
      penwidth="` + fmt.Sprintf("%f", penWidth) + `"
      forcelabels=true
      outputorder="nodesfirst"
	  margin="50.0"
    ];`
}

// dataFlowEdge returns the edge of a communication link in the data-flow diagram.
func dataFlowEdge(parsedModel *types.Model, technicalAsset *types.TechnicalAsset,
	dataFlow *types.CommunicationLink,
) string {
	var edge strings.Builder
	sourceId := technicalAsset.Id
	targetId := dataFlow.TargetId
	// log.Println("About to add link from", sourceId, "to", targetId, "with id", dataFlow.ID)
	var arrowStyle, arrowColor string
	dir, arrowHead, arrowTail := dataFlowArrows(dataFlow)
	arrowStyle = ` style="` + determineArrowLineStyle(dataFlow) +
		`" penwidth="` + determineArrowPenWidth(dataFlow, parsedModel) +
		`" arrowtail="` + arrowTail + `" arrowhead="` + arrowHead + `" dir="` + dir + `" arrowsize="2.0" `
	arrowColor = ` color="` + determineArrowColor(dataFlow, parsedModel) + `"`
	tweaks := ""
	if dataFlow.DiagramTweakWeight > 0 {
		tweaks += " weight=\"" + strconv.Itoa(dataFlow.DiagramTweakWeight) + "\" "
	}

	edge.WriteString("\n")
	edge.WriteString("  " + hash(sourceId) + " -> " + hash(targetId) +
		` [` + arrowColor + ` ` + arrowStyle + tweaks + ` constraint=` +
		strconv.FormatBool(dataFlow.DiagramTweakConstraint) + ` `)
	if !parsedModel.DiagramTweakSuppressEdgeLabels {
		edge.WriteString(` xlabel="` + encode(dataFlow.Protocol.String()) + `" fontcolor="` +
			determineLabelColor(dataFlow, parsedModel) + `" `)
	}
	edge.WriteString(" ];\n")
	return edge.String()
}

func makeLegendNode(id, title, compartmentBorder, labelColor, shape, borderLineStyle, borderPenWidth, shapeFillColor,
	shapeBorderColor string,
) string {
	return "  " + id + ` [
label=<<table border="0" cellborder="` + compartmentBorder +
		`" cellpadding="2" cellspacing="0"><tr><td><font point-size="15" color="` + DarkBlue + `">list of technologies` +
		`</font><br/><font point-size="15" color="` + LightGray +
		`">technical asset size</font></td></tr><tr><td><b><font color="` + labelColor + `">` + encode(title) +
		`</font></b><br/></td></tr><tr><td>attacker attractiveness level</td></tr></table>>
shape=` + shape + ` style="` + borderLineStyle + `,filled" penwidth="` + borderPenWidth +
		`" fillcolor="` + shapeFillColor + `"
peripheries=1
color="` + shapeBorderColor + "\"\n  ]; "
}

// Arrows:

// receivedBackArrowTail is the arrow at the source of a link that also receives data back. It
// must differ from both arrowheads at the target, the hollow read-only one included, so that the
// end that initiates the connection stays recognisable.
const receivedBackArrowTail = "onormalonormal"

// noArrow is the arrowtail of a one-way link, which dir=forward does not draw anyway.
const noArrow = "none"

// dataFlowArrows returns the dir, arrowhead and arrowtail of a communication link's edge. The
// arrowhead at the target marks the direction in which the source initiates the connection,
// filled for a read/write link and hollow for a read-only one. A link that sends data and also
// receives data back is drawn with dir=both and the hollow receivedBackArrowTail at the source.
// A link that only receives data stays one-way: its arrow still points from the initiator.
// The embedded Graphviz (12.1.2) draws dir=both edges correctly with ortho splines as well, so
// the workaround for https://gitlab.com/graphviz/graphviz/issues/144 is gone.
func dataFlowArrows(dataFlow *types.CommunicationLink) (dir, arrowHead, arrowTail string) {
	arrowHead = "normal"
	if dataFlow.Readonly {
		arrowHead = "empty"
	}
	if dataFlow.IsBidirectional() {
		return "both", arrowHead, receivedBackArrowTail
	}
	return "forward", arrowHead, noArrow
}

// makeLegendArrow draws the arrows of the given link between an initiator node and a target
// node that is labelled with the title.
func makeLegendArrow(id, title string, dataFlow *types.CommunicationLink) string {
	dir, arrowHead, arrowTail := dataFlowArrows(dataFlow)
	node := ` shape=box style="solid,filled" fillcolor="` + VeryLightGray + `" color="` + Black + `"];` + "\n"
	return "  " + id + `_initiator [label="Initiator"` + node +
		"  " + id + `_target [label="` + quote(title) + `"` + node +
		"  " + id + "_initiator -> " + id + `_target [color="` + Black + `" style="solid" penwidth="1.5"` +
		` arrowtail="` + arrowTail + `" arrowhead="` + arrowHead + `" dir="` + dir + `" arrowsize="2.0"];` + "\n"
}

// Pen Widths:

func determineArrowPenWidth(cl *types.CommunicationLink, parsedModel *types.Model) string {
	if determineArrowColor(cl, parsedModel) == Pink {
		return fmt.Sprintf("%f", 3.0)
	}
	if determineArrowColor(cl, parsedModel) != Black {
		return fmt.Sprintf("%f", 2.5)
	}
	return fmt.Sprintf("%f", 1.5)
}

func determineLabelColor(cl *types.CommunicationLink, parsedModel *types.Model) string {
	// This duplicates the risk logic; the generated risks could determine the colour instead.
	/*
		if dataFlow.Protocol.IsEncrypted() {
			return Gray
		} else {*/
	// check for red
	for _, sentDataAsset := range cl.DataAssetsSent {
		if parsedModel.DataAssets[sentDataAsset].Integrity == types.MissionCritical {
			return Red
		}
	}
	for _, receivedDataAsset := range cl.DataAssetsReceived {
		if parsedModel.DataAssets[receivedDataAsset].Integrity == types.MissionCritical {
			return Red
		}
	}
	// check for amber
	for _, sentDataAsset := range cl.DataAssetsSent {
		if parsedModel.DataAssets[sentDataAsset].Integrity == types.Critical {
			return Amber
		}
	}
	for _, receivedDataAsset := range cl.DataAssetsReceived {
		if parsedModel.DataAssets[receivedDataAsset].Integrity == types.Critical {
			return Amber
		}
	}
	// default
	return Gray
}

// lineStyleDotted is the line style of edges, nodes and clusters that look like a model forgery
// attempt, and of execution environments.
const lineStyleDotted = "dotted"

func determineArrowLineStyle(cl *types.CommunicationLink) string {
	if len(cl.DataAssetsSent) == 0 && len(cl.DataAssetsReceived) == 0 {
		// dotted, because it's strange when too many technical communication links transfer no data...
		// some ok, but many in a diagram ist a sign of model forgery...
		return lineStyleDotted
	}
	if cl.Usage == types.DevOps {
		return "dashed"
	}
	return "solid"
}

// pink when model forgery attempt (i.e. nothing being sent and received).
func determineArrowColor(cl *types.CommunicationLink, parsedModel *types.Model) string {
	// This duplicates the risk logic; the generated risks could determine the colour instead.
	if len(cl.DataAssetsSent) == 0 && len(cl.DataAssetsReceived) == 0 ||
		cl.Protocol == types.UnknownProtocol {
		// pink, because it's strange when too many technical communication links transfer no data...
		// some ok, but many in a diagram ist a sign of model forgery...
		return Pink
	}
	switch {
	case cl.Usage == types.DevOps:
		return MiddleLightGray
	case cl.VPN:
		return DarkBlue
	case cl.IpFiltered:
		return Brown
	}
	return dataFlowConfidentialityColor(cl, parsedModel)
}

// dataFlowConfidentialityColor is red when a communication link transfers strictly confidential
// data, amber when it transfers confidential data, and black otherwise.
func dataFlowConfidentialityColor(cl *types.CommunicationLink, parsedModel *types.Model) string {
	confidentialityIs := func(confidentiality types.Confidentiality) func(*types.DataAsset) bool {
		return func(dataAsset *types.DataAsset) bool { return dataAsset.Confidentiality == confidentiality }
	}
	// check for red
	if anyDataAsset(parsedModel, cl.DataAssetsSent, confidentialityIs(types.StrictlyConfidential)) ||
		anyDataAsset(parsedModel, cl.DataAssetsReceived, confidentialityIs(types.StrictlyConfidential)) {
		return Red
	}
	// check for amber
	if anyDataAsset(parsedModel, cl.DataAssetsSent, confidentialityIs(types.Confidential)) ||
		anyDataAsset(parsedModel, cl.DataAssetsReceived, confidentialityIs(types.Confidential)) {
		return Amber
	}
	// default
	return Black
}

// anyDataAsset reports whether one of the data assets with the given ids matches.
func anyDataAsset(parsedModel *types.Model, dataAssetIds []string, matches func(*types.DataAsset) bool) bool {
	for _, dataAssetId := range dataAssetIds {
		if matches(parsedModel.DataAssets[dataAssetId]) {
			return true
		}
	}
	return false
}

func GenerateDataFlowDiagramGraphvizImage(dotFile *os.File, targetDir string,
	dataFlowDiagramFilenamePNG string, progressReporter progressReporter,
) error {
	progressReporter.Info("Rendering data flow diagram input")
	return renderDiagramGraphvizImage(dotFile, filepath.Join(targetDir, dataFlowDiagramFilenamePNG))
}

func makeDiagramSameRankNodeTweaks(parsedModel *types.Model) (string, error) {
	// see https://stackoverflow.com/questions/25734244/how-do-i-place-nodes-on-the-same-level-in-dot
	tweak := ""
	if len(parsedModel.DiagramTweakSameRankAssets) > 0 {
		for _, sameRank := range parsedModel.DiagramTweakSameRankAssets {
			assetIDs := strings.Split(sameRank, ":")
			if len(assetIDs) > 0 {
				tweak += "{ rank=same; "
				for _, id := range assetIDs {
					err := parsedModel.CheckTechnicalAssetExists(id, "diagram tweak same-rank", true)
					if err != nil {
						return "", fmt.Errorf("error while checking technical asset existence: %w", err)
					}
					if len(parsedModel.GetTechnicalAssetTrustBoundaryId(parsedModel.TechnicalAssets[id])) > 0 {
						return "", fmt.Errorf("technical assets (referenced in same rank diagram tweak) "+
							"are inside trust boundaries: %v", parsedModel.DiagramTweakSameRankAssets)
					}
					tweak += " " + hash(id) + "; "
				}
				tweak += " }"
			}
		}
	}
	return tweak, nil
}

func makeDiagramInvisibleConnectionsTweaks(parsedModel *types.Model) (string, error) {
	// see https://stackoverflow.com/questions/2476575/how-to-control-node-placement-in-graphviz-i-e-avoid-edge-crossings
	tweak := ""
	if len(parsedModel.DiagramTweakInvisibleConnectionsBetweenAssets) > 0 {
		for _, invisibleConnections := range parsedModel.DiagramTweakInvisibleConnectionsBetweenAssets {
			assetIDs := strings.Split(invisibleConnections, ":")
			if len(assetIDs) == 2 {
				err := parsedModel.CheckTechnicalAssetExists(assetIDs[0], "diagram tweak connections", true)
				if err != nil {
					return "", fmt.Errorf("error while checking technical asset existence: %w", err)
				}
				err = parsedModel.CheckTechnicalAssetExists(assetIDs[1], "diagram tweak connections", true)
				if err != nil {
					return "", fmt.Errorf("error while checking technical asset existence: %w", err)
				}

				tweak += "\n" + hash(assetIDs[0]) + " -> " + hash(assetIDs[1]) + " [style=invis]; \n"
			}
		}
	}
	return tweak, nil
}

func WriteDataAssetDiagramGraphvizDOT(parsedModel *types.Model, diagramFilenameDOT string, dpi int,
	progressReporter progressReporter,
) (*os.File, error) {
	progressReporter.Info("Writing data asset diagram input")

	var dotContent strings.Builder
	dotContent.WriteString("digraph generatedModel { concentrate=true \n")

	// Metadata init ===============================================================================
	dotContent.WriteString(`	graph [
		dpi=` + strconv.Itoa(dpi) + `
		fontname="Verdana"
		labelloc="c"
		fontsize="20"
		splines=false
		rankdir="LR"
		nodesep=1.0
		ranksep=3.0
        outputorder="nodesfirst"
	];
	node [
		fontcolor="white"
		fontname="Verdana"
		fontsize="20"
	];
	edge [
		shape="none"
		fontname="Verdana"
		fontsize="18"
	];
`)

	// Technical Assets ===============================================================================
	techAssets := make([]*types.TechnicalAsset, 0, len(parsedModel.TechnicalAssets))
	for _, techAsset := range parsedModel.TechnicalAssets {
		techAssets = append(techAssets, techAsset)
	}
	sort.Sort(types.ByOrderAndIdSort(techAssets))
	for _, technicalAsset := range techAssets {
		if len(technicalAsset.DataAssetsStored) > 0 || len(technicalAsset.DataAssetsProcessed) > 0 {
			dotContent.WriteString(makeTechAssetNode(parsedModel, technicalAsset, true))
			dotContent.WriteString("\n")
		}
	}

	// Data Assets ===============================================================================
	dataAssets := make([]*types.DataAsset, 0, len(parsedModel.DataAssets))
	for _, dataAsset := range parsedModel.DataAssets {
		dataAssets = append(dataAssets, dataAsset)
	}

	sortByDataAssetDataBreachProbabilityAndTitle(parsedModel, dataAssets)
	for _, dataAsset := range dataAssets {
		dotContent.WriteString(makeDataAssetNode(parsedModel, dataAsset))
		dotContent.WriteString("\n")
	}

	// Data Asset to Tech Asset links ===============================================================================
	for _, technicalAsset := range techAssets {
		dotContent.WriteString(dataAssetLinks(technicalAsset))
	}

	dotContent.WriteString("}")

	return writeDOTFile(diagramFilenameDOT, dotContent.String())
}

// dataAssetLinks returns the edges of the data asset diagram from the data assets that a
// technical asset stores (solid) or only processes (dashed) to the technical asset.
func dataAssetLinks(technicalAsset *types.TechnicalAsset) string {
	var links strings.Builder
	for _, sourceId := range technicalAsset.DataAssetsStored {
		targetId := technicalAsset.Id
		links.WriteString("\n")
		links.WriteString(hash(sourceId) + " -> " + hash(targetId) +
			` [ color="blue" style="solid" ];`)
		links.WriteString("\n")
	}
	for _, sourceId := range technicalAsset.DataAssetsProcessed {
		if !contains(technicalAsset.DataAssetsStored, sourceId) { // here only if not already drawn above
			targetId := technicalAsset.Id
			links.WriteString("\n")
			links.WriteString(hash(sourceId) + " -> " + hash(targetId) +
				` [ color="#666666" style="dashed" ];`)
			links.WriteString("\n")
		}
	}
	return links.String()
}

func sortByDataAssetDataBreachProbabilityAndTitle(parsedModel *types.Model, assets []*types.DataAsset) {
	sort.Slice(assets, func(i, j int) bool {
		highestDataBreachProbabilityLeft := parsedModel.IdentifiedDataBreachProbability(assets[i])
		highestDataBreachProbabilityRight := parsedModel.IdentifiedDataBreachProbability(assets[j])
		if highestDataBreachProbabilityLeft == highestDataBreachProbabilityRight {
			return assets[i].Title < assets[j].Title
		}
		return highestDataBreachProbabilityLeft > highestDataBreachProbabilityRight
	})
}

func makeDataAssetNode(parsedModel *types.Model, dataAsset *types.DataAsset) string {
	var color string
	switch identifiedDataBreachProbabilityStillAtRisk(parsedModel, dataAsset) {
	case types.Probable:
		color = rgbHexColorHighRisk()
	case types.Possible:
		color = rgbHexColorMediumRisk()
	case types.Improbable:
		color = rgbHexColorLowRisk()
	default:
		color = Gray // since black is too dark here as fill color
	}
	if !isDataBreachPotentialStillAtRisk(parsedModel, dataAsset) {
		color = Gray // since black is too dark here as fill color
	}
	return "  " + hash(dataAsset.Id) + ` [ label=<<b>` + encode(dataAsset.Title) +
		`</b>> penwidth="3.0" style="filled" fillcolor="` + color + `" color="` + color + "\"\n  ]; "
}

// makeSimplifiedTechAssetNode returns the node of a technical asset in the data asset diagram,
// coloured by the highest severity of its risks still at risk.
func makeSimplifiedTechAssetNode(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) string {
	color := rgbHexColorOutOfScope()
	if !technicalAsset.OutOfScope {
		generatedRisks := parsedModel.GeneratedRisks(technicalAsset)
		switch types.HighestSeverityStillAtRisk(generatedRisks) {
		case types.CriticalSeverity:
			color = rgbHexColorCriticalRisk()
		case types.HighSeverity:
			color = rgbHexColorHighRisk()
		case types.ElevatedSeverity:
			color = rgbHexColorElevatedRisk()
		case types.MediumSeverity:
			color = rgbHexColorMediumRisk()
		case types.LowSeverity:
			color = rgbHexColorLowRisk()
		default:
			color = Gray // since black is too dark here as fill color
		}
		if len(types.ReduceToOnlyStillAtRisk(generatedRisks)) == 0 {
			color = Gray // since black is too dark here as fill color
		}
	}
	return "  " + hash(technicalAsset.Id) + ` [ shape="box" style="filled" fillcolor="` + color + `"
				label=<<b>` + encode(technicalAsset.Title) + `</b>> penwidth="3.0" color="` + color + `" ];
				`
}

func makeTechAssetNode(parsedModel *types.Model, technicalAsset *types.TechnicalAsset, simplified bool) string {
	if simplified {
		return makeSimplifiedTechAssetNode(parsedModel, technicalAsset)
	}

	shape, title, lineBreak := techAssetShape(technicalAsset)

	// RAA = Relative Attacker Attractiveness
	raa := technicalAsset.RAA
	var attackerAttractivenessLabel string
	if technicalAsset.OutOfScope {
		attackerAttractivenessLabel = "<font point-size=\"15\" color=\"#603112\">RAA: out of scope</font>"
	} else {
		attackerAttractivenessLabel = "<font point-size=\"15\" color=\"#603112\">RAA: " + fmt.Sprintf("%.0f", raa) +
			" %</font>"
	}

	compartmentBorder := "0"
	if technicalAsset.MultiTenant {
		compartmentBorder = "1"
	}

	return "  " + hash(technicalAsset.Id) + ` [
label=<<table border="0" cellborder="` + compartmentBorder +
		`" cellpadding="2" cellspacing="0"><tr><td><font point-size="15" color="` + DarkBlue + `">` +
		lineBreak + encode(technicalAsset.Technologies.String()) +
		`</font><br/><font point-size="15" color="` + LightGray + `">` + technicalAsset.Size.String() +
		`</font></td></tr><tr><td><b><font color="` + determineTechnicalAssetLabelColor(technicalAsset, parsedModel) + `">` +
		encode(title) + `</font></b><br/></td></tr><tr><td>` + attackerAttractivenessLabel + `</td></tr></table>>
shape=` + shape + ` style="` + determineShapeBorderLineStyle(technicalAsset) + `,` +
		determineShapeStyle(technicalAsset) + `" penwidth="` + determineShapeBorderPenWidth(technicalAsset, parsedModel) +
		`" fillcolor="` + determineShapeFillColor(technicalAsset, parsedModel) + `"
peripheries=` + strconv.Itoa(determineShapePeripheries(technicalAsset)) + `
color="` + determineShapeBorderColor(technicalAsset, parsedModel) + "\"\n  ]; "
}

// techAssetShape returns the shape of the node of a technical asset, its title, and the line
// break that a redundant datastore gets above its technologies.
func techAssetShape(technicalAsset *types.TechnicalAsset) (shape string, title string, lineBreak string) {
	switch technicalAsset.Type {
	case types.ExternalEntity:
		shape = "box"
		title = technicalAsset.Title
	case types.Process:
		shape = "ellipse"
		title = technicalAsset.Title
	case types.Datastore:
		shape = "cylinder"
		title = technicalAsset.Title
		if technicalAsset.Redundant {
			lineBreak = "<br/>"
		}
	}

	if technicalAsset.UsedAsClientByHuman {
		shape = "octagon"
	}
	return shape, title, lineBreak
}

func determineShapeStyle(ta *types.TechnicalAsset) string {
	return "filled"
}

func determineShapeFillColor(ta *types.TechnicalAsset, parsedModel *types.Model) string {
	fillColor := VeryLightGray
	switch {
	case (len(ta.DataAssetsProcessed) == 0 && len(ta.DataAssetsStored) == 0) || ta.Technologies.IsUnknown():
		// lightPink, because it's strange when too many technical assets process no data...
		// some ok, but many in a diagram ist a sign of model forgery...
		fillColor = LightPink
	case len(ta.CommunicationLinks) == 0 &&
		len(parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[ta.Id]) == 0:
		fillColor = LightPink
	case ta.Internet:
		fillColor = ExtremeLightBlue
	case ta.OutOfScope:
		fillColor = OutOfScopeFancy
	case ta.CustomDevelopedParts:
		fillColor = CustomDevelopedParts
	}
	return machineFillColor(fillColor, ta.Machine)
}

// machineFillColor darkens a fill colour for physical machines and brightens it for containers,
// and even more for serverless.
func machineFillColor(fillColor string, machine types.TechnicalAssetMachine) string {
	switch machine {
	case types.Physical:
		fillColor = darkenHexColor(fillColor)
	case types.Container:
		fillColor = brightenHexColor(fillColor)
	case types.Serverless:
		fillColor = brightenHexColor(brightenHexColor(fillColor))
	case types.Virtual:
	}
	return fillColor
}

func determineShapeBorderPenWidth(ta *types.TechnicalAsset, parsedModel *types.Model) string {
	if determineShapeBorderColor(ta, parsedModel) == Pink {
		return fmt.Sprintf("%f", 3.5)
	}
	if determineShapeBorderColor(ta, parsedModel) != Black {
		return fmt.Sprintf("%f", 3.0)
	}
	return fmt.Sprintf("%f", 2.0)
}

// red when mission-critical integrity, but still unauthenticated (non-readonly) channels access it
// amber when critical integrity, but still unauthenticated (non-readonly) channels access it
// pink when model forgery attempt (i.e. nothing being processed).
func determineShapeBorderColor(ta *types.TechnicalAsset, parsedModel *types.Model) string {
	// Check for red
	if ta.Confidentiality == types.StrictlyConfidential {
		return Red
	}
	for _, processedDataAsset := range ta.DataAssetsProcessed {
		if parsedModel.DataAssets[processedDataAsset].Confidentiality == types.StrictlyConfidential {
			return Red
		}
	}
	// Check for amber
	if ta.Confidentiality == types.Confidential {
		return Amber
	}
	for _, processedDataAsset := range ta.DataAssetsProcessed {
		if parsedModel.DataAssets[processedDataAsset].Confidentiality == types.Confidential {
			return Amber
		}
	}
	return Black
}

func determineShapePeripheries(ta *types.TechnicalAsset) int {
	if ta.Redundant {
		return 2
	}
	return 1
}

// dotted when model forgery attempt (i.e. nothing being processed or stored).
func determineShapeBorderLineStyle(ta *types.TechnicalAsset) string {
	if len(ta.DataAssetsProcessed) == 0 || ta.OutOfScope {
		// dotted, because it's strange when too many technical communication links transfer no data...
		// some ok, but many in a diagram ist a sign of model forgery...
		return lineStyleDotted
	}
	return "solid"
}

// red when >= confidential data stored in unencrypted technical asset.
func determineTechnicalAssetLabelColor(ta *types.TechnicalAsset, model *types.Model) string {
	integrityIs := func(integrity types.Criticality) func(*types.DataAsset) bool {
		return func(dataAsset *types.DataAsset) bool { return dataAsset.Integrity == integrity }
	}
	// Check for red
	if ta.Integrity == types.MissionCritical ||
		anyDataAsset(model, ta.DataAssetsStored, integrityIs(types.MissionCritical)) ||
		anyDataAsset(model, ta.DataAssetsProcessed, integrityIs(types.MissionCritical)) {
		return Red
	}
	// Check for amber
	if ta.Integrity == types.Critical ||
		anyDataAsset(model, ta.DataAssetsStored, integrityIs(types.Critical)) ||
		anyDataAsset(model, ta.DataAssetsProcessed, integrityIs(types.Critical)) {
		return Amber
	}
	return Black
}

func GenerateDataAssetDiagramGraphvizImage(dotFile *os.File, targetDir string,
	dataAssetDiagramFilenamePNG string, progressReporter progressReporter,
) error {
	progressReporter.Info("Rendering data asset diagram input")
	return renderDiagramGraphvizImage(dotFile, filepath.Join(targetDir, dataAssetDiagramFilenamePNG))
}

func renderDiagramGraphvizImage(dotFile *os.File, pngFile string) error {
	inputDOT, err := os.ReadFile(dotFile.Name())
	if err != nil {
		return fmt.Errorf("error reading %s: %w", dotFile.Name(), err)
	}
	inputPNG, err := renderDiagramPNG(inputDOT)
	if err != nil {
		return fmt.Errorf("error rendering %s: %w", dotFile.Name(), err)
	}
	err = os.WriteFile(filepath.Clean(pngFile), inputPNG, 0o600) // #nosec G703
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", pngFile, err)
	}
	return nil
}

func hash(s string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return strconv.FormatUint(uint64(h.Sum32()), 10)
}

// htmlLabelEscaper escapes text for Graphviz HTML-like labels (label=<...>).
var htmlLabelEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")

// encode escapes model text for an HTML-like label, so that titles with <, > or quotes neither
// break the DOT source nor inject markup into the label.
func encode(value string) string {
	return htmlLabelEscaper.Replace(value)
}

// quotedLabelEscaper escapes text for Graphviz double-quoted strings (label="...").
var quotedLabelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", "")

// quote escapes model text for a double-quoted DOT string.
func quote(value string) string {
	return quotedLabelEscaper.Replace(value)
}
