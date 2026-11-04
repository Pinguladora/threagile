package report

import (
	"slices"
	"strconv"
	"strings"

	"github.com/Pinguladora/threagile/pkg/types"
)

// The diagrams of the Markdown report are Mermaid flowcharts, which GitHub, GitLab, MkDocs
// Material and Docusaurus (with its Mermaid theme) render from a mermaid code block. They keep
// to the syntax that Mermaid has had since version 9: quoted labels, the classic node shapes,
// subgraphs with an id and a title, and classDef.

// mermaidIndent indents the statements of a diagram, and each level of subgraphs once more.
const mermaidIndent = "    "

// mermaidOutOfScope is the class of the technical assets out of scope, drawn with a dashed border.
const mermaidOutOfScope = "outOfScope"

// mermaidEscaper escapes model text for a quoted Mermaid label with Mermaid's entity codes, so
// that it neither ends the label nor the statement (" ; #), starts Markdown in it (`), or
// becomes HTML (< > &). A label is written on one line, which keeps it in its code block too.
var mermaidEscaper = strings.NewReplacer(
	"#", "#35;", ";", "#59;", `"`, "#quot;", "`", "#96;", "<", "#lt;", ">", "#gt;", "&", "#amp;", "|", "#124;",
)

// mermaidLabel is model text as a quoted Mermaid label.
func mermaidLabel(text string) string {
	label := mermaidEscaper.Replace(strings.TrimSpace(collapseSpace(text)))
	if label == "" {
		label = " " // Mermaid reads "" as no label at all
	}
	return `"` + label + `"`
}

// mermaidNodeIDs makes the node ids of the objects of a kind from their ids in the model: the
// prefix and the hash of the id, which only holds letters, digits and underscores whatever the
// model holds, and stays the same when other objects change. A hash that two ids share gets a
// suffix for the latter of them by id.
func mermaidNodeIDs(prefix string, ids []string) map[string]string {
	nodeIDs := make(map[string]string, len(ids))
	used := make(map[string]bool, len(ids))
	for _, id := range slices.Sorted(slices.Values(ids)) {
		nodeID := prefix + hash(id)
		for count := 2; used[nodeID]; count++ {
			nodeID = prefix + hash(id) + "_" + strconv.Itoa(count)
		}
		used[nodeID] = true
		nodeIDs[id] = nodeID
	}
	return nodeIDs
}

// mermaidNode is the node of a technical asset in the shape of its type, as in the PNG diagram:
// a box for an external entity, a stadium for a process (an ellipse there), a cylinder for a
// datastore, and a hexagon (an octagon there) for a client used by a human.
func mermaidNode(nodeID string, asset *types.TechnicalAsset) string {
	label := mermaidLabel(asset.Title)
	switch {
	case asset.UsedAsClientByHuman:
		return nodeID + "{{" + label + "}}"
	case asset.Type == types.Process:
		return nodeID + "([" + label + "])"
	case asset.Type == types.Datastore:
		return nodeID + "[(" + label + ")]"
	default:
		return nodeID + "[" + label + "]"
	}
}

// mermaidDiagram collects the statements of a flowchart.
type mermaidDiagram struct {
	lines      []string
	outOfScope []string // the node ids of the technical assets out of scope
}

func (what *mermaidDiagram) add(depth int, statement string) {
	what.lines = append(what.lines, strings.Repeat(mermaidIndent, depth)+statement)
}

// finish adds the class of the assets out of scope and returns the statements.
func (what *mermaidDiagram) finish() []string {
	if len(what.outOfScope) > 0 {
		what.add(1, "classDef "+mermaidOutOfScope+" stroke-dasharray: 5 5")
		what.add(1, "class "+strings.Join(what.outOfScope, ",")+" "+mermaidOutOfScope)
	}
	return what.lines
}

// mermaidDataFlowDiagram is the data-flow diagram: a node for each technical asset, the trust
// boundaries as subgraphs, nested as in the model, and an edge for each communication link from
// the asset that initiates it to its target, labelled with the protocol. A link that also
// receives data back is a thick arrow (==>), which keeps its direction, where the PNG diagram
// gives it a second arrowhead at the initiator.
func mermaidDataFlowDiagram(parsedModel *types.Model) []string {
	diagram := &mermaidDataFlow{
		model:     parsedModel,
		assetIDs:  mermaidNodeIDs("ta_", parsedModel.SortedTechnicalAssetIDs()),
		drawn:     make(map[string]bool),
		boundary:  make(map[string]bool),
		direction: "TB",
	}
	if parsedModel.DiagramTweakLayoutLeftToRight {
		diagram.direction = "LR"
	}
	return diagram.draw()
}

type mermaidDataFlow struct {
	mermaidDiagram
	model       *types.Model
	assetIDs    map[string]string
	boundaryIDs map[string]string
	drawn       map[string]bool // the technical assets drawn
	boundary    map[string]bool // the trust boundaries drawn
	direction   string
}

func (what *mermaidDataFlow) draw() []string {
	what.add(0, "flowchart "+what.direction)
	boundaryIDs := make([]string, 0, len(what.model.TrustBoundaries))
	for id := range what.model.TrustBoundaries {
		boundaryIDs = append(boundaryIDs, id)
	}
	what.boundaryIDs = mermaidNodeIDs("tb_", boundaryIDs)
	for _, id := range slices.Sorted(slices.Values(boundaryIDs)) {
		if boundary := what.model.TrustBoundaries[id]; what.model.FindParentTrustBoundary(boundary) == nil {
			what.trustBoundary(boundary, 1)
		}
	}
	for _, id := range what.model.SortedTechnicalAssetIDs() {
		what.asset(id, 1)
	}
	for _, id := range what.model.SortedTechnicalAssetIDs() {
		for _, link := range what.model.TechnicalAssets[id].CommunicationLinksSorted() {
			what.link(link)
		}
	}
	return what.finish()
}

// trustBoundary adds the subgraph of a trust boundary with the assets and boundaries inside;
// one with nothing inside is left out, as in the PNG diagram.
func (what *mermaidDataFlow) trustBoundary(boundary *types.TrustBoundary, depth int) {
	if what.boundary[boundary.Id] || !what.holdsAssets(boundary, make(map[string]bool)) {
		return
	}
	what.boundary[boundary.Id] = true
	what.add(depth, "subgraph "+what.boundaryIDs[boundary.Id]+" ["+
		mermaidLabel(boundary.Title+" ("+boundary.Type.String()+")")+"]")
	for _, id := range sortedCopy(boundary.TechnicalAssetsInside) {
		what.asset(id, depth+1)
	}
	for _, id := range sortedCopy(boundary.TrustBoundariesNested) {
		if nested, ok := what.model.TrustBoundaries[id]; ok {
			what.trustBoundary(nested, depth+1)
		}
	}
	what.add(depth, "end")
}

// holdsAssets tells whether a trust boundary or one nested in it holds an asset not yet drawn.
func (what *mermaidDataFlow) holdsAssets(boundary *types.TrustBoundary, seen map[string]bool) bool {
	if seen[boundary.Id] {
		return false
	}
	seen[boundary.Id] = true
	for _, id := range boundary.TechnicalAssetsInside {
		if _, ok := what.model.TechnicalAssets[id]; ok && !what.drawn[id] {
			return true
		}
	}
	for _, id := range boundary.TrustBoundariesNested {
		if nested, ok := what.model.TrustBoundaries[id]; ok && !what.boundary[id] && what.holdsAssets(nested, seen) {
			return true
		}
	}
	return false
}

// asset adds the node of a technical asset unless it is drawn already.
func (what *mermaidDataFlow) asset(id string, depth int) {
	asset, ok := what.model.TechnicalAssets[id]
	if !ok || what.drawn[id] {
		return
	}
	what.drawn[id] = true
	what.add(depth, mermaidNode(what.assetIDs[id], asset))
	if asset.OutOfScope {
		what.outOfScope = append(what.outOfScope, what.assetIDs[id])
	}
}

func (what *mermaidDataFlow) link(link *types.CommunicationLink) {
	source, target := what.assetIDs[link.SourceId], what.assetIDs[link.TargetId]
	if !what.drawn[link.SourceId] || !what.drawn[link.TargetId] {
		return
	}
	arrow := "-->"
	if link.IsBidirectional() {
		arrow = "==>"
	}
	if !what.model.DiagramTweakSuppressEdgeLabels {
		arrow += "|" + mermaidLabel(link.Protocol.String()) + "|"
	}
	what.add(1, source+" "+arrow+" "+target)
}

// mermaidDataStorageDiagram is the smaller one of the data mapping: an edge from each data asset
// to each technical asset that stores it. Where data is processed as well, edges for all of
// that made the data mapping of the example model a tangle of over 50 crossing edges; the table
// of the chapter shows both.
func mermaidDataStorageDiagram(parsedModel *types.Model, dataAssets []viewDataAsset) []string {
	dataIDs := make([]string, 0, len(dataAssets))
	for _, asset := range dataAssets {
		dataIDs = append(dataIDs, asset.Asset.Id)
	}
	dataNodeIDs := mermaidNodeIDs("da_", dataIDs)
	assetNodeIDs := mermaidNodeIDs("ta_", parsedModel.SortedTechnicalAssetIDs())

	diagram := new(mermaidDiagram)
	diagram.add(0, "flowchart LR")
	edges, stores := make([]string, 0), make(map[string]bool)
	for _, dataAsset := range dataAssets {
		storedBy := parsedModel.StoredByTechnicalAssetsSorted(dataAsset.Asset)
		if len(storedBy) == 0 {
			continue
		}
		diagram.add(1, dataNodeIDs[dataAsset.Asset.Id]+"(["+mermaidLabel(dataAsset.Asset.Title)+"])")
		for _, asset := range storedBy {
			edges = append(edges, dataNodeIDs[dataAsset.Asset.Id]+" --> "+assetNodeIDs[asset.Id])
			stores[asset.Id] = true
		}
	}
	if len(edges) == 0 {
		return nil
	}
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		if asset := parsedModel.TechnicalAssets[id]; stores[id] {
			diagram.add(1, assetNodeIDs[id]+"["+mermaidLabel(asset.Title)+"]")
			if asset.OutOfScope {
				diagram.outOfScope = append(diagram.outOfScope, assetNodeIDs[id])
			}
		}
	}
	for _, edge := range edges {
		diagram.add(1, edge)
	}
	return diagram.finish()
}

// mermaid writes a Mermaid code block.
func (what *markdownWriter) mermaid(statements []string) {
	what.block(slices.Concat([]string{"```mermaid"}, statements, []string{"```"})...)
}

func (what *markdownWriter) dataFlowDiagram(view *reportView) {
	what.paragraph("The following diagram was generated by Threagile based on the model input and gives a " +
		"high-level overview of the data-flow between technical assets. The RAA value of each asset, the calculated " +
		muted("Relative Attacker Attractiveness") + " in percent, is in the chapter " +
		what.linked("RAA Analysis", "raa") + ".")
	if len(view.Model.TechnicalAssets) == 0 {
		what.paragraph(muted("The model has no technical assets to draw."))
		return
	}
	what.mermaid(mermaidDataFlowDiagram(view.Model))
	what.paragraph("Data-flow diagram of " + quoted(view.Title) + ". A box is an external entity, a stadium a " +
		"process, a cylinder a datastore and a hexagon a client used by a human; assets out of scope have a dashed " +
		"border, and the trust boundaries enclose the assets inside them. An arrow points from the asset that " +
		"initiates a communication link to its target and names the protocol; a thick arrow is a link that also " +
		"receives data back.")
}

func (what *markdownWriter) dataMapping(view *reportView) {
	what.paragraph("The following table and diagram were generated by Threagile based on the model input and give a " +
		"high-level distribution of data assets across technical assets, with the data breach probability still at " +
		"risk of each data asset (see the chapter " +
		what.linked("Identified Data Breach Probabilities by Data Asset", "data-assets") + ").")
	rows := make([][]string, 0, len(view.DataAssets))
	for _, asset := range view.DataAssets {
		breach := viewNone
		if asset.Breach != nil {
			breach = asset.Breach.Title
		}
		rows = append(rows, []string{
			what.linked(markdownText(asset.Asset.Title), asset.Anchor), breach,
			what.refs(asset.StoredBy), what.refs(asset.ProcessedBy),
		})
	}
	what.table([]markdownColumn{
		{"Data asset", false},
		{"Data breach", false},
		{"Stored by", false},
		{"Processed by", false},
	}, rows...)
	statements := mermaidDataStorageDiagram(view.Model, view.DataAssets)
	if statements == nil {
		what.paragraph(muted("No technical asset stores a data asset."))
		return
	}
	what.paragraph("The diagram shows where the data assets are stored: an arrow points from a data asset, a " +
		"stadium, to each technical asset that stores it, a box; assets out of scope have a dashed border.")
	what.mermaid(statements)
}
