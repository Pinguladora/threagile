package report

import (
	"fmt"
	"html/template"
	"strconv"
	"strings"
	"time"

	"github.com/Pinguladora/threagile/pkg/types"
)

// htmlReport is what the HTML report template shows: the model's own objects where the template
// only prints their fields, and views where the report selects, sorts or counts.
type htmlReport struct {
	Model                 *types.Model
	CSS                   template.CSS
	ContentSecurityPolicy string
	Title                 string
	Author                htmlAuthor
	Contributors          []htmlAuthor
	Date                  string
	Run                   HTMLReportOptions
	ExecutionTimestamp    string
	Generated             string
	Sections              []htmlSection
	sectionShown          map[string]bool

	BusinessCriticality []htmlChoice
	Summary             htmlSummary
	InitialImpact       htmlImpact
	RemainingImpact     htmlImpact
	Mitigation          []htmlMitigationRow
	RisksBySeverity     []htmlSeverityRisks
	TrackedRisks        []*htmlRisk
	DataFlowDiagram     template.HTML
	DataAssetDiagram    template.HTML

	SecurityRequirements []htmlTitledText
	AbuseCases           []htmlTitledText
	Questions            []htmlQuestion
	UnansweredQuestions  int
	Tags                 []htmlTag
	STRIDE               []htmlRiskGroup
	Functions            []htmlRiskGroup
	RAA                  []htmlRAAEntry
	OutOfScope           []htmlOutOfScope
	ModelFailures        htmlImpact

	Categories         []htmlCategory
	TechnicalAssets    []htmlTechnicalAsset
	DataAssets         []htmlDataAsset
	TrustBoundaries    []htmlTrustBoundary
	SharedRuntimes     []htmlSharedRuntime
	CommunicationLinks []htmlCommunicationLink
	RiskRules          []htmlRiskRule
	Confidentiality    []htmlRating
	Criticality        []htmlRating
}

// htmlAuthor is the author or a contributor of the model.
type htmlAuthor struct {
	Name     string
	Contact  string
	Homepage string // empty unless it is an http(s) URL
}

func newHTMLAuthor(author *types.Author) htmlAuthor {
	if author == nil {
		return htmlAuthor{}
	}
	return htmlAuthor{Name: author.Name, Contact: author.Contact, Homepage: authorHomepage(author.Homepage)}
}

// htmlQuestionsTitle is the title of the chapter of the questions, which the PDF report has too.
const htmlQuestionsTitle = "Questions"

type htmlSection struct {
	ID    string
	Title string
}

// htmlRef refers to an object of the model in the report; without an anchor it is plain text.
type htmlRef struct {
	Anchor string
	Title  string
}

// htmlLevel is a severity, status or probability, shown as text in the colour of its class.
type htmlLevel struct {
	Title string
	Class string
}

type htmlCount struct {
	Level htmlLevel
	Count int
}

type htmlChoice struct {
	Title    string
	Selected bool
}

type htmlTitledText struct {
	Title string
	Text  template.HTML
}

var (
	htmlSeverities = []types.RiskSeverity{
		types.CriticalSeverity, types.HighSeverity, types.ElevatedSeverity, types.MediumSeverity, types.LowSeverity,
	}
	htmlStatuses = []types.RiskStatus{
		types.Unchecked, types.InDiscussion, types.Accepted, types.InProgress, types.Mitigated, types.FalsePositive,
	}
	htmlFunctions = []types.RiskFunction{types.BusinessSide, types.Architecture, types.Development, types.Operations}
	htmlSTRIDE    = []types.STRIDE{
		types.Spoofing, types.Tampering, types.Repudiation, types.InformationDisclosure, types.DenialOfService,
		types.ElevationOfPrivilege,
	}
)

func newHTMLReport(parsedModel *types.Model, options HTMLReportOptions) *htmlReport {
	report := &htmlReport{
		Model:                 parsedModel,
		CSS:                   template.CSS(htmlReportCSS), // #nosec G203 -- the embedded style sheet
		ContentSecurityPolicy: htmlContentSecurityPolicy(htmlReportCSS),
		Title:                 parsedModel.Title,
		Date:                  reportDate(parsedModel).Format("2 January 2006"),
		Run:                   options,
	}
	now := types.Now()
	report.ExecutionTimestamp, report.Generated = now.Format("20060102150405"), now.Format(time.RFC3339)
	report.Author = newHTMLAuthor(parsedModel.Author)
	for _, contributor := range parsedModel.Contributors {
		if contributor != nil {
			report.Contributors = append(report.Contributors, newHTMLAuthor(contributor))
		}
	}
	risks := newHTMLRisks(parsedModel)
	report.addSummary(parsedModel, risks)
	report.addModelChapters(parsedModel)
	report.addRiskChapters(parsedModel, risks)
	report.addAssetChapters(parsedModel, risks)
	report.RiskRules = htmlRiskRules(parsedModel, options)
	report.Confidentiality, report.Criticality = htmlRatings()
	report.Sections = report.sections(options)
	report.sectionShown = make(map[string]bool)
	for _, section := range report.Sections {
		report.sectionShown[section.ID] = true
	}
	return report
}

// Shows tells whether the chapter of the id is in the report.
func (what *htmlReport) Shows(id string) bool {
	return what.sectionShown[id]
}

func (what *htmlReport) sections(options HTMLReportOptions) []htmlSection {
	optional := map[string]bool{
		"remaining-risks":       len(what.RemainingImpact.Entries) > 0 || !options.HideEmptyChapters,
		"asset-register":        !options.HideChapters[AssetRegister],
		"security-requirements": len(what.SecurityRequirements) > 0,
		"abuse-cases":           len(what.AbuseCases) > 0,
		"tags":                  len(what.Tags) > 0,
		"questions":             len(what.Questions) > 0,
		"risk-rules":            !options.HideChapters[RiskRulesCheckedByThreagile],
	}
	all := []htmlSection{
		{"management-summary", "Management Summary"},
		{"initial-risks", "Impact Analysis of the Initial Risks"},
		{"risk-mitigation", "Risk Mitigation"},
		{"remaining-risks", "Impact Analysis of the Remaining Risks"},
		{"risks-by-severity", "Risks by Severity"},
		{"application-overview", "Application Overview"},
		{"data-flow-diagram", "Data-Flow Diagram"},
		{"asset-register", "Asset Register"},
		{"security-requirements", "Security Requirements"},
		{"abuse-cases", "Abuse Cases"},
		{"tags", "Tag Listing"},
		{"stride", "STRIDE Classification of Identified Risks"},
		{"functions", "Assignment by Function"},
		{"raa", "RAA Analysis"},
		{"data-mapping", "Data Mapping"},
		{"out-of-scope-assets", "Out-of-Scope Assets"},
		{"model-failures", "Potential Model Failures"},
		{"questions", htmlQuestionsTitle},
		{"risk-categories", "Identified Risks by Vulnerability Category"},
		{"technical-assets", "Identified Risks by Technical Asset"},
		{"data-assets", "Identified Data Breach Probabilities by Data Asset"},
		{"trust-boundaries", "Trust Boundaries"},
		{"shared-runtimes", "Shared Runtimes"},
		{"communication-links", "Communication Links"},
		{"risk-tracking", "Risk Tracking"},
		{"risk-rules", "Risk Rules Checked by Threagile"},
		{"ratings", "Ratings"},
		{"disclaimer", "Disclaimer"},
	}
	sections := make([]htmlSection, 0, len(all))
	for _, section := range all {
		if shown, isOptional := optional[section.ID]; shown || !isOptional {
			sections = append(sections, section)
		}
	}
	return sections
}

func reportDate(parsedModel *types.Model) types.Date {
	if parsedModel.Date.IsZero() {
		return types.Date{Time: types.Now()}
	}
	return parsedModel.Date
}

// authorHomepage is the homepage as a link, with https:// added as the AsciiDoc report does.
func authorHomepage(homepage string) string {
	homepage = strings.TrimSpace(homepage)
	if homepage == "" {
		return ""
	}
	if !strings.HasPrefix(homepage, "http") {
		homepage = "https://" + homepage
	}
	link, _ := httpLink(homepage)
	return link
}

// htmlAnchor makes the id of an element for an object of the model. Model ids only hold letters,
// digits and hyphens, but risk ids hold more, so any other character is written as _ and its
// code in hex: the anchors stay unique and need no escaping in a URL.
func htmlAnchor(kind, id string) string {
	var anchor strings.Builder
	anchor.WriteString(kind + "-")
	for _, b := range []byte(id) {
		if b == '-' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
			anchor.WriteByte(b)
		} else {
			_, _ = fmt.Fprintf(&anchor, "_%02x", b)
		}
	}
	return anchor.String()
}

func severityLevel(severity types.RiskSeverity) htmlLevel {
	return htmlLevel{Title: severity.Title(), Class: "sev-" + severity.String()}
}

func statusLevel(status types.RiskStatus) htmlLevel {
	return htmlLevel{Title: status.Title(), Class: "status-" + status.String()}
}

// highestSeverityStillAtRisk is the level of the highest severity of the risks still at risk,
// nil for none.
func highestSeverityStillAtRisk(risks []*types.Risk) *htmlLevel {
	if len(types.ReduceToOnlyStillAtRisk(risks)) == 0 {
		return nil
	}
	level := severityLevel(types.HighestSeverityStillAtRisk(risks))
	return &level
}

func refTechnicalAsset(parsedModel *types.Model, id string) htmlRef {
	if asset, ok := parsedModel.TechnicalAssets[id]; ok {
		return htmlRef{Anchor: htmlAnchor("asset", id), Title: asset.Title}
	}
	return htmlRef{Title: id}
}

func refDataAsset(parsedModel *types.Model, id string) htmlRef {
	if asset, ok := parsedModel.DataAssets[id]; ok {
		return htmlRef{Anchor: htmlAnchor("data-asset", id), Title: asset.Title}
	}
	return htmlRef{Title: id}
}

func refTrustBoundary(parsedModel *types.Model, id string) htmlRef {
	if boundary, ok := parsedModel.TrustBoundaries[id]; ok {
		return htmlRef{Anchor: htmlAnchor("trust-boundary", id), Title: boundary.Title}
	}
	return htmlRef{Title: id}
}

func refSharedRuntime(parsedModel *types.Model, id string) htmlRef {
	if runtime, ok := parsedModel.SharedRuntimes[id]; ok {
		return htmlRef{Anchor: htmlAnchor("shared-runtime", id), Title: runtime.Title}
	}
	return htmlRef{Title: id}
}

func refCommunicationLink(link *types.CommunicationLink) htmlRef {
	return htmlRef{Anchor: htmlAnchor("link", link.Id), Title: link.Title}
}

func refCategory(category *types.RiskCategory) htmlRef {
	return htmlRef{Anchor: htmlAnchor("category", category.ID), Title: category.Title}
}

func refs[T any](values []T, ref func(T) htmlRef) []htmlRef {
	result := make([]htmlRef, 0, len(values))
	for _, value := range values {
		result = append(result, ref(value))
	}
	return result
}

func refsOfIDs(parsedModel *types.Model, ids []string, ref func(*types.Model, string) htmlRef) []htmlRef {
	return refs(ids, func(id string) htmlRef { return ref(parsedModel, id) })
}

func formatRAA(asset *types.TechnicalAsset) string {
	if asset.OutOfScope {
		return "out of scope"
	}
	return strconv.FormatFloat(asset.RAA, 'f', 0, 64) + " %"
}
