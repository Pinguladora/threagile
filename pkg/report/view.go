package report

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Pinguladora/threagile/pkg/baseline"
	"github.com/Pinguladora/threagile/pkg/types"
)

// ReportOptions are the inputs of the HTML and Markdown reports besides the model.
type ReportOptions struct {
	ModelFilename    string
	ModelHash        string
	BuildTimestamp   string
	ThreagileVersion string
	IntroTextRAA     string
	SkipRiskRules    []string
	RiskRules        types.RiskRules
	CustomRiskRules  types.RiskRules
	HideChapters     map[ChaptersToShowHide]bool
	// HideEmptyChapters leaves out the chapter of the remaining risks when there are none; the
	// optional chapters of the model are left out when empty anyway.
	HideEmptyChapters bool
	// Baseline compares the risks with those of an earlier analysis; nil when there is none to compare with.
	Baseline *baseline.Comparison
}

// markupText is text that may carry threagile's basic markup (see basicMarkup). The view keeps
// it as it is, as each report turns it into its own format.
type markupText string

// reportView is what the HTML and Markdown reports show, in the same chapters: the model's own
// objects where a report only prints their fields, and views where it selects, sorts or counts.
type reportView struct {
	Model              *types.Model
	Title              string
	Author             viewAuthor
	Contributors       []viewAuthor
	Date               string
	Run                ReportOptions
	ExecutionTimestamp string
	Generated          string
	Sections           []viewSection
	sectionShown       map[string]bool

	ManagementSummaryComment markupText
	BusinessOverview         *markupText // nil when the model has none, as is TechnicalOverview
	TechnicalOverview        *markupText
	IntroTextRAA             markupText

	BusinessCriticality []viewChoice
	Summary             viewSummary
	InitialImpact       viewImpact
	RemainingImpact     viewImpact
	Mitigation          []viewMitigationRow
	RisksBySeverity     []viewSeverityRisks
	Baseline            *viewBaseline // nil when the risks are not compared with a baseline
	TrackedRisks        []*viewRisk

	SecurityRequirements []viewTitledText
	AbuseCases           []viewTitledText
	Questions            []viewQuestion
	UnansweredQuestions  int
	Tags                 []viewTag
	STRIDE               []viewRiskGroup
	Functions            []viewRiskGroup
	RAA                  []viewRAAEntry
	OutOfScope           []viewOutOfScope
	ModelFailures        viewImpact

	Categories         []viewCategory
	TechnicalAssets    []viewTechnicalAsset
	DataAssets         []viewDataAsset
	TrustBoundaries    []viewTrustBoundary
	SharedRuntimes     []viewSharedRuntime
	DecisionPoints     []viewDecisionPoint
	CommunicationLinks []viewCommunicationLink
	RiskRules          []viewRiskRule
	Catalogs           []viewCatalog
	Confidentiality    []viewRating
	Criticality        []viewRating
}

// viewAuthor is the author or a contributor of the model.
type viewAuthor struct {
	Name     string
	Contact  string
	Homepage string // empty unless it is an http(s) URL
}

func newViewAuthor(author *types.Author) viewAuthor {
	if author == nil {
		return viewAuthor{}
	}
	return viewAuthor{Name: author.Name, Contact: author.Contact, Homepage: authorHomepage(author.Homepage)}
}

// viewQuestionsTitle is the title of the chapter of the questions, which the PDF report has too.
const viewQuestionsTitle = "Questions"

type viewSection struct {
	ID    string
	Title string
}

// viewRef refers to an object of the model in the report; without an anchor it is plain text.
type viewRef struct {
	Anchor string
	Title  string
}

// viewLevel is a severity, status or probability, always shown as text; the HTML report also
// shows it in the colour of its class.
type viewLevel struct {
	Title string
	Class string
}

type viewCount struct {
	Level viewLevel
	Count int
}

type viewChoice struct {
	Title    string
	Selected bool
}

type viewTitledText struct {
	Title string
	Text  markupText
}

var (
	viewSeverities = []types.RiskSeverity{
		types.CriticalSeverity, types.HighSeverity, types.ElevatedSeverity, types.MediumSeverity, types.LowSeverity,
	}
	viewStatuses = []types.RiskStatus{
		types.Unchecked, types.InDiscussion, types.Accepted, types.InProgress, types.Mitigated, types.FalsePositive,
	}
	viewFunctions = []types.RiskFunction{types.BusinessSide, types.Architecture, types.Development, types.Operations}
	viewSTRIDE    = []types.STRIDE{
		types.Spoofing, types.Tampering, types.Repudiation, types.InformationDisclosure, types.DenialOfService,
		types.ElevationOfPrivilege,
	}
)

func newReportView(parsedModel *types.Model, options ReportOptions) *reportView {
	report := &reportView{
		Model:                    parsedModel,
		Title:                    parsedModel.Title,
		Date:                     reportDate(parsedModel).Format("2 January 2006"),
		Run:                      options,
		ManagementSummaryComment: markupText(parsedModel.ManagementSummaryComment),
		BusinessOverview:         overviewText(parsedModel.BusinessOverview),
		TechnicalOverview:        overviewText(parsedModel.TechnicalOverview),
		IntroTextRAA:             markupText(options.IntroTextRAA),
	}
	now := types.Now()
	report.ExecutionTimestamp, report.Generated = now.Format("20060102150405"), now.Format(time.RFC3339)
	report.Author = newViewAuthor(parsedModel.Author)
	for _, contributor := range parsedModel.Contributors {
		if contributor != nil {
			report.Contributors = append(report.Contributors, newViewAuthor(contributor))
		}
	}
	risks := newViewRisks(parsedModel)
	report.addSummary(parsedModel, risks)
	report.addModelChapters(parsedModel)
	report.addRiskChapters(parsedModel, risks)
	report.Baseline = newViewBaseline(options.Baseline, risks)
	report.addAssetChapters(parsedModel, risks)
	report.DecisionPoints = viewDecisionPoints(parsedModel)
	report.RiskRules = viewRiskRules(parsedModel, options)
	report.Catalogs = viewCatalogs(report.RiskRules, report.Categories)
	report.Confidentiality, report.Criticality = viewRatings()
	report.Sections = report.sections(options)
	report.sectionShown = make(map[string]bool)
	for _, section := range report.Sections {
		report.sectionShown[section.ID] = true
	}
	return report
}

// Shows tells whether the chapter of the id is in the report.
func (what *reportView) Shows(id string) bool {
	return what.sectionShown[id]
}

func (what *reportView) sections(options ReportOptions) []viewSection {
	optional := map[string]bool{
		chapterRemainingRisks:       len(what.RemainingImpact.Entries) > 0 || !options.HideEmptyChapters,
		chapterBaseline:             what.Baseline != nil,
		chapterAssetRegister:        !options.HideChapters[AssetRegister],
		chapterSecurityRequirements: len(what.SecurityRequirements) > 0,
		chapterAbuseCases:           len(what.AbuseCases) > 0,
		chapterTags:                 len(what.Tags) > 0,
		chapterQuestions:            len(what.Questions) > 0,
		chapterCatalogCoverage:      len(what.Catalogs) > 0,
		chapterDecisionPoints:       len(what.DecisionPoints) > 0,
		chapterRiskRules:            !options.HideChapters[RiskRulesCheckedByThreagile],
	}
	sections := make([]viewSection, 0, len(viewChapters))
	for _, section := range viewChapters {
		if shown, isOptional := optional[section.ID]; shown || !isOptional {
			sections = append(sections, section)
		}
	}
	return sections
}

// The ids of the chapters that a report leaves out when they would be empty or are hidden.
const (
	chapterRemainingRisks       = "remaining-risks"
	chapterBaseline             = "baseline"
	chapterAssetRegister        = "asset-register"
	chapterSecurityRequirements = "security-requirements"
	chapterAbuseCases           = "abuse-cases"
	chapterTags                 = "tags"
	chapterQuestions            = "questions"
	chapterCatalogCoverage      = "catalog-coverage"
	chapterDecisionPoints       = "decision-points"
	chapterRiskRules            = "risk-rules"
)

// viewOutOfScopeText is what the reports show for a technical asset out of scope.
const viewOutOfScopeText = "out of scope"

// viewChapters are all chapters of the report, in their order.
var viewChapters = []viewSection{
	{"management-summary", "Management Summary"},
	{"initial-risks", "Impact Analysis of the Initial Risks"},
	{"risk-mitigation", "Risk Mitigation"},
	{chapterRemainingRisks, "Impact Analysis of the Remaining Risks"},
	{"risks-by-severity", "Risks by Severity"},
	{chapterBaseline, textChangesSinceBaseline},
	{"application-overview", "Application Overview"},
	{"data-flow-diagram", "Data-Flow Diagram"},
	{chapterAssetRegister, "Asset Register"},
	{chapterSecurityRequirements, "Security Requirements"},
	{chapterAbuseCases, "Abuse Cases"},
	{chapterTags, "Tag Listing"},
	{"stride", "STRIDE Classification of Identified Risks"},
	{"functions", "Assignment by Function"},
	{"raa", "RAA Analysis"},
	{"data-mapping", "Data Mapping"},
	{"out-of-scope-assets", "Out-of-Scope Assets"},
	{"model-failures", "Potential Model Failures"},
	{chapterQuestions, viewQuestionsTitle},
	{"risk-categories", "Identified Risks by Vulnerability Category"},
	{"technical-assets", "Identified Risks by Technical Asset"},
	{"data-assets", "Identified Data Breach Probabilities by Data Asset"},
	{"trust-boundaries", "Trust Boundaries"},
	{"shared-runtimes", "Shared Runtimes"},
	{chapterDecisionPoints, textPolicyDecisionPoints},
	{"communication-links", "Communication Links"},
	{"risk-tracking", "Risk Tracking"},
	{chapterCatalogCoverage, textCatalogCoverage},
	{chapterRiskRules, "Risk Rules Checked by Threagile"},
	{"ratings", "Ratings"},
	{"disclaimer", "Disclaimer"},
}

func overviewText(overview *types.Overview) *markupText {
	if overview == nil {
		return nil
	}
	text := markupText(overview.Description)
	return &text
}

func reportDate(parsedModel *types.Model) types.Date {
	if parsedModel.Date.IsZero() {
		return types.Date{Time: types.Now()}
	}
	return parsedModel.Date
}

// authorHomepage is the homepage as a link, with https:// added when it has no scheme.
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

// viewAnchor makes the anchor of an object of the model: the id of its element in the HTML
// report, and what the Markdown report looks up its heading by. Model ids only hold letters,
// digits and hyphens, but risk ids hold more, so any other character is written as _ and its
// code in hex: the anchors stay unique and need no escaping in a URL.
func viewAnchor(kind, id string) string {
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

func severityLevel(severity types.RiskSeverity) viewLevel {
	return viewLevel{Title: severity.Title(), Class: "sev-" + severity.String()}
}

func statusLevel(status types.RiskStatus) viewLevel {
	return viewLevel{Title: status.Title(), Class: "status-" + status.String()}
}

// highestSeverityStillAtRisk is the level of the highest severity of the risks still at risk,
// nil for none.
func highestSeverityStillAtRisk(risks []*types.Risk) *viewLevel {
	if len(types.ReduceToOnlyStillAtRisk(risks)) == 0 {
		return nil
	}
	level := severityLevel(types.HighestSeverityStillAtRisk(risks))
	return &level
}

func refTechnicalAsset(parsedModel *types.Model, id string) viewRef {
	if asset, ok := parsedModel.TechnicalAssets[id]; ok {
		return viewRef{Anchor: viewAnchor("asset", id), Title: asset.Title}
	}
	return viewRef{Title: id}
}

func refDataAsset(parsedModel *types.Model, id string) viewRef {
	if asset, ok := parsedModel.DataAssets[id]; ok {
		return viewRef{Anchor: viewAnchor("data-asset", id), Title: asset.Title}
	}
	return viewRef{Title: id}
}

func refTrustBoundary(parsedModel *types.Model, id string) viewRef {
	if boundary, ok := parsedModel.TrustBoundaries[id]; ok {
		return viewRef{Anchor: viewAnchor("trust-boundary", id), Title: boundary.Title}
	}
	return viewRef{Title: id}
}

func refSharedRuntime(parsedModel *types.Model, id string) viewRef {
	if runtime, ok := parsedModel.SharedRuntimes[id]; ok {
		return viewRef{Anchor: viewAnchor("shared-runtime", id), Title: runtime.Title}
	}
	return viewRef{Title: id}
}

func refCommunicationLink(link *types.CommunicationLink) viewRef {
	return viewRef{Anchor: viewAnchor("link", link.Id), Title: link.Title}
}

func refCategory(category *types.RiskCategory) viewRef {
	return viewRef{Anchor: viewAnchor("category", category.ID), Title: category.Title}
}

func refs[T any](values []T, ref func(T) viewRef) []viewRef {
	result := make([]viewRef, 0, len(values))
	for _, value := range values {
		result = append(result, ref(value))
	}
	return result
}

func refsOfIDs(parsedModel *types.Model, ids []string, ref func(*types.Model, string) viewRef) []viewRef {
	return refs(ids, func(id string) viewRef { return ref(parsedModel, id) })
}

func formatRAA(asset *types.TechnicalAsset) string {
	if asset.OutOfScope {
		return viewOutOfScopeText
	}
	return strconv.FormatFloat(asset.RAA, 'f', 0, 64) + " %"
}
