package report

import (
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/Pinguladora/threagile/pkg/types"
)

// viewRisk is a risk with its tracking, shown in full in the chapter of its category; the other
// chapters link there.
type viewRisk struct {
	Anchor                string
	SyntheticID           string
	Title                 markupText
	Severity              viewLevel
	Status                viewLevel
	StillAtRisk           bool
	Likelihood            string
	Impact                string
	DataBreachProbability string
	Category              viewRef
	Targets               []viewRef // the most relevant objects of the model
	Tracked               bool
	Tracking              types.RiskTracking
	TrackingDate          string
	Justification         markupText // of the tracking
}

// viewRisks are the views of all risks. They are not looked up by synthetic id, as a rule may
// give two risks the same one.
type viewRisks map[*types.Risk]*viewRisk

func newViewRisks(parsedModel *types.Model) viewRisks {
	risks := make(viewRisks)
	anchors := make(map[string]bool)
	for _, risk := range flattenRiskSlice(parsedModel.GeneratedRisksByCategoryWithCurrentStatus()) {
		details := newRiskDetails(parsedModel, parsedModel.GetRiskCategory(risk.CategoryId), risk)
		anchor := viewAnchor("risk", risk.SyntheticId)
		for count := 2; anchors[anchor]; count++ {
			anchor = viewAnchor("risk", risk.SyntheticId) + "." + strconv.Itoa(count) // viewAnchor writes no dots
		}
		anchors[anchor] = true
		risks[risk] = &viewRisk{
			Anchor:                anchor,
			SyntheticID:           risk.SyntheticId,
			Title:                 markupText(risk.Title),
			Severity:              severityLevel(risk.Severity),
			Status:                statusLevel(risk.RiskStatus),
			StillAtRisk:           risk.RiskStatus.IsStillAtRisk(),
			Likelihood:            risk.ExploitationLikelihood.Title(),
			Impact:                risk.ExploitationImpact.Title(),
			DataBreachProbability: risk.DataBreachProbability.Title(),
			Category:              refCategory(details.category),
			Targets:               riskTargets(parsedModel, risk),
			Tracked:               parsedModel.IsRiskTracked(risk),
			Tracking:              details.tracking,
			TrackingDate:          details.trackingDate(),
			Justification:         markupText(details.tracking.Justification),
		}
	}
	return risks
}

func (what viewRisks) of(risks []*types.Risk) []*viewRisk {
	result := make([]*viewRisk, 0, len(risks))
	for _, risk := range risks {
		result = append(result, what[risk])
	}
	return result
}

func riskTargets(parsedModel *types.Model, risk *types.Risk) []viewRef {
	targets := make([]viewRef, 0)
	if risk.MostRelevantTechnicalAssetId != "" {
		targets = append(targets, refTechnicalAsset(parsedModel, risk.MostRelevantTechnicalAssetId))
	}
	if link, ok := parsedModel.CommunicationLinks[risk.MostRelevantCommunicationLinkId]; ok {
		targets = append(targets, refCommunicationLink(link))
	}
	if risk.MostRelevantDataAssetId != "" {
		targets = append(targets, refDataAsset(parsedModel, risk.MostRelevantDataAssetId))
	}
	if risk.MostRelevantTrustBoundaryId != "" {
		targets = append(targets, refTrustBoundary(parsedModel, risk.MostRelevantTrustBoundaryId))
	}
	if risk.MostRelevantSharedRuntimeId != "" {
		targets = append(targets, refSharedRuntime(parsedModel, risk.MostRelevantSharedRuntimeId))
	}
	return targets
}

type viewSummary struct {
	TotalRisks     int
	CategoryCount  int
	BySeverity     []viewCount
	ByStatus       []viewCount
	RemainingRisks int
	// RemainingBySeverity and RemainingByFunction count the risks still at risk.
	RemainingBySeverity []viewCount
	RemainingByFunction []viewCount
}

type viewImpact struct {
	Count         int
	CategoryCount int
	StillAtRisk   int
	Entries       []viewImpactEntry
}

// viewImpactEntry is a risk category in a list of categories by severity, as the impact analysis,
// the STRIDE classification and the assignment by function show them.
type viewImpactEntry struct {
	Severity    viewLevel
	StillAtRisk bool
	Category    viewRef
	Summary     string
	Likelihood  string
	Impact      string
	Text        markupText
}

type viewRiskGroup struct {
	Title       string
	Explanation string
	Count       int
	Entries     []viewImpactEntry
}

type viewSeverityRisks struct {
	Severity viewLevel
	Risks    []*viewRisk
}

// viewMitigationRow is the tracking status of the risks of a severity, with a bar of a length
// relative to the severity of the most risks.
type viewMitigationRow struct {
	Severity viewLevel
	Total    int
	ByStatus []viewCount
	Bar      []viewBarSegment
}

type viewBarSegment struct {
	Class string
	X     string
	Width string
}

func (what *reportView) addSummary(parsedModel *types.Model, risks viewRisks) {
	summary := viewSummary{
		TotalRisks:     totalRiskCount(parsedModel),
		CategoryCount:  len(parsedModel.GeneratedRisksByCategory),
		RemainingRisks: len(filteredByStillAtRisk(parsedModel)),
	}
	for _, severity := range viewSeverities {
		bySeverity := filteredBySeverity(parsedModel, severity)
		summary.BySeverity = append(summary.BySeverity, viewCount{severityLevel(severity), len(bySeverity)})
		summary.RemainingBySeverity = append(summary.RemainingBySeverity,
			viewCount{severityLevel(severity), len(types.ReduceToOnlyStillAtRisk(bySeverity))})
		what.RisksBySeverity = append(what.RisksBySeverity, viewSeverityRisks{severityLevel(severity), risks.of(bySeverity)})
		for _, risk := range bySeverity {
			if risks[risk].Tracked {
				what.TrackedRisks = append(what.TrackedRisks, risks[risk])
			}
		}
	}
	for _, status := range viewStatuses {
		count := len(filteredByRiskStatus(parsedModel, status))
		summary.ByStatus = append(summary.ByStatus, viewCount{statusLevel(status), count})
	}
	for _, function := range viewFunctions {
		count := len(types.ReduceToOnlyStillAtRisk(filteredByRiskFunction(parsedModel, function)))
		summary.RemainingByFunction = append(summary.RemainingByFunction,
			viewCount{viewLevel{Title: function.Title()}, count})
	}
	what.Summary = summary
	what.Mitigation = viewMitigation(parsedModel)
}

func viewMitigation(parsedModel *types.Model) []viewMitigationRow {
	rows := make([]viewMitigationRow, 0, len(viewSeverities))
	most := 1
	for _, severity := range viewSeverities {
		bySeverity := filteredBySeverity(parsedModel, severity)
		row := viewMitigationRow{Severity: severityLevel(severity), Total: len(bySeverity)}
		for _, status := range viewStatuses {
			row.ByStatus = append(row.ByStatus, viewCount{statusLevel(status), len(reduceToRiskStatus(bySeverity, status))})
		}
		most = max(most, row.Total)
		rows = append(rows, row)
	}
	for i := range rows {
		x := 0.0
		for _, count := range rows[i].ByStatus {
			if count.Count == 0 {
				continue
			}
			width := 100 * float64(count.Count) / float64(most)
			rows[i].Bar = append(rows[i].Bar, viewBarSegment{count.Level.Class, formatPercent(x), formatPercent(width)})
			x += width
		}
	}
	return rows
}

func formatPercent(value float64) string {
	return strconv.FormatFloat(value, 'f', 2, 64)
}

func (what *reportView) addRiskChapters(parsedModel *types.Model, risks viewRisks) {
	risksByCategory := parsedModel.GeneratedRisksByCategoryWithCurrentStatus()
	impact := func(category *types.RiskCategory) string { return category.Impact }
	description := func(category *types.RiskCategory) string { return category.Description }
	mitigation := func(category *types.RiskCategory) string { return category.Mitigation }

	what.InitialImpact = viewImpact{
		Count:         totalRiskCount(parsedModel),
		CategoryCount: len(parsedModel.GeneratedRisksByCategory),
		Entries:       viewImpactEntries(parsedModel, risksByCategory, true, false, impact),
	}
	what.RemainingImpact = viewImpact{
		Count:         len(filteredByStillAtRisk(parsedModel)),
		CategoryCount: len(reduceToOnlyStillAtRisk(risksByCategory)),
		Entries:       viewImpactEntries(parsedModel, risksByCategory, false, false, impact),
	}

	modelFailures := filterByModelFailures(parsedModel, risksByCategory)
	what.ModelFailures = viewImpact{
		Count:       countRisks(modelFailures),
		StillAtRisk: len(types.ReduceToOnlyStillAtRisk(flattenRiskSlice(modelFailures))),
		Entries:     viewImpactEntries(parsedModel, modelFailures, true, true, description),
	}

	for _, stride := range viewSTRIDE {
		byStride := reduceToSTRIDERisk(parsedModel, risksByCategory, stride)
		what.STRIDE = append(what.STRIDE, viewRiskGroup{
			Title: stride.Title(), Explanation: stride.Explain(), Count: countRisks(byStride),
			Entries: viewImpactEntries(parsedModel, byStride, true, true, description),
		})
	}
	for _, function := range viewFunctions {
		byFunction := reduceToFunctionRisk(parsedModel, risksByCategory, function)
		what.Functions = append(what.Functions, viewRiskGroup{
			Title: function.Title(), Explanation: function.Explain(), Count: countRisks(byFunction),
			Entries: viewImpactEntries(parsedModel, byFunction, true, true, mitigation),
		})
	}

	for _, category := range parsedModel.SortedRiskCategories() {
		categoryRisks := risks.of(parsedModel.SortedRisksOfCategory(category))
		what.Categories = append(what.Categories, newViewCategory(category, categoryRisks))
	}
}

// viewImpactEntries lists the categories of the risks by severity, as the impact analysis of the
// PDF and AsciiDoc reports does: the initial risks or only those still at risk, the latter also
// counted against all when both is set, with the first paragraph of a text of the category.
func viewImpactEntries(parsedModel *types.Model, risksByCategory map[string][]*types.Risk, initialRisks, both bool,
	text func(*types.RiskCategory) string,
) []viewImpactEntry {
	entries := make([]viewImpactEntry, 0)
	for _, severity := range viewSeverities {
		categories := getRiskCategories(parsedModel, reduceToSeverityRisk(risksByCategory, initialRisks, severity))
		sort.Sort(types.ByRiskCategoryTitleSort(categories))
		for _, category := range categories {
			risks := risksByCategory[category.ID]
			remaining := types.ReduceToOnlyStillAtRisk(risks)
			if !initialRisks {
				risks = remaining
			}
			if len(risks) == 0 {
				continue
			}
			entry := viewImpactEntry{
				Severity:    severityLevel(severity),
				StillAtRisk: len(remaining) > 0,
				Category:    refCategory(category),
				Summary:     impactSummary(len(risks), len(remaining), initialRisks, both),
				Likelihood:  highestExploitationLikelihood(risks).Title(),
				Impact:      highestExploitationImpact(risks).Title(),
				Text:        markupText(firstParagraph(text(category))),
			}
			entries = append(entries, entry)
		}
	}
	return entries
}

func impactSummary(count, remaining int, initialRisks, both bool) string {
	if both {
		return riskSuffix(remaining, count)
	}
	kind := " Initial Risk"
	if !initialRisks {
		kind = " Remaining Risk"
	}
	if count != 1 {
		kind += "s"
	}
	return strconv.Itoa(count) + kind
}

type viewCategory struct {
	Anchor         string
	Category       *types.RiskCategory
	Severity       *viewLevel // the highest severity still at risk, nil for none
	Summary        string
	Description    markupText
	Impact         markupText
	DetectionLogic markupText
	RiskAssessment markupText
	FalsePositives markupText
	Mitigation     markupText
	Check          markupText
	CWELink        string
	CheatSheet     viewRef // the link as anchor, empty unless http(s)
	Risks          []*viewRisk
}

func newViewCategory(category *types.RiskCategory, risks []*viewRisk) viewCategory {
	stillAtRisk := 0
	var severity *viewLevel
	for _, risk := range risks {
		if risk.StillAtRisk {
			stillAtRisk++
			if severity == nil {
				severity = &risk.Severity // the risks come sorted by severity
			}
		}
	}
	result := viewCategory{
		Anchor:         viewAnchor("category", category.ID),
		Category:       category,
		Severity:       severity,
		Summary:        riskSuffix(stillAtRisk, len(risks)),
		Description:    markupText(category.Description),
		Impact:         markupText(category.Impact),
		DetectionLogic: markupText(category.DetectionLogic),
		RiskAssessment: markupText(category.RiskAssessment),
		FalsePositives: markupText(category.FalsePositives),
		Mitigation:     markupText(category.Mitigation),
		Check:          markupText(category.Check),
		Risks:          risks,
	}
	if category.CWE > 0 {
		result.CWELink = "https://cwe.mitre.org/data/definitions/" + strconv.Itoa(category.CWE) + ".html"
	}
	if link, ok := httpLink(category.CheatSheet); ok {
		result.CheatSheet = viewRef{Anchor: link, Title: cheatSheetTitle(link)}
	}
	return result
}

// cheatSheetTitle is the last part of the link without an .html or .htm extension, as the
// AsciiDoc report shows it.
func cheatSheetTitle(link string) string {
	parts := strings.Split(link, "/")
	title := parts[len(parts)-1]
	for _, extension := range []string{".html", ".htm"} {
		if trimmed, found := strings.CutSuffix(title, extension); found && trimmed != "" {
			return trimmed
		}
	}
	if title == "" {
		return link
	}
	return title
}

type viewRiskRule struct {
	ID             string
	Kind           string
	Skipped        bool
	Category       *types.RiskCategory
	Description    markupText
	DetectionLogic markupText
	RiskAssessment markupText
}

// viewRiskRules lists the risk rules checked as the PDF and AsciiDoc reports do: the custom risk
// rules, the individual risk categories of the model and the built-in rules.
func viewRiskRules(parsedModel *types.Model, options ReportOptions) []viewRiskRule {
	count := len(options.CustomRiskRules) + len(parsedModel.CustomRiskCategories) + len(options.RiskRules)
	rules := make([]viewRiskRule, 0, count)
	for _, id := range slices.Sorted(maps.Keys(options.CustomRiskRules)) {
		rule := newViewRiskRule(options.CustomRiskRules[id].Category(), "Custom risk rule")
		rule.ID, rule.Skipped = id, contains(options.SkipRiskRules, id)
		rules = append(rules, rule)
	}
	individual := slices.Clone(parsedModel.CustomRiskCategories)
	sort.Stable(types.ByRiskCategoryTitleSort(individual))
	for _, category := range individual {
		rules = append(rules, newViewRiskRule(category, "Individual risk category"))
	}
	for _, id := range slices.Sorted(maps.Keys(options.RiskRules)) {
		rule := newViewRiskRule(options.RiskRules[id].Category(), "")
		rule.Skipped = contains(options.SkipRiskRules, rule.ID)
		rules = append(rules, rule)
	}
	return rules
}

func newViewRiskRule(category *types.RiskCategory, kind string) viewRiskRule {
	return viewRiskRule{
		ID:             category.ID,
		Kind:           kind,
		Category:       category,
		Description:    markupText(firstParagraph(category.Description)),
		DetectionLogic: markupText(category.DetectionLogic),
		RiskAssessment: markupText(category.RiskAssessment),
	}
}

type viewRating struct {
	Name        string
	Value       int
	Explanation string
}

// viewRatings are the confidentiality and criticality values with their explanations.
func viewRatings() (confidentiality, criticality []viewRating) {
	for index, value := range types.ConfidentialityValues() {
		confidentiality = append(confidentiality, viewRating{value.String(), index + 1, value.Explain()})
	}
	for index, value := range types.CriticalityValues() {
		criticality = append(criticality, viewRating{value.String(), index + 1, value.Explain()})
	}
	return confidentiality, criticality
}
