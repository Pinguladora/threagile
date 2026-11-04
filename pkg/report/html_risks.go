package report

import (
	"html/template"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/Pinguladora/threagile/pkg/types"
)

// htmlRisk is a risk with its tracking, shown in full in the chapter of its category; the other
// chapters link there.
type htmlRisk struct {
	Anchor                string
	SyntheticID           string
	Title                 template.HTML
	Severity              htmlLevel
	Status                htmlLevel
	StillAtRisk           bool
	Likelihood            string
	Impact                string
	DataBreachProbability string
	Category              htmlRef
	Targets               []htmlRef // the most relevant objects of the model
	Tracked               bool
	Tracking              types.RiskTracking
	TrackingDate          string
}

// htmlRisks are the views of all risks. They are not looked up by synthetic id, as a rule may
// give two risks the same one.
type htmlRisks map[*types.Risk]*htmlRisk

func newHTMLRisks(parsedModel *types.Model) htmlRisks {
	risks := make(htmlRisks)
	anchors := make(map[string]bool)
	for _, risk := range flattenRiskSlice(parsedModel.GeneratedRisksByCategoryWithCurrentStatus()) {
		details := newRiskDetails(parsedModel, parsedModel.GetRiskCategory(risk.CategoryId), risk)
		anchor := htmlAnchor("risk", risk.SyntheticId)
		for count := 2; anchors[anchor]; count++ {
			anchor = htmlAnchor("risk", risk.SyntheticId) + "." + strconv.Itoa(count) // htmlAnchor writes no dots
		}
		anchors[anchor] = true
		risks[risk] = &htmlRisk{
			Anchor:                anchor,
			SyntheticID:           risk.SyntheticId,
			Title:                 basicMarkup(risk.Title),
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
		}
	}
	return risks
}

func (what htmlRisks) of(risks []*types.Risk) []*htmlRisk {
	result := make([]*htmlRisk, 0, len(risks))
	for _, risk := range risks {
		result = append(result, what[risk])
	}
	return result
}

func riskTargets(parsedModel *types.Model, risk *types.Risk) []htmlRef {
	targets := make([]htmlRef, 0)
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

type htmlSummary struct {
	TotalRisks     int
	CategoryCount  int
	BySeverity     []htmlCount
	ByStatus       []htmlCount
	RemainingRisks int
	// RemainingBySeverity and RemainingByFunction count the risks still at risk.
	RemainingBySeverity []htmlCount
	RemainingByFunction []htmlCount
}

type htmlImpact struct {
	Count         int
	CategoryCount int
	StillAtRisk   int
	Entries       []htmlImpactEntry
}

// htmlImpactEntry is a risk category in a list of categories by severity, as the impact analysis,
// the STRIDE classification and the assignment by function show them.
type htmlImpactEntry struct {
	Severity    htmlLevel
	StillAtRisk bool
	Category    htmlRef
	Summary     string
	Likelihood  string
	Impact      string
	Text        template.HTML
}

type htmlRiskGroup struct {
	Title       string
	Explanation string
	Count       int
	Entries     []htmlImpactEntry
}

type htmlSeverityRisks struct {
	Severity htmlLevel
	Risks    []*htmlRisk
}

// htmlMitigationRow is the tracking status of the risks of a severity, with a bar of a length
// relative to the severity of the most risks.
type htmlMitigationRow struct {
	Severity htmlLevel
	Total    int
	ByStatus []htmlCount
	Bar      []htmlBarSegment
}

type htmlBarSegment struct {
	Class string
	X     string
	Width string
}

func (what *htmlReport) addSummary(parsedModel *types.Model, risks htmlRisks) {
	summary := htmlSummary{
		TotalRisks:     totalRiskCount(parsedModel),
		CategoryCount:  len(parsedModel.GeneratedRisksByCategory),
		RemainingRisks: len(filteredByStillAtRisk(parsedModel)),
	}
	for _, severity := range htmlSeverities {
		bySeverity := filteredBySeverity(parsedModel, severity)
		summary.BySeverity = append(summary.BySeverity, htmlCount{severityLevel(severity), len(bySeverity)})
		summary.RemainingBySeverity = append(summary.RemainingBySeverity,
			htmlCount{severityLevel(severity), len(types.ReduceToOnlyStillAtRisk(bySeverity))})
		what.RisksBySeverity = append(what.RisksBySeverity, htmlSeverityRisks{severityLevel(severity), risks.of(bySeverity)})
		for _, risk := range bySeverity {
			if risks[risk].Tracked {
				what.TrackedRisks = append(what.TrackedRisks, risks[risk])
			}
		}
	}
	for _, status := range htmlStatuses {
		count := len(filteredByRiskStatus(parsedModel, status))
		summary.ByStatus = append(summary.ByStatus, htmlCount{statusLevel(status), count})
	}
	for _, function := range htmlFunctions {
		count := len(types.ReduceToOnlyStillAtRisk(filteredByRiskFunction(parsedModel, function)))
		summary.RemainingByFunction = append(summary.RemainingByFunction,
			htmlCount{htmlLevel{Title: function.Title()}, count})
	}
	what.Summary = summary
	what.Mitigation = htmlMitigation(parsedModel)
}

func htmlMitigation(parsedModel *types.Model) []htmlMitigationRow {
	rows := make([]htmlMitigationRow, 0, len(htmlSeverities))
	most := 1
	for _, severity := range htmlSeverities {
		bySeverity := filteredBySeverity(parsedModel, severity)
		row := htmlMitigationRow{Severity: severityLevel(severity), Total: len(bySeverity)}
		for _, status := range htmlStatuses {
			row.ByStatus = append(row.ByStatus, htmlCount{statusLevel(status), len(reduceToRiskStatus(bySeverity, status))})
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
			rows[i].Bar = append(rows[i].Bar, htmlBarSegment{count.Level.Class, formatPercent(x), formatPercent(width)})
			x += width
		}
	}
	return rows
}

func formatPercent(value float64) string {
	return strconv.FormatFloat(value, 'f', 2, 64)
}

func (what *htmlReport) addRiskChapters(parsedModel *types.Model, risks htmlRisks) {
	risksByCategory := parsedModel.GeneratedRisksByCategoryWithCurrentStatus()
	impact := func(category *types.RiskCategory) string { return category.Impact }
	description := func(category *types.RiskCategory) string { return category.Description }
	mitigation := func(category *types.RiskCategory) string { return category.Mitigation }

	what.InitialImpact = htmlImpact{
		Count:         totalRiskCount(parsedModel),
		CategoryCount: len(parsedModel.GeneratedRisksByCategory),
		Entries:       htmlImpactEntries(parsedModel, risksByCategory, true, false, impact),
	}
	what.RemainingImpact = htmlImpact{
		Count:         len(filteredByStillAtRisk(parsedModel)),
		CategoryCount: len(reduceToOnlyStillAtRisk(risksByCategory)),
		Entries:       htmlImpactEntries(parsedModel, risksByCategory, false, false, impact),
	}

	modelFailures := filterByModelFailures(parsedModel, risksByCategory)
	what.ModelFailures = htmlImpact{
		Count:       countRisks(modelFailures),
		StillAtRisk: len(types.ReduceToOnlyStillAtRisk(flattenRiskSlice(modelFailures))),
		Entries:     htmlImpactEntries(parsedModel, modelFailures, true, true, description),
	}

	for _, stride := range htmlSTRIDE {
		byStride := reduceToSTRIDERisk(parsedModel, risksByCategory, stride)
		what.STRIDE = append(what.STRIDE, htmlRiskGroup{
			Title: stride.Title(), Explanation: stride.Explain(), Count: countRisks(byStride),
			Entries: htmlImpactEntries(parsedModel, byStride, true, true, description),
		})
	}
	for _, function := range htmlFunctions {
		byFunction := reduceToFunctionRisk(parsedModel, risksByCategory, function)
		what.Functions = append(what.Functions, htmlRiskGroup{
			Title: function.Title(), Explanation: function.Explain(), Count: countRisks(byFunction),
			Entries: htmlImpactEntries(parsedModel, byFunction, true, true, mitigation),
		})
	}

	for _, category := range parsedModel.SortedRiskCategories() {
		categoryRisks := risks.of(parsedModel.SortedRisksOfCategory(category))
		what.Categories = append(what.Categories, newHTMLCategory(category, categoryRisks))
	}
}

// htmlImpactEntries lists the categories of the risks by severity, as the impact analysis of the
// PDF and AsciiDoc reports does: the initial risks or only those still at risk, the latter also
// counted against all when both is set, with the first paragraph of a text of the category.
func htmlImpactEntries(parsedModel *types.Model, risksByCategory map[string][]*types.Risk, initialRisks, both bool,
	text func(*types.RiskCategory) string,
) []htmlImpactEntry {
	entries := make([]htmlImpactEntry, 0)
	for _, severity := range htmlSeverities {
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
			entry := htmlImpactEntry{
				Severity:    severityLevel(severity),
				StillAtRisk: len(remaining) > 0,
				Category:    refCategory(category),
				Summary:     impactSummary(len(risks), len(remaining), initialRisks, both),
				Likelihood:  highestExploitationLikelihood(risks).Title(),
				Impact:      highestExploitationImpact(risks).Title(),
				Text:        basicMarkup(firstParagraph(text(category))),
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

type htmlCategory struct {
	Anchor         string
	Category       *types.RiskCategory
	Severity       *htmlLevel // the highest severity still at risk, nil for none
	Summary        string
	Description    template.HTML
	Impact         template.HTML
	DetectionLogic template.HTML
	RiskAssessment template.HTML
	FalsePositives template.HTML
	Mitigation     template.HTML
	Check          template.HTML
	CWELink        string
	CheatSheet     htmlRef // the link as anchor, empty unless http(s)
	Risks          []*htmlRisk
}

func newHTMLCategory(category *types.RiskCategory, risks []*htmlRisk) htmlCategory {
	stillAtRisk := 0
	var severity *htmlLevel
	for _, risk := range risks {
		if risk.StillAtRisk {
			stillAtRisk++
			if severity == nil {
				severity = &risk.Severity // the risks come sorted by severity
			}
		}
	}
	result := htmlCategory{
		Anchor:         htmlAnchor("category", category.ID),
		Category:       category,
		Severity:       severity,
		Summary:        riskSuffix(stillAtRisk, len(risks)),
		Description:    basicMarkup(category.Description),
		Impact:         basicMarkup(category.Impact),
		DetectionLogic: basicMarkup(category.DetectionLogic),
		RiskAssessment: basicMarkup(category.RiskAssessment),
		FalsePositives: basicMarkup(category.FalsePositives),
		Mitigation:     basicMarkup(category.Mitigation),
		Check:          basicMarkup(category.Check),
		Risks:          risks,
	}
	if category.CWE > 0 {
		result.CWELink = "https://cwe.mitre.org/data/definitions/" + strconv.Itoa(category.CWE) + ".html"
	}
	if link, ok := httpLink(category.CheatSheet); ok {
		result.CheatSheet = htmlRef{Anchor: link, Title: cheatSheetTitle(link)}
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

type htmlRiskRule struct {
	ID             string
	Kind           string
	Skipped        bool
	Category       *types.RiskCategory
	Description    template.HTML
	DetectionLogic template.HTML
	RiskAssessment template.HTML
}

// htmlRiskRules lists the risk rules checked as the PDF and AsciiDoc reports do: the custom risk
// rules, the individual risk categories of the model and the built-in rules.
func htmlRiskRules(parsedModel *types.Model, options HTMLReportOptions) []htmlRiskRule {
	count := len(options.CustomRiskRules) + len(parsedModel.CustomRiskCategories) + len(options.RiskRules)
	rules := make([]htmlRiskRule, 0, count)
	for _, id := range slices.Sorted(maps.Keys(options.CustomRiskRules)) {
		rule := newHTMLRiskRule(options.CustomRiskRules[id].Category(), "Custom risk rule")
		rule.ID, rule.Skipped = id, contains(options.SkipRiskRules, id)
		rules = append(rules, rule)
	}
	individual := slices.Clone(parsedModel.CustomRiskCategories)
	sort.Stable(types.ByRiskCategoryTitleSort(individual))
	for _, category := range individual {
		rules = append(rules, newHTMLRiskRule(category, "Individual risk category"))
	}
	for _, id := range slices.Sorted(maps.Keys(options.RiskRules)) {
		rule := newHTMLRiskRule(options.RiskRules[id].Category(), "")
		rule.Skipped = contains(options.SkipRiskRules, rule.ID)
		rules = append(rules, rule)
	}
	return rules
}

func newHTMLRiskRule(category *types.RiskCategory, kind string) htmlRiskRule {
	return htmlRiskRule{
		ID:             category.ID,
		Kind:           kind,
		Category:       category,
		Description:    basicMarkup(firstParagraph(category.Description)),
		DetectionLogic: basicMarkup(category.DetectionLogic),
		RiskAssessment: basicMarkup(category.RiskAssessment),
	}
}

type htmlRating struct {
	Name        string
	Value       int
	Explanation string
}

// htmlRatings are the confidentiality and criticality values with their explanations.
func htmlRatings() (confidentiality, criticality []htmlRating) {
	for index, value := range types.ConfidentialityValues() {
		confidentiality = append(confidentiality, htmlRating{value.String(), index + 1, value.Explain()})
	}
	for index, value := range types.CriticalityValues() {
		criticality = append(criticality, htmlRating{value.String(), index + 1, value.Explain()})
	}
	return confidentiality, criticality
}
