package report

import (
	"slices"
	"strings"

	"github.com/Pinguladora/threagile/pkg/catalog"
	"github.com/Pinguladora/threagile/pkg/types"
)

// viewCatalog is the coverage of a threat catalog: which risk rules checked each of its entries and the risks
// they found.
type viewCatalog struct {
	Anchor  string
	Title   string
	Link    string
	Checked int // the entries that a risk rule checked
	Entries []viewCatalogEntry
}

type viewCatalogEntry struct {
	ID          string
	Title       string
	Rules       []viewRef // the categories of the risk rules that checked it
	RuleIDs     []string  // the ids of those categories, in the same order
	Risks       int
	StillAtRisk bool
	Summary     string
}

// catalogCoverageIntro introduces the coverage of the threat catalogs in the reports.
const catalogCoverageIntro = "The risk rules reference the entries of threat catalogs. For each entry of the " +
	"catalogs that the risks of this model fall into, the report lists the risk rules that checked it and the risks " +
	"they found. An entry that no risk rule checks needs a review of its own."

// Texts of the catalog coverage.
const (
	textCatalogCoverage = "Threat Catalog Coverage"
	textNoRisksFound    = "no risks found"
	textNotChecked      = "not checked by any risk rule"
)

// viewCatalogs returns the coverage of the threat catalogs that the risks of the model fall into: catalogs that no
// risk of the model references are left out, as they likely do not apply to it.
func viewCatalogs(rules []viewRiskRule, categories []viewCategory) []viewCatalog {
	risksByCategory := make(map[string]viewCategory, len(categories))
	for _, category := range categories {
		risksByCategory[category.Category.ID] = category
	}

	catalogs := make([]viewCatalog, 0)
	for _, threatCatalog := range catalog.All() {
		result := viewCatalog{
			Anchor: viewAnchor("catalog", threatCatalog.ID), Title: threatCatalog.Title, Link: threatCatalog.Link,
		}
		risks := 0
		for _, entry := range threatCatalog.Entries {
			viewEntry := newViewCatalogEntry(entry, rules, risksByCategory)
			if len(viewEntry.Rules) > 0 {
				result.Checked++
			}
			risks += viewEntry.Risks
			result.Entries = append(result.Entries, viewEntry)
		}
		if risks > 0 {
			catalogs = append(catalogs, result)
		}
	}
	return catalogs
}

// modelCatalogs is the coverage of the threat catalogs for the reports that build no report view, the PDF and
// AsciiDoc reports.
func modelCatalogs(parsedModel *types.Model, options ReportOptions) []viewCatalog {
	risks := newViewRisks(parsedModel)
	sorted := parsedModel.SortedRiskCategories()
	categories := make([]viewCategory, 0, len(sorted))
	for _, category := range sorted {
		categories = append(categories, newViewCategory(category, risks.of(parsedModel.SortedRisksOfCategory(category))))
	}
	return viewCatalogs(viewRiskRules(parsedModel, options), categories)
}

// newViewCatalogEntry is the coverage of the catalog entry by the risk rules that were not skipped and reference
// it, each listed once, by title, and linked to its category when it found risks.
func newViewCatalogEntry(
	entry catalog.Entry, rules []viewRiskRule, risksByCategory map[string]viewCategory,
) viewCatalogEntry {
	result := viewCatalogEntry{ID: entry.ID, Title: entry.Title, Summary: textNotChecked}
	seen := make(map[string]bool)
	stillAtRisk := 0
	for _, rule := range rules {
		category := rule.Category
		if rule.Skipped || seen[category.ID] || !slices.Contains(category.References, entry.Reference) {
			continue
		}
		seen[category.ID] = true
		ref := viewRef{Title: category.Title}
		if found, ok := risksByCategory[category.ID]; ok && len(found.Risks) > 0 {
			ref.Anchor = found.Anchor
			result.Risks += len(found.Risks)
			stillAtRisk += countStillAtRisk(found.Risks)
		}
		result.Rules = append(result.Rules, ref)
		result.RuleIDs = append(result.RuleIDs, category.ID)
	}
	sortRulesByTitle(&result)
	result.StillAtRisk = stillAtRisk > 0
	switch {
	case result.Risks > 0:
		result.Summary = riskSuffix(stillAtRisk, result.Risks)
	case len(result.Rules) > 0:
		result.Summary = textNoRisksFound
	default:
	}
	return result
}

func countStillAtRisk(risks []*viewRisk) int {
	count := 0
	for _, risk := range risks {
		if risk.StillAtRisk {
			count++
		}
	}
	return count
}

// sortRulesByTitle sorts the risk rules of the entry, and their ids with them, by title.
func sortRulesByTitle(entry *viewCatalogEntry) {
	order := make([]int, len(entry.Rules))
	for index := range order {
		order[index] = index
	}
	slices.SortStableFunc(order, func(a, b int) int { return strings.Compare(entry.Rules[a].Title, entry.Rules[b].Title) })
	rules, ids := make([]viewRef, 0, len(order)), make([]string, 0, len(order))
	for _, index := range order {
		rules, ids = append(rules, entry.Rules[index]), append(ids, entry.RuleIDs[index])
	}
	entry.Rules, entry.RuleIDs = rules, ids
}
