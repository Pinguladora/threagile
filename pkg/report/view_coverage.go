package report

import (
	"slices"
	"strings"

	"github.com/Pinguladora/threagile/pkg/catalog"
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
	Risks       int
	StillAtRisk bool
	Summary     string
}

// catalogCoverageIntro introduces the coverage of the threat catalogs in the reports.
const catalogCoverageIntro = "The risk rules reference the entries of threat catalogs. For each entry of the " +
	"catalogs that the risks of this model fall into, the tables list the risk rules that checked it and the risks " +
	"they found. An entry that no risk rule checks needs a review of its own."

// Texts of the catalog entries without risks.
const (
	textNoRisksFound = "no risks found"
	textNotChecked   = "not checked by any risk rule"
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
	}
	slices.SortFunc(result.Rules, func(a, b viewRef) int { return strings.Compare(a.Title, b.Title) })
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
