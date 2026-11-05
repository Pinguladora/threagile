// Package baseline compares the risks of an analysis with those of an earlier one, read from the risks JSON
// output of that analysis.
package baseline

import (
	"cmp"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/Pinguladora/threagile/pkg/types"
)

// Risk is what the comparison needs of a risk of the earlier analysis.
type Risk struct {
	SyntheticId string             `json:"synthetic_id"`
	Severity    types.RiskSeverity `json:"severity"`
	Title       string             `json:"plain_title"`
	Category    string             `json:"category"`
}

// Change is a risk whose severity differs from the one it had in the earlier analysis.
type Change struct {
	Risk     *types.Risk
	Previous types.RiskSeverity
}

// Comparison tells how the risks of an analysis differ from those of an earlier one. Each list is sorted by
// severity, the highest first, then by synthetic id.
type Comparison struct {
	Filename    string
	New         []*types.Risk
	Resolved    []Risk
	Escalated   []Change
	Deescalated []Change
	Unchanged   int
	previous    map[string]types.RiskSeverity
}

// Load reads the risks of an earlier analysis from its risks JSON output.
func Load(filename string) ([]Risk, error) {
	data, err := os.ReadFile(filepath.Clean(filename))
	if err != nil {
		return nil, fmt.Errorf("unable to read the baseline: %w", err)
	}
	var risks []Risk
	if err := json.Unmarshal(data, &risks); err != nil {
		return nil, fmt.Errorf("unable to parse the baseline %v, which should be the risks JSON of an analysis: %w",
			filename, err)
	}
	for i, risk := range risks {
		if risk.SyntheticId == "" {
			return nil, fmt.Errorf("risk %d of the baseline %v has no synthetic_id", i+1, filename)
		}
	}
	return risks, nil
}

// Compare compares the current risks with those of the baseline.
func Compare(filename string, baseline []Risk, current []*types.Risk) *Comparison {
	comparison := &Comparison{Filename: filename, previous: make(map[string]types.RiskSeverity, len(baseline))}
	for _, risk := range baseline {
		comparison.previous[risk.SyntheticId] = risk.Severity
	}

	currentIds := make(map[string]bool, len(current))
	for _, risk := range current {
		currentIds[risk.SyntheticId] = true
		previous, known := comparison.previous[risk.SyntheticId]
		switch {
		case !known:
			comparison.New = append(comparison.New, risk)
		case risk.Severity > previous:
			comparison.Escalated = append(comparison.Escalated, Change{Risk: risk, Previous: previous})
		case risk.Severity < previous:
			comparison.Deescalated = append(comparison.Deescalated, Change{Risk: risk, Previous: previous})
		default:
			comparison.Unchanged++
		}
	}
	for _, risk := range baseline {
		if !currentIds[risk.SyntheticId] {
			comparison.Resolved = append(comparison.Resolved, risk)
		}
	}

	slices.SortFunc(comparison.New, func(a, b *types.Risk) int {
		return bySeverity(a.Severity, a.SyntheticId, b.Severity, b.SyntheticId)
	})
	slices.SortFunc(comparison.Resolved, func(a, b Risk) int {
		return bySeverity(a.Severity, a.SyntheticId, b.Severity, b.SyntheticId)
	})
	for _, changes := range [][]Change{comparison.Escalated, comparison.Deescalated} {
		slices.SortFunc(changes, func(a, b Change) int {
			return bySeverity(a.Risk.Severity, a.Risk.SyntheticId, b.Risk.Severity, b.Risk.SyntheticId)
		})
	}
	return comparison
}

// Previous returns the severity that the risk of the synthetic id had in the baseline, and false when the
// baseline did not have it.
func (what *Comparison) Previous(syntheticId string) (types.RiskSeverity, bool) {
	severity, known := what.previous[syntheticId]
	return severity, known
}

func bySeverity(severityA types.RiskSeverity, idA string, severityB types.RiskSeverity, idB string) int {
	return cmp.Or(cmp.Compare(severityB, severityA), cmp.Compare(idA, idB))
}
