package report

import (
	"path/filepath"

	"github.com/Pinguladora/threagile/pkg/baseline"
)

// textChangesSinceBaseline is the title of the chapter that compares the risks with a baseline.
const textChangesSinceBaseline = "Changes Since the Baseline"

// viewBaseline compares the risks with those of an earlier analysis, the baseline.
type viewBaseline struct {
	Filename    string
	New         []*viewRisk
	Escalated   []viewRiskChange
	Deescalated []viewRiskChange
	Resolved    []viewResolvedRisk
	Unchanged   int
}

// viewRiskChange is a risk whose severity changed since the baseline.
type viewRiskChange struct {
	Risk     *viewRisk
	Previous viewLevel
}

// viewResolvedRisk is a risk of the baseline that the model no longer has. It links nowhere, as the report does not
// show it otherwise.
type viewResolvedRisk struct {
	SyntheticID string
	Title       string
	Severity    viewLevel
}

func newViewBaseline(comparison *baseline.Comparison, risks viewRisks) *viewBaseline {
	if comparison == nil {
		return nil
	}
	changes := func(changes []baseline.Change) []viewRiskChange {
		result := make([]viewRiskChange, 0, len(changes))
		for _, change := range changes {
			result = append(result, viewRiskChange{Risk: risks[change.Risk], Previous: severityLevel(change.Previous)})
		}
		return result
	}
	view := &viewBaseline{
		Filename:    filepath.Base(comparison.Filename),
		New:         risks.of(comparison.New),
		Escalated:   changes(comparison.Escalated),
		Deescalated: changes(comparison.Deescalated),
		Unchanged:   comparison.Unchanged,
	}
	for _, risk := range comparison.Resolved {
		view.Resolved = append(view.Resolved, viewResolvedRisk{
			SyntheticID: risk.SyntheticId, Title: risk.Title, Severity: severityLevel(risk.Severity),
		})
	}
	return view
}
