package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSortByRiskSeverityBreaksTiesBySyntheticId(t *testing.T) {
	risks := []*Risk{
		{SyntheticId: "c", Title: "same", Severity: MediumSeverity},
		{SyntheticId: "a", Title: "same", Severity: MediumSeverity},
		{SyntheticId: "d", Title: "other", Severity: HighSeverity},
		{SyntheticId: "b", Title: "same", Severity: MediumSeverity},
	}

	SortByRiskSeverity(risks)

	ids := make([]string, 0, len(risks))
	for _, risk := range risks {
		ids = append(ids, risk.SyntheticId)
	}
	assert.Equal(t, []string{"d", "a", "b", "c"}, ids)
}

func TestAllRisksOrderedByCategory(t *testing.T) {
	model := &Model{GeneratedRisksByCategory: map[string][]*Risk{
		"charlie": {{SyntheticId: "charlie@1"}},
		"alpha":   {{SyntheticId: "alpha@2"}, {SyntheticId: "alpha@1"}},
		"echo":    {{SyntheticId: "echo@1"}},
		"bravo":   {{SyntheticId: "bravo@1"}},
		"delta":   {{SyntheticId: "delta@1"}},
	}}

	allRisks := model.AllRisks()
	ids := make([]string, 0, len(allRisks))
	for _, risk := range allRisks {
		ids = append(ids, risk.SyntheticId)
	}
	assert.Equal(t, []string{"alpha@2", "alpha@1", "bravo@1", "charlie@1", "delta@1", "echo@1"}, ids)
}
