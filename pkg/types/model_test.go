package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRisksMatching(t *testing.T) {
	model := &Model{GeneratedRisksBySyntheticId: map[string]*Risk{
		"some-rule@b":          {SyntheticId: "some-rule@b"},
		"some-rule@a":          {SyntheticId: "some-rule@a"},
		"some-rule@a@link":     {SyntheticId: "some-rule@a@link"},
		"other-rule@a":         {SyntheticId: "other-rule@a"},
		"some-rule-variant@ab": {SyntheticId: "some-rule-variant@ab"},
	}}
	ids := func(pattern string) []string {
		matching := model.RisksMatching(pattern)
		result := make([]string, 0, len(matching))
		for _, risk := range matching {
			result = append(result, risk.SyntheticId)
		}
		return result
	}

	assert.Equal(t, []string{"some-rule@a"}, ids("some-rule@a"), "an exact id")
	assert.Equal(t, []string{"some-rule@a", "some-rule@b"}, ids("some-rule@*"),
		"a wildcard stands for one part of the id")
	assert.Equal(t, []string{"some-rule@a@link"}, ids("some-rule@*@*"))
	assert.Equal(t, []string{"other-rule@a", "some-rule@a"}, ids("*@a"), "the pattern covers the whole id")
	assert.Empty(t, ids("some-rule@c"), "an unknown id without wildcards")
}

func TestWildcardRiskTrackingMatchesWholeIds(t *testing.T) {
	model := &Model{
		GeneratedRisksBySyntheticId: map[string]*Risk{
			"some-rule@db":         {SyntheticId: "some-rule@db"},
			"some-rule@db-replica": {SyntheticId: "some-rule@db-replica"},
			"some-rule@db@link":    {SyntheticId: "some-rule@db@link"},
		},
		RiskTracking: map[string]*RiskTracking{
			"*@db": {SyntheticRiskId: "*@db", Status: Mitigated},
		},
	}

	assert.NoError(t, model.ApplyWildcardRiskTrackingEvaluation(false, silentReporter{}))

	assert.Contains(t, model.RiskTracking, "some-rule@db")
	assert.NotContains(t, model.RiskTracking, "some-rule@db-replica", "another asset whose id starts the same")
	assert.NotContains(t, model.RiskTracking, "some-rule@db@link", "an id with more parts")
}

// silentReporter drops all progress.
type silentReporter struct{}

func (silentReporter) Info(...any)           {}
func (silentReporter) Warn(...any)           {}
func (silentReporter) Error(...any)          {}
func (silentReporter) Infof(string, ...any)  {}
func (silentReporter) Warnf(string, ...any)  {}
func (silentReporter) Errorf(string, ...any) {}
