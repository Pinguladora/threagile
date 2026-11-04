package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
