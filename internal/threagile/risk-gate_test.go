package threagile

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRiskGate(t *testing.T) {
	_, enabled, err := parseRiskGate("")
	require.NoError(t, err)
	assert.False(t, enabled, "an empty --fail-on turns the gate off")

	threshold, enabled, err := parseRiskGate("High")
	require.NoError(t, err)
	assert.True(t, enabled)
	assert.Equal(t, types.HighSeverity, threshold)

	_, _, err = parseRiskGate("severe")
	assert.Error(t, err)
}

func TestCheckRiskGate(t *testing.T) {
	gateModel := &types.Model{
		GeneratedRisksByCategory: map[string][]*types.Risk{
			"a": {
				{SyntheticId: "a@critical-untracked", Severity: types.CriticalSeverity},
				{SyntheticId: "a@high-unchecked", Severity: types.HighSeverity},
				{SyntheticId: "a@high-accepted", Severity: types.HighSeverity},
			},
			"b": {
				{SyntheticId: "b@elevated-untracked", Severity: types.ElevatedSeverity},
				{SyntheticId: "b@critical-mitigated", Severity: types.CriticalSeverity},
			},
		},
		RiskTracking: map[string]*types.RiskTracking{
			"a@high-unchecked":     {Status: types.Unchecked},
			"a@high-accepted":      {Status: types.Accepted},
			"b@critical-mitigated": {Status: types.Mitigated},
		},
	}

	for _, test := range []struct {
		threshold types.RiskSeverity
		failing   []string
	}{
		{types.CriticalSeverity, []string{"a@critical-untracked"}},
		{types.HighSeverity, []string{"a@critical-untracked", "a@high-unchecked"}},
		{types.ElevatedSeverity, []string{"a@critical-untracked", "a@high-unchecked", "b@elevated-untracked"}},
	} {
		t.Run(test.threshold.String(), func(t *testing.T) {
			err := checkRiskGate(gateModel, test.threshold)

			gateError, failed := riskGateFailure(fmt.Errorf("wrapped: %w", err))
			require.True(t, failed, "expected the gate to fail, got %v", err)

			failing := make([]string, 0, len(gateError.risks))
			for _, risk := range gateError.risks {
				failing = append(failing, risk.SyntheticId)
			}
			assert.Equal(t, test.failing, failing)
		})
	}

	passing := &types.Model{
		GeneratedRisksByCategory: map[string][]*types.Risk{
			"a": {{SyntheticId: "a@medium", Severity: types.MediumSeverity}},
		},
	}
	assert.NoError(t, checkRiskGate(passing, types.HighSeverity))

	_, failed := riskGateFailure(errors.New("some other error"))
	assert.False(t, failed)
}
