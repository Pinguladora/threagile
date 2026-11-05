package baseline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompare(t *testing.T) {
	risk := func(id string, severity types.RiskSeverity) *types.Risk {
		return &types.Risk{SyntheticId: id, Severity: severity}
	}
	current := []*types.Risk{
		risk("same@a", types.MediumSeverity),
		risk("new@low", types.LowSeverity),
		risk("new@high", types.HighSeverity),
		risk("up@a", types.HighSeverity),
		risk("down@a", types.LowSeverity),
	}
	baseline := []Risk{
		{SyntheticId: "same@a", Severity: types.MediumSeverity},
		{SyntheticId: "up@a", Severity: types.MediumSeverity},
		{SyntheticId: "down@a", Severity: types.ElevatedSeverity},
		{SyntheticId: "gone@b", Severity: types.LowSeverity},
		{SyntheticId: "gone@a", Severity: types.CriticalSeverity},
	}

	comparison := Compare("old.json", baseline, current)

	assert.Equal(t, []*types.Risk{current[2], current[1]}, comparison.New, "the highest severity first")
	assert.Equal(t, []Risk{baseline[4], baseline[3]}, comparison.Resolved)
	assert.Equal(t, []Change{{Risk: current[3], Previous: types.MediumSeverity}}, comparison.Escalated)
	assert.Equal(t, []Change{{Risk: current[4], Previous: types.ElevatedSeverity}}, comparison.Deescalated)
	assert.Equal(t, 1, comparison.Unchanged)

	previous, known := comparison.Previous("up@a")
	assert.True(t, known)
	assert.Equal(t, types.MediumSeverity, previous)
	_, known = comparison.Previous("new@high")
	assert.False(t, known)
}

func TestLoad(t *testing.T) {
	write := func(content string) string {
		filename := filepath.Join(t.TempDir(), "risks.json")
		require.NoError(t, os.WriteFile(filename, []byte(content), 0o600))
		return filename
	}

	risks, err := Load(write(`[{"synthetic_id": "rule@a", "severity": "elevated", "plain_title": "Rule at A",
		"category": "rule", "risk_status": "unchecked"}]`))
	require.NoError(t, err)
	assert.Equal(t, []Risk{{SyntheticId: "rule@a", Severity: types.ElevatedSeverity, Title: "Rule at A", Category: "rule"}},
		risks)

	_, err = Load(write(`{"risks": []}`))
	assert.ErrorContains(t, err, "should be the risks JSON of an analysis")
	_, err = Load(write(`[{"severity": "low"}]`))
	assert.ErrorContains(t, err, "has no synthetic_id")
	_, err = Load(write(`[{"synthetic_id": "rule@a", "severity": "dreadful"}]`))
	assert.Error(t, err)
	_, err = Load(filepath.Join(t.TempDir(), "missing.json"))
	assert.ErrorContains(t, err, "unable to read the baseline")
}
