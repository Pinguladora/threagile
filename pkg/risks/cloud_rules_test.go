package risks_test

import (
	"testing"

	"github.com/Pinguladora/threagile/internal/threagile"
	"github.com/Pinguladora/threagile/pkg/model"
	"github.com/Pinguladora/threagile/pkg/risks"
	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCloudRulesEndToEnd analyzes a small AWS model with all built-in rules and checks the risks of the
// cloud rules for threagile#26-#29.
func TestCloudRulesEndToEnd(t *testing.T) {
	config := new(threagile.Config).Defaults("")
	config.SetAppFolder(t.TempDir())
	config.SetPluginFolder(t.TempDir())
	config.SetInputFile("testdata/cloud-rules/threagile.yaml")
	config.SetOutputFolder(t.TempDir())
	config.SetTempFolder(t.TempDir())

	result, err := model.ReadAndAnalyzeModel(config, risks.GetBuiltInRiskRules(), testReporter{t})
	require.NoError(t, err)

	type expectedRisk struct {
		likelihood types.RiskExploitationLikelihood
		impact     types.RiskExploitationImpact
		severity   types.RiskSeverity
	}
	expected := map[string]map[string]expectedRisk{
		"public-cloud-asset-access": {
			"public-cloud-asset-access@image-bucket": {types.Likely, types.MediumImpact, types.ElevatedSeverity},
			"public-cloud-asset-access@order-queue":  {types.Unlikely, types.VeryHighImpact, types.ElevatedSeverity},
		},
		"public-cloud-snapshot": {
			"public-cloud-snapshot@customer-database": {types.Unlikely, types.VeryHighImpact, types.ElevatedSeverity},
		},
		"cross-account-takeover": {
			"cross-account-takeover@customer-database@analytics-job@analytics-job>records-export": {
				types.Likely, types.VeryHighImpact, types.ElevatedSeverity,
			},
		},
		"encryption-key-deletion": {
			"encryption-key-deletion@customer-database": {types.Unlikely, types.VeryHighImpact, types.ElevatedSeverity},
		},
	}

	for category, expectedRisks := range expected {
		t.Run(category, func(t *testing.T) {
			got := make(map[string]expectedRisk)
			for _, risk := range result.ParsedModel.GeneratedRisksByCategory[category] {
				got[risk.SyntheticId] = expectedRisk{risk.ExploitationLikelihood, risk.ExploitationImpact, risk.Severity}
			}
			assert.Equal(t, expectedRisks, got)
		})
	}
}

type testReporter struct {
	t *testing.T
}

func (r testReporter) Info(...any) {}

func (r testReporter) Infof(string, ...any) {}

func (r testReporter) Warn(a ...any) {
	r.t.Log(a...)
}

func (r testReporter) Warnf(format string, a ...any) {
	r.t.Logf(format, a...)
}

func (r testReporter) Error(a ...any) {
	r.t.Error(a...)
}

func (r testReporter) Errorf(format string, a ...any) {
	r.t.Errorf(format, a...)
}
