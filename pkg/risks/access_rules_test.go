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

// TestAccessRulesEndToEnd analyzes a shop with all built-in rules and checks the risks of the rules on credentials
// and authorization. The model also holds what the rules must skip: the password of a person, a long-lived token
// of a workload identity, a token of unknown lifetime, links with object-level or unknown authorization, a
// redundant policy decision point and an authenticated, encrypted link to one.
func TestAccessRulesEndToEnd(t *testing.T) {
	config := new(threagile.Config).Defaults("")
	config.SetAppFolder(t.TempDir())
	config.SetPluginFolder(t.TempDir())
	config.SetInputFile("testdata/access-rules/threagile.yaml")
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
		"long-lived-credentials": {
			// a partner on the internet with an API key
			"long-lived-credentials@shop-api@partner>partner-feed": {types.Likely, types.MediumImpact, types.ElevatedSeverity},
			// the database password of the service
			"long-lived-credentials@orders-db@shop-api>order-storage": {
				types.Unlikely, types.MediumImpact, types.MediumSeverity,
			},
		},
		"missing-object-level-authorization": {
			"missing-object-level-authorization@shop-api@browser>shop-use": {
				types.VeryLikely, types.MediumImpact, types.ElevatedSeverity,
			},
			// no function-level authorization either, which raises the impact
			"missing-object-level-authorization@shop-api@admin-console>admin-use": {
				types.Likely, types.HighImpact, types.ElevatedSeverity,
			},
		},
		"missing-policy-decision-point-redundancy": {
			"missing-policy-decision-point-redundancy@policy-engine": {
				types.Unlikely, types.MediumImpact, types.MediumSeverity,
			},
		},
		"unprotected-authorization-decisions": {
			"unprotected-authorization-decisions@legacy-service@legacy-service>legacy-decisions": {
				types.Likely, types.MediumImpact, types.ElevatedSeverity,
			},
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
