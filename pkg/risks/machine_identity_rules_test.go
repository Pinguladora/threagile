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

// TestMachineIdentityRulesEndToEnd analyzes a shop with all built-in rules and checks the risks of the rules on
// machine identities. The model also holds what the rules must skip: an administrator's own identity, a service
// account used by people for public data, an account of a single caller, the share of an out-of-scope caller, an
// agent that passes on the identity of its users, an agent that acts for no user and the identity of an agent
// towards its language model.
func TestMachineIdentityRulesEndToEnd(t *testing.T) {
	config := new(threagile.Config).Defaults("")
	config.SetAppFolder(t.TempDir())
	config.SetPluginFolder(t.TempDir())
	config.SetInputFile("testdata/machine-identity-rules/threagile.yaml")
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
		"human-use-of-machine-identity": {
			"human-use-of-machine-identity@orders-db@admin-laptop>db-admin": {
				types.Likely, types.MediumImpact, types.ElevatedSeverity,
			},
		},
		"shared-machine-account": {
			// shared with the administrator in the office network
			"shared-machine-account@shop-api@orders-db-owner": {types.Likely, types.MediumImpact, types.ElevatedSeverity},
			// shared within the shop network
			"shared-machine-account@report-job@report-role": {types.Unlikely, types.MediumImpact, types.MediumSeverity},
			"shared-machine-account@analytics-job@report-role": {
				types.Unlikely, types.MediumImpact, types.MediumSeverity,
			},
		},
		"confused-deputy-agent": {
			// through the tools of the MCP server
			"confused-deputy-agent@support-agent": {types.Likely, types.MediumImpact, types.ElevatedSeverity},
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

	deputies := result.ParsedModel.GeneratedRisksByCategory["confused-deputy-agent"]
	require.Len(t, deputies, 1)
	assert.Equal(t, []string{"orders-db"}, deputies[0].DataBreachTechnicalAssetIDs, "the language model is no target")
}
