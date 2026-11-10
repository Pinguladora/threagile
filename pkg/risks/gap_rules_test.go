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

// TestGapRulesEndToEnd analyzes a shop with all built-in rules and checks the risks of the rules on overprivileged
// machine identities and unbounded model consumption. The model also holds what the rules must skip: a readonly
// link, an authorization by role or not modelled, the identity of a user, a target with no sensitive data, an
// out-of-scope target with no sensitive data, an out-of-scope caller of an out-of-scope target, a gateway
// in front of an agent, an agent calling its model through a gateway, and a model that no user reaches.
func TestGapRulesEndToEnd(t *testing.T) {
	config := new(threagile.Config).Defaults("")
	config.SetAppFolder(t.TempDir())
	config.SetPluginFolder(t.TempDir())
	config.SetInputFile("testdata/gap-rules/threagile.yaml")
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
		"overprivileged-machine-identity": {
			// across a network trust boundary
			"overprivileged-machine-identity@orders-db@deployer>schema-admin": {
				types.Likely, types.MediumImpact, types.ElevatedSeverity,
			},
			"overprivileged-machine-identity@orders-db@order-service>order-storage": {
				types.Unlikely, types.MediumImpact, types.MediumSeverity,
			},
			// out of scope, one level lower, and on the internet
			"overprivileged-machine-identity@cloud-api@deployer>provision": {
				types.Likely, types.LowImpact, types.MediumSeverity,
			},
		},
		"unbounded-model-consumption": {
			// from the internet, directly and through the open agent
			"unbounded-model-consumption@open-agent":   {types.VeryLikely, types.MediumImpact, types.ElevatedSeverity},
			"unbounded-model-consumption@shared-model": {types.VeryLikely, types.MediumImpact, types.ElevatedSeverity},
			// calls one of its models directly
			"unbounded-model-consumption@mixed-agent": {types.VeryLikely, types.MediumImpact, types.ElevatedSeverity},
			// from staff through an application, mission-critical
			"unbounded-model-consumption@staff-model": {types.Likely, types.HighImpact, types.ElevatedSeverity},
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

	for _, risk := range result.ParsedModel.GeneratedRisksByCategory["overprivileged-machine-identity"] {
		if risk.SyntheticId == "overprivileged-machine-identity@cloud-api@deployer>provision" {
			assert.Equal(t, "deployer", risk.MostRelevantTechnicalAssetId, "the in-scope caller, for an out-of-scope target")
			assert.Equal(t, []string{"cloud-api"}, risk.DataBreachTechnicalAssetIDs)
		}
	}
}
