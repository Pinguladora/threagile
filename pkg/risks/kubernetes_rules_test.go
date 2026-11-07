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

// TestKubernetesRulesEndToEnd analyzes a cluster with all built-in rules and checks the risks of the Kubernetes rules.
// The model also holds what the rules must skip: a namespace whose policies restrict both directions, one without
// policies that holds only public data, namespaces whose policies are not modelled, readonly access to the Kubernetes
// API, a deployment and an administrator.
func TestKubernetesRulesEndToEnd(t *testing.T) {
	config := new(threagile.Config).Defaults("")
	config.SetAppFolder(t.TempDir())
	config.SetPluginFolder(t.TempDir())
	config.SetInputFile("testdata/kubernetes-rules/threagile.yaml")
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
		"missing-network-policy": {
			// no policy at all: every pod of the cluster reaches the namespace
			"missing-network-policy@shop-namespace": {types.Likely, types.MediumImpact, types.ElevatedSeverity},
			// incoming traffic restricted, outgoing not
			"missing-network-policy@orders-namespace": {types.Unlikely, types.MediumImpact, types.MediumSeverity},
		},
		"privileged-workload": {
			// next to the internet
			"privileged-workload@frontend": {types.Likely, types.MediumImpact, types.ElevatedSeverity},
			// a node agent with no sensitive data of its own, rated by what shares its node pool
			"privileged-workload@log-agent": {types.Unlikely, types.MediumImpact, types.MediumSeverity},
		},
		"kubernetes-api-write-access": {
			"kubernetes-api-write-access@frontend@frontend>create-jobs": {
				types.Likely, types.MediumImpact, types.ElevatedSeverity,
			},
			"kubernetes-api-write-access@operator@operator>reconcile": {
				types.Unlikely, types.MediumImpact, types.MediumSeverity,
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
