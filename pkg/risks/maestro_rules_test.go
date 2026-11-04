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

// TestMAESTRORulesEndToEnd analyzes a chat service with all built-in rules and checks the risks of the rules on
// AI guardrails and AI monitoring. The model also holds what the rules must skip: a guardrail service in the path
// of the content, a guardrail library inside an agent, an agent asking a guardrail service, a model that only an
// agent sends content to, an agent that only trusted content reaches, monitoring links in both directions and a
// model on the internet.
func TestMAESTRORulesEndToEnd(t *testing.T) {
	config := new(threagile.Config).Defaults("")
	config.SetAppFolder(t.TempDir())
	config.SetPluginFolder(t.TempDir())
	config.SetInputFile("testdata/maestro-rules/threagile.yaml")
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
		"missing-ai-guardrail": {
			// called from the internet
			"missing-ai-guardrail@plain-agent": {types.Likely, types.MediumImpact, types.ElevatedSeverity},
			"missing-ai-guardrail@summarizer":  {types.Unlikely, types.MediumImpact, types.MediumSeverity},
		},
		"missing-ai-monitoring": {
			"missing-ai-monitoring@planner":    {types.Likely, types.MediumImpact, types.ElevatedSeverity},
			"missing-ai-monitoring@summarizer": {types.Likely, types.MediumImpact, types.ElevatedSeverity},
			// only trusted content reaches it
			"missing-ai-monitoring@batch-agent": {types.Unlikely, types.MediumImpact, types.MediumSeverity},
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
