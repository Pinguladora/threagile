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

// TestAIRulesEndToEnd analyzes a support assistant with all built-in rules and checks the risks of the AI rules.
// The model also holds what the rules must skip: an agent and a link tagged human-in-the-loop, a readonly link,
// a call to a language model, an MCP server whose tools reach nothing sensitive, and an out-of-scope model on
// the internet, whose responses are no internet content.
func TestAIRulesEndToEnd(t *testing.T) {
	config := new(threagile.Config).Defaults("")
	config.SetAppFolder(t.TempDir())
	config.SetPluginFolder(t.TempDir())
	config.SetInputFile("testdata/ai-rules/threagile.yaml")
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
		"prompt-injection": {
			// the agent acts on what it reads, which raises the impact
			"prompt-injection@support-agent": {types.Likely, types.HighImpact, types.ElevatedSeverity},
			"prompt-injection@inference":     {types.Likely, types.MediumImpact, types.ElevatedSeverity},
		},
		"excessive-agency": {
			// through the tools of the MCP server
			"excessive-agency@support-agent@support-agent>tool-calls": {
				types.Likely, types.MediumImpact, types.ElevatedSeverity,
			},
			"excessive-agency@reporting-agent@reporting-agent>order-fix": {
				types.Unlikely, types.MediumImpact, types.MediumSeverity,
			},
		},
		"vector-store-poisoning": {
			// the support agent, which takes untrusted input, writes its memory into the knowledge base
			"vector-store-poisoning@knowledge-base": {types.Likely, types.MediumImpact, types.ElevatedSeverity},
			"vector-store-poisoning@policy-index":   {types.Unlikely, types.MediumImpact, types.MediumSeverity},
		},
		"model-supply-chain": {
			"model-supply-chain@inference":      {types.Unlikely, types.MediumImpact, types.MediumSeverity},
			"model-supply-chain@model-registry": {types.Unlikely, types.MediumImpact, types.MediumSeverity},
		},
		"model-output-disclosure": {
			"model-output-disclosure@support-agent": {types.Likely, types.MediumImpact, types.ElevatedSeverity},
			"model-output-disclosure@inference":     {types.Likely, types.MediumImpact, types.ElevatedSeverity},
		},
		"unauthenticated-mcp-server": {
			"unauthenticated-mcp-server@mcp-tools@support-agent>tool-calls": {
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
