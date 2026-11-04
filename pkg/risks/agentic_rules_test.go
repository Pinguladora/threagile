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

// TestAgenticRulesEndToEnd analyzes agents working together and running code with all built-in rules and checks
// the risks of the rules on them. The model also holds what the rules must skip: a short-lived token over TLS, an
// agent that can change nothing sensitive, agents within one process, an out-of-scope agent, a caller that is no
// agent, a sandbox the code cannot leave, and interpreters of code that only trusted content shapes.
func TestAgenticRulesEndToEnd(t *testing.T) {
	config := new(threagile.Config).Defaults("")
	config.SetAppFolder(t.TempDir())
	config.SetPluginFolder(t.TempDir())
	config.SetInputFile("testdata/agentic-rules/threagile.yaml")
	config.SetOutputFolder(t.TempDir())
	config.SetTempFolder(t.TempDir())

	result, err := model.ReadAndAnalyzeModel(config, risks.GetBuiltInRiskRules(), testReporter{t})
	require.NoError(t, err)

	type expectedRisk struct {
		likelihood types.RiskExploitationLikelihood
		impact     types.RiskExploitationImpact
		severity   types.RiskSeverity
		title      string
	}
	const (
		interAgent    = "<b>Insecure Inter-Agent Communication</b> risk at "
		codeExecution = "<b>Unsandboxed Code Execution</b> risk at "
	)
	expected := map[string]map[string]expectedRisk{
		"insecure-inter-agent-communication": {
			// across a network trust boundary
			"insecure-inter-agent-communication@worker-a@orchestrator>task-a": {
				types.Likely, types.MediumImpact, types.ElevatedSeverity,
				interAgent + "<b>Worker A</b> from <b>Orchestrator</b> (unauthenticated)",
			},
			"insecure-inter-agent-communication@worker-b@orchestrator>task-b": {
				types.Unlikely, types.MediumImpact, types.MediumSeverity,
				interAgent + "<b>Worker B</b> from <b>Orchestrator</b> (long-lived-token, unencrypted)",
			},
			// changes the orders through the tools of the MCP server
			"insecure-inter-agent-communication@worker-g@orchestrator>task-g": {
				types.Unlikely, types.MediumImpact, types.MediumSeverity,
				interAgent + "<b>Worker G</b> from <b>Orchestrator</b> (unauthenticated)",
			},
		},
		"unsandboxed-code-execution": {
			// the agent writing the code talks to the browser on the internet
			"unsandboxed-code-execution@linked-interpreter": {
				types.VeryLikely, types.MediumImpact, types.ElevatedSeverity,
				codeExecution + "<b>Linked Interpreter</b> running code of <b>Coding Agent</b>",
			},
			"unsandboxed-code-execution@egress-interpreter": {
				types.VeryLikely, types.MediumImpact, types.ElevatedSeverity,
				codeExecution + "<b>Egress Interpreter</b> running code of <b>Coding Agent</b>",
			},
			"unsandboxed-code-execution@runtime-interpreter": {
				types.VeryLikely, types.MediumImpact, types.ElevatedSeverity,
				codeExecution + "<b>Runtime Interpreter</b> running code of <b>Coding Agent</b>",
			},
			// inside the agent
			"unsandboxed-code-execution@notebook-agent": {
				types.VeryLikely, types.MediumImpact, types.ElevatedSeverity, codeExecution + "<b>Notebook Agent</b>",
			},
		},
	}

	for category, expectedRisks := range expected {
		t.Run(category, func(t *testing.T) {
			got := make(map[string]expectedRisk)
			for _, risk := range result.ParsedModel.GeneratedRisksByCategory[category] {
				got[risk.SyntheticId] = expectedRisk{
					risk.ExploitationLikelihood, risk.ExploitationImpact, risk.Severity, risk.Title,
				}
			}
			assert.Equal(t, expectedRisks, got)
		})
	}
}
