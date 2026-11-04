package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

type UnsandboxedCodeExecutionRule struct{}

func NewUnsandboxedCodeExecutionRule() *UnsandboxedCodeExecutionRule {
	return &UnsandboxedCodeExecutionRule{}
}

func (*UnsandboxedCodeExecutionRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "unsandboxed-code-execution",
		Title: "Unsandboxed Code Execution",
		Description: "A code interpreter runs the code that a language model or an AI agent writes. When untrusted " +
			"content reaches the model, a prompt injection decides what that code does, and the code can do " +
			"whatever the interpreter can reach: the systems it has links to, the internet, and the other assets " +
			"of the runtime it shares, or all of the agent when it runs inside it.",
		Impact: "If this risk is unmitigated, attackers might run code of their choice to read, change or exfiltrate " +
			"the data the interpreter can reach, or to move on to other systems from it.",
		ASVS:       asvsValidation,
		CheatSheet: cheatSheetLLMPromptInjection,
		Action:     "Sandboxed Code Execution",
		Mitigation: "Run the code in a sandbox of its own, like a microVM or gVisor, created for each task and " +
			"thrown away after it, without credentials, without network access other than what the task needs, " +
			"and with limits on time and resources. Model the sandbox as a " + types.CodeInterpreter + " " +
			"technical asset outside of the shared runtimes of other assets, with only the links the code needs.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Architecture,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "In-scope " + types.CodeInterpreter + " technical assets that a language model or an AI " +
			"agent taking untrusted content (as for prompt injection) sends code to, or that are such a model or " +
			"agent themselves, when the code can reach data rated at least as " + types.Confidential.String() +
			" or " + types.Critical.String() + ": through a link of the interpreter, in an asset of a shared " +
			"runtime it runs in, by sending what it processes to an internet asset, or, inside an agent, through " +
			"what the agent processes and can change.",
		RiskAssessment: "The risk rating depends on the most sensitive data the code can reach. The attack is very " +
			"likely when the model or agent writing the code talks to the internet directly, and likely otherwise.",
		FalsePositives: "Interpreters that run only code reviewed by a human before it runs can be considered as " +
			"false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweCodeInjection,
		References: []string{
			owaspAgenticCodeExecution, owaspLLMImproperOutputHandling, maestroAgentFrameworks,
			maestroDeploymentAndInfrastucture,
		},
	}
}

func (*UnsandboxedCodeExecutionRule) SupportedTags() []string {
	return []string{}
}

func (r *UnsandboxedCodeExecutionRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	untrusted := untrustedAssets(input)
	for _, interpreter := range input.InScopeTechnicalAssets() {
		if !interpreter.Technologies.GetAttribute(types.CodeInterpreter) {
			continue
		}
		writer, link := r.untrustedCodeWriter(input, untrusted, interpreter)
		if writer == nil {
			continue
		}
		if reach := r.codeReach(input, interpreter); reach >= types.MediumImpact {
			risks = append(risks, r.createRisk(input, interpreter, writer, link, reach))
		}
	}
	return risks, nil
}

// untrustedCodeWriter returns the language model or agent taking untrusted content that writes the code the
// interpreter runs: the interpreter itself, when it runs inside one, or the source of an incoming link, with that
// link.
func (r *UnsandboxedCodeExecutionRule) untrustedCodeWriter(
	input *types.Model, untrusted map[string]bool, interpreter *types.TechnicalAsset,
) (*types.TechnicalAsset, *types.CommunicationLink) {
	if isPromptedAsset(interpreter) {
		if takesUntrustedInput(input, untrusted, interpreter) {
			return interpreter, nil
		}
		return nil, nil
	}
	for _, link := range sortedIncomingLinks(input, interpreter) {
		writer, ok := input.TechnicalAssets[link.SourceId]
		if ok && isPromptedAsset(writer) && takesUntrustedInput(input, untrusted, writer) {
			return writer, link
		}
	}
	return nil, nil
}

// codeReach rates the most sensitive data that code in the interpreter can reach. Inside an agent, that is all the
// agent can do. Otherwise, it is the targets of the links of the interpreter, the other assets of the shared
// runtimes it runs in and, when it can send to an internet asset, the data it processes.
func (r *UnsandboxedCodeExecutionRule) codeReach(
	input *types.Model, interpreter *types.TechnicalAsset,
) types.RiskExploitationImpact {
	if isPromptedAsset(interpreter) {
		return agentReach(input, interpreter)
	}
	reach := types.LowImpact
	for _, link := range interpreter.CommunicationLinksSorted() {
		target, ok := input.TechnicalAssets[link.TargetId]
		if !ok || isLanguageModel(target) {
			continue
		}
		reach = max(reach, assetImpact(input, target))
		if target.Internet {
			reach = max(reach, processedImpact(input, interpreter))
		}
	}
	return max(reach, runtimeNeighbourImpact(input, interpreter))
}

// runtimeNeighbourImpact rates the most sensitive of the other technical assets in the shared runtimes that the
// technical asset runs in.
func runtimeNeighbourImpact(input *types.Model, technicalAsset *types.TechnicalAsset) types.RiskExploitationImpact {
	impact := types.LowImpact
	for _, runtime := range input.SharedRuntimes {
		if !contains(runtime.TechnicalAssetsRunning, technicalAsset.Id) {
			continue
		}
		for _, id := range runtime.TechnicalAssetsRunning {
			if neighbour, ok := input.TechnicalAssets[id]; ok && id != technicalAsset.Id {
				impact = max(impact, assetImpact(input, neighbour))
			}
		}
	}
	return impact
}

func (r *UnsandboxedCodeExecutionRule) createRisk(
	input *types.Model, interpreter, writer *types.TechnicalAsset, link *types.CommunicationLink,
	reach types.RiskExploitationImpact,
) *types.Risk {
	likelihood := types.Likely
	if isInternetAdjacent(input, writer) {
		likelihood = types.VeryLikely
	}

	detail := ""
	if writer != interpreter {
		detail = "running code of <b>" + writer.Title + "</b>"
	}
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(likelihood, reach),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           reach,
		Title:                        assetRiskTitle("Unsandboxed Code Execution", interpreter, detail),
		MostRelevantTechnicalAssetId: interpreter.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{interpreter.Id},
	}
	if link != nil {
		risk.MostRelevantCommunicationLinkId = link.Id
	}
	risk.SyntheticId = risk.CategoryId + "@" + interpreter.Id
	return risk
}
