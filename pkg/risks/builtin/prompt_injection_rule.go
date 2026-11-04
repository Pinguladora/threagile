package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

type PromptInjectionRule struct{}

func NewPromptInjectionRule() *PromptInjectionRule {
	return &PromptInjectionRule{}
}

func (*PromptInjectionRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "prompt-injection",
		Title: "Prompt Injection",
		Description: "A language model cannot tell the instructions of its prompt apart from the data in it. " +
			"Content that reaches a model or an agent from users, the internet or another trust zone can carry " +
			"instructions of its own, either directly in a request or indirectly in a document, a web page or a " +
			"tool response the model reads, and so take over what the model does.",
		Impact: "If this risk is unmitigated, attackers might make the model leak what it has access to, give " +
			"misleading answers, or, for an agent, use its tools and permissions for their own goals.",
		ASVS:       asvsValidation,
		CheatSheet: cheatSheetLLMPromptInjection,
		Action:     "Prompt Injection Defenses",
		Mitigation: "Treat everything a model reads as untrusted, including retrieved documents and tool responses: " +
			"keep instructions apart from data (for example with clearly delimited and labelled content), filter " +
			"input and output, and give the model and its tools only the permissions the task needs. Require a " +
			"human approval for actions with side effects, and monitor for injection attempts. See the " +
			"OWASP GenAI Security Project at " + htmlLink(owaspGenAIProject) + ".",
		Check:    checkCheatSheetAndASVS,
		Function: types.Development,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "In-scope " + types.LLM + " and " + types.AIAgent + " technical assets that untrusted " +
			"content reaches: they are on the internet, are called across a network trust boundary, read from " +
			"internet assets (directly or through a tool that does), or are sent requests, directly or through " +
			"other technical assets, by internet assets or clients used by humans.",
		RiskAssessment: "The risk rating depends on the sensitivity of the data processed by the model or agent, " +
			"raised by one step for agents as they act on what they read. Talking to the internet directly makes the " +
			"attack very likely, other untrusted input likely.",
		FalsePositives: "Models that only ever see content from fully trusted sources, for example a fixed set of " +
			"internal documents reviewed before ingestion, can be considered as false positives after individual " +
			"review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweImproperLLMPromptNeutralize,
		References: []string{
			owaspLLMPromptInjection, owaspAgenticGoalHijack, maestroFoundationModels, maestroAgentFrameworks,
		},
	}
}

func (*PromptInjectionRule) SupportedTags() []string {
	return []string{}
}

func (r *PromptInjectionRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	untrusted := untrustedAssets(input)
	for _, technicalAsset := range input.InScopeTechnicalAssets() {
		if !isPromptedAsset(technicalAsset) || !takesUntrustedInput(input, untrusted, technicalAsset) {
			continue
		}
		risks = append(risks, r.createRisk(input, untrusted, technicalAsset))
	}
	return risks, nil
}

func (r *PromptInjectionRule) createRisk(
	input *types.Model, untrusted map[string]bool, technicalAsset *types.TechnicalAsset,
) *types.Risk {
	likelihood := types.Likely
	if isInternetAdjacent(input, technicalAsset) {
		likelihood = types.VeryLikely
	}

	impact := processedImpact(input, technicalAsset)
	if isAIAgent(technicalAsset) {
		impact = raiseImpact(impact)
	}

	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        aiRiskTitle("Prompt Injection", technicalAsset, ""),
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Possible,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	if links := untrustedInputLinks(input, untrusted, technicalAsset); len(links) > 0 {
		risk.MostRelevantCommunicationLinkId = links[0].Id
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
