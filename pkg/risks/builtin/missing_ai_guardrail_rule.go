package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

type MissingAIGuardrailRule struct{}

func NewMissingAIGuardrailRule() *MissingAIGuardrailRule {
	return &MissingAIGuardrailRule{}
}

func (*MissingAIGuardrailRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-ai-guardrail",
		Title: "Missing AI Guardrail",
		Description: "A guardrail screens what reaches a language model or an agent, and what comes back from it, " +
			"for prompt injection, jailbreaks and data that must not pass, independently of the model. Without " +
			"one, the instructions of the system prompt are the only defense, and a model follows whatever " +
			"content convinces it.",
		Impact: "If this risk is unmitigated, prompt injections and jailbreaks reach the model or the agent " +
			"unchecked, and harmful or confidential output leaves it unchecked.",
		ASVS:       asvsValidation,
		CheatSheet: cheatSheetLLMPromptInjection,
		Action:     "AI Guardrails",
		Mitigation: "Screen the untrusted input of the model or agent, and its output, with a guardrail like a " +
			"prompt injection classifier, a content safety service or a policy framework for agents, and block or " +
			"flag what it finds. Model a guardrail service as an " + types.AIGuardrail + " technical asset in the " +
			"path of the untrusted content, or one the agent asks, and a guardrail library inside the agent by " +
			"adding " + types.AIGuardrail + " to the technologies of the agent. A guardrail lowers the risk of " +
			"prompt injection, but does not remove it.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Architecture,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "In-scope " + types.LLM + " and " + types.AIAgent + " technical assets that untrusted " +
			"content reaches (as for prompt injection) through a communication link that no guardrail screens. A " +
			"link is screened when it comes from an " + types.AIGuardrail + " technical asset, or when the model or " +
			"agent is one itself or has a link to one. Links from other language models and agents are skipped, " +
			"as the rule reports a missing guardrail where the content first reaches a model.",
		RiskAssessment: "The risk rating depends on the sensitivity of the data processed by the model or agent. " +
			"The attack is likely when the model or agent talks to the internet directly, and unlikely otherwise.",
		FalsePositives: "Models and agents whose platform screens their input and output without a modelled " +
			"guardrail, like a managed model service with content filtering turned on, can be considered as false " +
			"positives after individual review.",
		ModelFailurePossibleReason: true,
		CWE:                        cweImproperLLMPromptNeutralize,
		References: []string{
			maestroSecurityAndCompliance, owaspLLMPromptInjection, owaspAgenticGoalHijack,
		},
	}
}

func (*MissingAIGuardrailRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingAIGuardrailRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	untrusted := untrustedAssets(input)
	for _, technicalAsset := range input.InScopeTechnicalAssets() {
		if !isPromptedAsset(technicalAsset) || r.isGuarded(input, technicalAsset) {
			continue
		}
		if links := r.unscreenedInputLinks(input, untrusted, technicalAsset); len(links) > 0 {
			risks = append(risks, r.createRisk(input, technicalAsset, links[0]))
		}
	}
	return risks, nil
}

// isGuarded reports whether a guardrail screens all content of the model or agent: it is a guardrail itself, as
// a library inside it, or it asks one.
func (r *MissingAIGuardrailRule) isGuarded(input *types.Model, technicalAsset *types.TechnicalAsset) bool {
	if isAIGuardrail(technicalAsset) {
		return true
	}
	for _, link := range technicalAsset.CommunicationLinks {
		if target, ok := input.TechnicalAssets[link.TargetId]; ok && isAIGuardrail(target) {
			return true
		}
	}
	return false
}

// unscreenedInputLinks returns, sorted by id, the links that bring untrusted content into the model or agent
// without passing a guardrail. Links from other models and agents are left to the rule at those.
func (r *MissingAIGuardrailRule) unscreenedInputLinks(
	input *types.Model, untrusted map[string]bool, technicalAsset *types.TechnicalAsset,
) []*types.CommunicationLink {
	links := make([]*types.CommunicationLink, 0)
	for _, link := range untrustedInputLinks(input, untrusted, technicalAsset) {
		if link.TargetId == technicalAsset.Id {
			source, ok := input.TechnicalAssets[link.SourceId]
			if !ok || isAIGuardrail(source) || isPromptedAsset(source) {
				continue
			}
		}
		links = append(links, link)
	}
	return links
}

func (r *MissingAIGuardrailRule) createRisk(
	input *types.Model, technicalAsset *types.TechnicalAsset, link *types.CommunicationLink,
) *types.Risk {
	likelihood := types.Unlikely
	if isInternetAdjacent(input, technicalAsset) {
		likelihood = types.Likely
	}
	impact := processedImpact(input, technicalAsset)

	risk := &types.Risk{
		CategoryId:                      r.Category().ID,
		Severity:                        types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           assetRiskTitle("Missing AI Guardrail", technicalAsset, ""),
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: link.Id,
		DataBreachProbability:           types.Possible,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
