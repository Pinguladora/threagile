package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

type ModelOutputDisclosureRule struct{}

func NewModelOutputDisclosureRule() *ModelOutputDisclosureRule {
	return &ModelOutputDisclosureRule{}
}

func (*ModelOutputDisclosureRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "model-output-disclosure",
		Title: "Sensitive Data Disclosure through Model Output",
		Description: "Whatever a language model or an agent can read, it can be talked into writing: data in its " +
			"prompt, in its context window, in the documents it retrieves or in its training data. A model that " +
			"has confidential data at hand and answers callers from the internet, from users or from another " +
			"trust zone may hand that data to callers who are not allowed to see it.",
		Impact: "If this risk is unmitigated, attackers might extract confidential data, other users' data or the " +
			"system prompt through crafted questions.",
		ASVS:       asvsDataProtection,
		CheatSheet: cheatSheetLLMPromptInjection,
		Action:     "Output Data Protection",
		Mitigation: "Give the model only the data the caller may see: filter retrieved documents by the caller's " +
			"permissions before they reach the prompt, keep secrets and other users' data out of prompts and " +
			"training data, and filter the output for sensitive data. Do not rely on the system prompt to keep " +
			"anything secret.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Architecture,
		STRIDE:   types.InformationDisclosure,
		DetectionLogic: "In-scope " + types.LLM + " and " + types.AIAgent + " technical assets that take untrusted " +
			"input (as the prompt-injection rule defines it) and process, or read from a " + types.VectorDatabase +
			" technical asset, data rated at least as " + types.Confidential.String() + ".",
		RiskAssessment: "The risk rating depends on the confidentiality of the data the model or agent can read. " +
			"Talking to the internet directly makes the attack very likely, other untrusted input likely.",
		FalsePositives: "Models that only read data every one of their callers may see can be considered as false " +
			"positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweSensitiveInformationExposure,
		References:                 []string{owaspLLMSensitiveInformation, maestroFoundationModels},
	}
}

func (*ModelOutputDisclosureRule) SupportedTags() []string {
	return []string{}
}

func (r *ModelOutputDisclosureRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	untrusted := untrustedAssets(input)
	for _, technicalAsset := range input.InScopeTechnicalAssets() {
		if !isPromptedAsset(technicalAsset) || !takesUntrustedInput(input, untrusted, technicalAsset) {
			continue
		}
		stores := connectedAssets(input, technicalAsset, func(other *types.TechnicalAsset) bool {
			return other.Technologies.GetAttribute(types.VectorDatabase)
		})
		confidentiality := input.HighestProcessedConfidentiality(technicalAsset)
		for _, store := range stores {
			confidentiality = max(confidentiality, input.HighestStoredConfidentiality(store))
		}
		if confidentiality < types.Confidential {
			continue
		}
		risks = append(risks, r.createRisk(input, technicalAsset, stores, confidentiality))
	}
	return risks, nil
}

func (r *ModelOutputDisclosureRule) createRisk(
	input *types.Model, technicalAsset *types.TechnicalAsset, stores []*types.TechnicalAsset,
	confidentiality types.Confidentiality,
) *types.Risk {
	likelihood := types.Likely
	if isInternetAdjacent(input, technicalAsset) {
		likelihood = types.VeryLikely
	}
	impact := aiRiskImpact(confidentiality, types.Archive, types.Archive)

	breachAssets := make([]string, 0, 1+len(stores))
	breachAssets = append(breachAssets, technicalAsset.Id)
	for _, store := range stores {
		breachAssets = append(breachAssets, store.Id)
	}
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        aiRiskTitle("Sensitive Data Disclosure through Model Output", technicalAsset, ""),
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  breachAssets,
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
