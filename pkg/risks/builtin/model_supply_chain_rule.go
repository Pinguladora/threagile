package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

type ModelSupplyChainRule struct{}

func NewModelSupplyChainRule() *ModelSupplyChainRule {
	return &ModelSupplyChainRule{}
}

func (*ModelSupplyChainRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "model-supply-chain",
		Title: "Unverified Model Supply Chain",
		Description: "Model weights are code in all but name: they decide what the system answers, and some " +
			"model formats run code when they are loaded. Models that are self-hosted, fine-tuned or pulled " +
			"from a model registry can be swapped, backdoored or poisoned anywhere between their training and " +
			"their deployment.",
		Impact: "If this risk is unmitigated, attackers might deploy a backdoored or tampered model that answers " +
			"as they want, leaks data or runs code on the systems that load it.",
		ASVS:       asvsConfiguration,
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html",
		Action:     "Model Provenance",
		Mitigation: "Take models only from trusted sources, pin them by digest and verify their signatures or " +
			"hashes before they are loaded. Keep a bill of materials of the models and their training data (an ML " +
			"BOM), prefer formats that cannot run code when loaded (like safetensors), restrict who can write to " +
			"the model registry, and evaluate a model before it reaches production.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Operations,
		STRIDE:   types.Tampering,
		DetectionLogic: "In-scope " + types.ModelRegistry + " technical assets, and in-scope " + types.LLM +
			" technical assets that are custom-developed or communicate with a " + types.ModelRegistry + ".",
		RiskAssessment: "The risk rating depends on the sensitivity of the data processed by the model, or by the " +
			"models a registry serves.",
		FalsePositives: "Models whose provenance is verified on every deployment, for example by signature checks " +
			"in the deployment pipeline, can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweDownloadWithoutIntegrity,
		References: []string{
			owaspLLMSupplyChain, owaspLLMDataAndModelPoisoning, owaspAgenticSupplyChain, maestroFoundationModels,
		},
	}
}

func (*ModelSupplyChainRule) SupportedTags() []string {
	return []string{}
}

func (r *ModelSupplyChainRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, technicalAsset := range input.InScopeTechnicalAssets() {
		switch {
		case technicalAsset.Technologies.GetAttribute(types.ModelRegistry):
			impact := types.LowImpact
			for _, model := range connectedLanguageModels(input, technicalAsset) {
				impact = max(impact, processedImpact(input, model))
			}
			impact = max(impact, processedImpact(input, technicalAsset))
			risks = append(risks, r.createRisk(technicalAsset, impact))

		case isLanguageModel(technicalAsset) &&
			(technicalAsset.CustomDevelopedParts || len(connectedModelRegistries(input, technicalAsset)) > 0):
			risks = append(risks, r.createRisk(technicalAsset, processedImpact(input, technicalAsset)))
		}
	}
	return risks, nil
}

// connectedLanguageModels returns the language models that communicate with the technical asset, sorted by id.
func connectedLanguageModels(input *types.Model, technicalAsset *types.TechnicalAsset) []*types.TechnicalAsset {
	return connectedAssets(input, technicalAsset, isLanguageModel)
}

// connectedModelRegistries returns the model registries that communicate with the technical asset, sorted by id.
func connectedModelRegistries(input *types.Model, technicalAsset *types.TechnicalAsset) []*types.TechnicalAsset {
	return connectedAssets(input, technicalAsset, func(other *types.TechnicalAsset) bool {
		return other.Technologies.GetAttribute(types.ModelRegistry)
	})
}

// connectedAssets returns the technical assets that communicate with the technical asset, in either direction,
// and match, sorted by id.
func connectedAssets(
	input *types.Model, technicalAsset *types.TechnicalAsset, match func(*types.TechnicalAsset) bool,
) []*types.TechnicalAsset {
	result := make([]*types.TechnicalAsset, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		other := input.TechnicalAssets[id]
		if other.Id != technicalAsset.Id && match(other) &&
			(input.HasDirectConnection(other, technicalAsset.Id) || input.HasDirectConnection(technicalAsset, other.Id)) {
			result = append(result, other)
		}
	}
	return result
}

func (r *ModelSupplyChainRule) createRisk(technicalAsset *types.TechnicalAsset, impact types.RiskExploitationImpact,
) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood:       types.Unlikely,
		ExploitationImpact:           impact,
		Title:                        aiRiskTitle("Unverified Model Supply Chain", technicalAsset, ""),
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
