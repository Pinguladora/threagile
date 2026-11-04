package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

type VectorStorePoisoningRule struct{}

func NewVectorStorePoisoningRule() *VectorStorePoisoningRule {
	return &VectorStorePoisoningRule{}
}

func (*VectorStorePoisoningRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "vector-store-poisoning",
		Title: "Vector Store Poisoning",
		Description: "Language models and agents answer and act on what they retrieve from vector stores, for " +
			"retrieval-augmented generation (RAG) or as the memory of an agent. Whoever can write into the store " +
			"decides what the model believes: a poisoned document or memory entry carries false facts or hidden " +
			"instructions into every answer that retrieves it, long after it was written.",
		Impact: "If this risk is unmitigated, attackers might plant content that misleads the model, injects " +
			"instructions into its prompts or makes it disclose data, persistently and for every user.",
		ASVS:       asvsValidation,
		CheatSheet: cheatSheetLLMPromptInjection,
		Action:     "Ingestion Integrity",
		Mitigation: "Ingest only content from vetted sources, record where each entry came from and validate it " +
			"before it is embedded. Keep the entries of different users and tenants apart with access controls " +
			"at retrieval time, limit what agents may write into their memory, and review and expire stored " +
			"entries regularly.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Architecture,
		STRIDE:   types.Tampering,
		DetectionLogic: "In-scope " + types.VectorDatabase + " technical assets that an " + types.LLM + " or " +
			types.AIAgent + " technical asset communicates with.",
		RiskAssessment: "The risk rating depends on the sensitivity of the data processed by the models and agents " +
			"that use the store. The attack is likely when the store is written by an asset that takes untrusted " +
			"input or sits across a network trust boundary, and unlikely otherwise.",
		FalsePositives: "Vector stores filled only from fully trusted and reviewed content can be considered as " +
			"false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweInsufficientAuthenticity,
		References: []string{
			owaspLLMDataAndModelPoisoning, owaspLLMVectorAndEmbedding, owaspAgenticMemoryPoisoning,
			maestroDataOperations,
		},
	}
}

func (*VectorStorePoisoningRule) SupportedTags() []string {
	return []string{}
}

func (r *VectorStorePoisoningRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	untrusted := untrustedAssets(input)
	for _, store := range input.InScopeTechnicalAssets() {
		if !store.Technologies.GetAttribute(types.VectorDatabase) {
			continue
		}
		users := connectedAssets(input, store, isPromptedAsset)
		if len(users) == 0 {
			continue
		}
		risks = append(risks, r.createRisk(input, store, users, writtenFromUntrustedSource(input, untrusted, store)))
	}
	return risks, nil
}

// writtenFromUntrustedSource reports whether a non-readonly link from an asset that takes untrusted input, or
// from across a network trust boundary, writes into the store. Agents writing into their memory count as well.
func writtenFromUntrustedSource(input *types.Model, untrusted map[string]bool, store *types.TechnicalAsset) bool {
	for _, link := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[store.Id] {
		source, ok := input.TechnicalAssets[link.SourceId]
		if !ok || link.Readonly {
			continue
		}
		if takesUntrustedInput(input, untrusted, source) || isAcrossTrustBoundaryNetworkOnly(input, link) {
			return true
		}
	}
	return false
}

func (r *VectorStorePoisoningRule) createRisk(
	input *types.Model, store *types.TechnicalAsset, users []*types.TechnicalAsset, untrustedWriter bool,
) *types.Risk {
	likelihood := types.Unlikely
	if untrustedWriter {
		likelihood = types.Likely
	}
	impact := types.LowImpact
	for _, user := range users {
		impact = max(impact, processedImpact(input, user))
	}

	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        assetRiskTitle("Vector Store Poisoning", store, "used by <b>"+users[0].Title+"</b>"),
		MostRelevantTechnicalAssetId: store.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{store.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + store.Id
	return risk
}
