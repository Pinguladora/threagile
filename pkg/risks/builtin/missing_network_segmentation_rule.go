package builtin

import (
	"sort"

	"github.com/Pinguladora/threagile/pkg/types"
)

// networkSegmentationRAALimit is the RAA value (in %) from which technical assets should be segmented from less
// protected ones.
const networkSegmentationRAALimit = 50

type MissingNetworkSegmentationRule struct {
	raaLimit int
}

func NewMissingNetworkSegmentationRule() *MissingNetworkSegmentationRule {
	return &MissingNetworkSegmentationRule{raaLimit: networkSegmentationRAALimit}
}

func (*MissingNetworkSegmentationRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-network-segmentation",
		Title: "Missing Network Segmentation",
		Description: "Highly sensitive assets and/or data stores residing in the same network segment than other " +
			"lower sensitive assets (like webservers or content management systems etc.) should be better protected " +
			"by a network segmentation trust-boundary.",
		Impact: "If this risk is unmitigated, attackers successfully attacking other components of the system might have " +
			"an easy path towards more valuable targets, as they are not separated by network segmentation.",
		ASVS:       asvsArchitecture,
		CheatSheet: cheatSheetAttackSurfaceAnalysis,
		Action:     actionNetworkSegmentation,
		Mitigation: "Apply a network segmentation trust-boundary around the highly sensitive assets and/or data stores.",
		Check:      checkCheatSheetAndASVS,
		Function:   types.Operations,
		STRIDE:     types.ElevationOfPrivilege,
		DetectionLogic: "In-scope technical assets with high sensitivity and RAA values as well as data stores " +
			"when surrounded by assets (without a network trust-boundary in-between) which are of type " +
			types.ClientSystem + ", " + types.WebServer + ", " + types.WebApplication + ", " + types.CMS + ", " +
			types.WebServiceREST + ", " + types.WebServiceSOAP + ", " + types.BuildPipeline + ", " +
			types.SourcecodeRepository + ", " + types.Monitoring + ", or similar and there is no direct connection " +
			"between these (hence no requirement to be so close to each other).",
		RiskAssessment: "Default is " + types.LowSeverity.String() + " risk. The risk is increased to " +
			types.MediumSeverity.String() + " when the asset missing the " +
			"trust-boundary protection is rated as " + types.StrictlyConfidential.String() + " or " +
			types.MissionCritical.String() + ".",
		FalsePositives: "When all assets within the network segmentation trust-boundary are hardened and protected to the " +
			"same extend as if all were containing/processing highly sensitive data.",
		ModelFailurePossibleReason: false,
		CWE:                        cweArchitecturalConcepts,
		References:                 []string{owaspInsecureDesign},
	}
}

func (*MissingNetworkSegmentationRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingNetworkSegmentationRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	// first create them in memory (see the link replacement below for nested trust boundaries) - otherwise in Go
	// ranging over map is random order
	// range over them in sorted (hence re-producible) way:
	keys := make([]string, 0, len(input.TechnicalAssets))
	for k := range input.TechnicalAssets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		technicalAsset := input.TechnicalAssets[key]
		if r.skipAsset(technicalAsset) {
			continue
		}

		// now check for any other same-network assets of certain types which have no direct connection
		if hasUnconnectedLessProtectedNeighbour(input, technicalAsset, keys) {
			highRisk := technicalAsset.Confidentiality == types.StrictlyConfidential ||
				technicalAsset.Integrity == types.MissionCritical || technicalAsset.Availability == types.MissionCritical
			risks = append(risks, r.createRisk(technicalAsset, highRisk))
		}
	}
	return risks, nil
}

func (r *MissingNetworkSegmentationRule) skipAsset(technicalAsset *types.TechnicalAsset) bool {
	if technicalAsset.OutOfScope {
		return true
	}

	if technicalAsset.Technologies.GetAttribute(types.IsNoNetworkSegmentationRequired) {
		return true
	}

	if technicalAsset.RAA < float64(r.raaLimit) {
		return true
	}

	return technicalAsset.Type != types.Datastore &&
		technicalAsset.Confidentiality < types.Confidential &&
		technicalAsset.Integrity < types.Critical &&
		technicalAsset.Availability < types.Critical
}

func hasUnconnectedLessProtectedNeighbour(
	input *types.Model, technicalAsset *types.TechnicalAsset, technicalAssetIDs []string,
) bool {
	for _, sparringAssetCandidateId := range technicalAssetIDs { // so inner loop again over all assets
		if technicalAsset.Id == sparringAssetCandidateId {
			continue
		}

		sparringAssetCandidate := input.TechnicalAssets[sparringAssetCandidateId]
		if sparringAssetCandidate.Technologies.GetAttribute(types.IsLessProtectedType) &&
			isSameTrustBoundaryNetworkOnly(input, technicalAsset, sparringAssetCandidateId) &&
			!input.HasDirectConnection(technicalAsset, sparringAssetCandidateId) &&
			!sparringAssetCandidate.Technologies.GetAttribute(types.IsCloseToHighValueTargetsTolerated) {
			return true
		}
	}
	return false
}

func (r *MissingNetworkSegmentationRule) createRisk(techAsset *types.TechnicalAsset, moreRisky bool) *types.Risk {
	impact := types.LowImpact
	if moreRisky {
		impact = types.MediumImpact
	}
	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood: types.Unlikely,
		ExploitationImpact:     impact,
		Title: "<b>Missing Network Segmentation</b> to further encapsulate and protect <b>" + techAsset.Title +
			"</b> against unrelated lower protected assets in the same network segment, which might be easier to compromise " +
			"by attackers",
		MostRelevantTechnicalAssetId: techAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{techAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + techAsset.Id
	return risk
}
