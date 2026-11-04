package builtin

import (
	"slices"
	"strings"

	"github.com/Pinguladora/threagile/pkg/types"
)

func isAcrossTrustBoundaryNetworkOnly(parsedModel *types.Model, communicationLink *types.CommunicationLink) bool {
	isAcrossNetworkTrustBoundary := func(
		trustBoundaryOfSourceAsset *types.TrustBoundary, trustBoundaryOfTargetAsset *types.TrustBoundary,
	) bool {
		return trustBoundaryOfSourceAsset.Id != trustBoundaryOfTargetAsset.Id &&
			trustBoundaryOfTargetAsset.Type.IsNetworkBoundary()
	}

	boundaryOf := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId

	trustBoundaryOfSourceAsset, trustBoundaryOfSourceAssetOk := boundaryOf[communicationLink.SourceId]
	if !isNetworkOnly(parsedModel, trustBoundaryOfSourceAssetOk, trustBoundaryOfSourceAsset) {
		return false
	}

	trustBoundaryOfTargetAsset, trustBoundaryOfTargetAssetOk := boundaryOf[communicationLink.TargetId]
	if !isNetworkOnly(parsedModel, trustBoundaryOfTargetAssetOk, trustBoundaryOfTargetAsset) {
		return false
	}

	return isAcrossNetworkTrustBoundary(trustBoundaryOfSourceAsset, trustBoundaryOfTargetAsset)
}

func isNetworkOnly(parsedModel *types.Model, trustBoundaryOk bool, trustBoundary *types.TrustBoundary) bool {
	if !trustBoundaryOk {
		return false
	}
	if !trustBoundary.Type.IsNetworkBoundary() { // find and use the parent boundary then
		parentTrustBoundary := parsedModel.FindParentTrustBoundary(trustBoundary)
		if parentTrustBoundary != nil {
			return false
		}
	}
	return true
}

func contains(as []string, b string) bool {
	return slices.Contains(as, b)
}

func containsCaseInsensitiveAny(as []string, bs ...string) bool {
	for _, a := range as {
		for _, b := range bs {
			if strings.TrimSpace(strings.ToLower(b)) == strings.TrimSpace(strings.ToLower(a)) {
				return true
			}
		}
	}
	return false
}

// newCallerAttackRisk creates the risk of the caller of an incoming flow attacking the technical asset, rated by the
// sensitivity of the data the asset processes.
func newCallerAttackRisk(
	input *types.Model, categoryId string, title string, technicalAsset *types.TechnicalAsset,
	incomingFlow *types.CommunicationLink, likelihood types.RiskExploitationLikelihood,
) *types.Risk {
	caller := input.TechnicalAssets[incomingFlow.SourceId]
	impact := types.MediumImpact
	if input.HighestProcessedConfidentiality(technicalAsset) == types.StrictlyConfidential ||
		input.HighestProcessedIntegrity(technicalAsset) == types.MissionCritical {
		impact = types.HighImpact
	}
	risk := &types.Risk{
		CategoryId:                      categoryId,
		Severity:                        types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    caller.Id,
		MostRelevantCommunicationLinkId: incomingFlow.Id,
		DataBreachProbability:           types.Probable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + caller.Id + "@" + technicalAsset.Id + "@" + incomingFlow.Id
	return risk
}

// processesHighestRatedData tells whether the technical asset processes strictly confidential or mission-critical
// data.
func processesHighestRatedData(parsedModel *types.Model, ta *types.TechnicalAsset) bool {
	return parsedModel.HighestProcessedConfidentiality(ta) == types.StrictlyConfidential ||
		parsedModel.HighestProcessedIntegrity(ta) == types.MissionCritical ||
		parsedModel.HighestProcessedAvailability(ta) == types.MissionCritical
}

// transfersHighestRatedData tells whether the communication link transfers strictly confidential or mission-critical
// data.
func transfersHighestRatedData(parsedModel *types.Model, link *types.CommunicationLink) bool {
	return parsedModel.HighestCommunicationLinkConfidentiality(link) == types.StrictlyConfidential ||
		parsedModel.HighestCommunicationLinkIntegrity(link) == types.MissionCritical ||
		parsedModel.HighestCommunicationLinkAvailability(link) == types.MissionCritical
}

// findUnrelatedNeighbours checks all other technical assets that are not related to the given one, as decided by
// isRelated: whether any of them is in the same network segment or execution environment as the given one, and
// whether any of them is even in the same execution environment.
func findUnrelatedNeighbours(
	parsedModel *types.Model, ta *types.TechnicalAsset, isRelated func(*types.TechnicalAsset) bool,
) (found bool, sameExecutionEnv bool) {
	for sparringAssetCandidateId := range parsedModel.TechnicalAssets { // so inner loop again over all assets
		if ta.Id == sparringAssetCandidateId {
			continue
		}
		if isRelated(parsedModel.TechnicalAssets[sparringAssetCandidateId]) {
			continue
		}

		if isSameExecutionEnvironment(parsedModel, ta, sparringAssetCandidateId) {
			found = true
			sameExecutionEnv = true
		} else if isSameTrustBoundaryNetworkOnly(parsedModel, ta, sparringAssetCandidateId) {
			found = true
		}
	}
	return found, sameExecutionEnv
}

func isSameExecutionEnvironment(parsedModel *types.Model, ta *types.TechnicalAsset, otherAssetId string) bool {
	boundaryOf := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId
	trustBoundaryOfMyAsset, trustBoundaryOfMyAssetOk := boundaryOf[ta.Id]
	trustBoundaryOfOtherAsset, trustBoundaryOfOtherAssetOk := boundaryOf[otherAssetId]
	if trustBoundaryOfMyAssetOk != trustBoundaryOfOtherAssetOk {
		return false
	}
	if !trustBoundaryOfMyAssetOk {
		return true
	}
	if trustBoundaryOfMyAsset.Type == types.ExecutionEnvironment &&
		trustBoundaryOfOtherAsset.Type == types.ExecutionEnvironment {
		return trustBoundaryOfMyAsset.Id == trustBoundaryOfOtherAsset.Id
	}
	return false
}

func isSameTrustBoundaryNetworkOnly(parsedModel *types.Model, ta *types.TechnicalAsset, otherAssetId string) bool {
	useParentBoundary := func(
		trustBoundaryOfAsset **types.TrustBoundary, parsedModel *types.Model, trustBoundaryOfAssetOk *bool,
	) {
		if trustBoundaryOfAsset == nil {
			return
		}
		tb := *trustBoundaryOfAsset
		if tb != nil && !tb.Type.IsNetworkBoundary() {
			*trustBoundaryOfAsset = parsedModel.FindParentTrustBoundary(tb)
			*trustBoundaryOfAssetOk = *trustBoundaryOfAsset != nil
		}
	}

	boundaryOf := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId

	trustBoundaryOfMyAsset, trustBoundaryOfMyAssetOk := boundaryOf[ta.Id]
	useParentBoundary(&trustBoundaryOfMyAsset, parsedModel, &trustBoundaryOfMyAssetOk)

	trustBoundaryOfOtherAsset, trustBoundaryOfOtherAssetOk := boundaryOf[otherAssetId]
	useParentBoundary(&trustBoundaryOfOtherAsset, parsedModel, &trustBoundaryOfOtherAssetOk)

	if trustBoundaryOfMyAssetOk != trustBoundaryOfOtherAssetOk {
		return false
	}
	if !trustBoundaryOfMyAssetOk {
		return true
	}
	return trustBoundaryOfMyAsset.Id == trustBoundaryOfOtherAsset.Id
}
