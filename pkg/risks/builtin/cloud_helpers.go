package builtin

import (
	"strings"

	"github.com/Pinguladora/threagile/pkg/types"
)

// Helpers shared by the cloud risk rules. They use the vocabulary of the missing-cloud-hardening rule:
// cloud trust boundary types and the provider tags (aws, azure, gcp, ocp and their "provider:service" sub-tags).

// isCloudTechnicalAsset reports whether the technical asset runs at a cloud provider: it, a trust boundary
// around it or a shared runtime it runs on carries a cloud provider tag, or one of its trust boundaries is
// a cloud boundary (network-cloud-provider or network-cloud-security-group).
func isCloudTechnicalAsset(model *types.Model, technicalAsset *types.TechnicalAsset) bool {
	if hasCloudProviderTag(technicalAsset.Tags) {
		return true
	}

	for _, trustBoundary := range trustBoundariesAround(model, technicalAsset) {
		if trustBoundary.Type.IsWithinCloud() || hasCloudProviderTag(trustBoundary.Tags) {
			return true
		}
	}

	for _, sharedRuntime := range model.SharedRuntimes {
		if hasCloudProviderTag(sharedRuntime.Tags) && contains(sharedRuntime.TechnicalAssetsRunning, technicalAsset.Id) {
			return true
		}
	}

	return false
}

// hasCloudProviderTag reports whether the tags hold a cloud provider tag, either a base tag like "aws" or a
// sub-tag like "aws:s3".
func hasCloudProviderTag(tags []string) bool {
	for _, provider := range providers {
		if isTaggedWithBaseTag(tags, strings.ToLower(provider)) {
			return true
		}
	}
	return false
}

// cloudAccountTrustBoundary returns the innermost trust boundary of type network-cloud-provider that holds the
// technical asset, or nil. Such a boundary stands for a cloud account, subscription, project or VPC, so two
// assets in different ones are isolated from each other by the cloud provider.
func cloudAccountTrustBoundary(model *types.Model, technicalAsset *types.TechnicalAsset) *types.TrustBoundary {
	for _, trustBoundary := range trustBoundariesAround(model, technicalAsset) {
		if trustBoundary.Type == types.NetworkCloudProvider {
			return trustBoundary
		}
	}
	return nil
}

// trustBoundariesAround returns the trust boundaries that hold the technical asset, innermost first.
func trustBoundariesAround(model *types.Model, technicalAsset *types.TechnicalAsset) []*types.TrustBoundary {
	var result []*types.TrustBoundary
	trustBoundary := model.TrustBoundaries[model.GetTechnicalAssetTrustBoundaryId(technicalAsset)]
	for ; trustBoundary != nil; trustBoundary = model.FindParentTrustBoundary(trustBoundary) {
		result = append(result, trustBoundary)
	}
	return result
}

// cloudRiskImpact rates the impact of a cloud risk from the CIA ratings at stake: medium by default, high from
// confidential or critical, and very high from strictly-confidential or mission-critical. Rules that do not
// put one of the ratings at risk pass its lowest value (types.Public or types.Archive).
func cloudRiskImpact(
	confidentiality types.Confidentiality, integrity, availability types.Criticality,
) types.RiskExploitationImpact {
	if confidentiality == types.StrictlyConfidential ||
		integrity == types.MissionCritical || availability == types.MissionCritical {
		return types.VeryHighImpact
	}
	if confidentiality >= types.Confidential || integrity >= types.Critical || availability >= types.Critical {
		return types.HighImpact
	}
	return types.MediumImpact
}
