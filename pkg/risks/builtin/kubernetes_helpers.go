package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

// The entries of the OWASP Kubernetes Top 10 2025 that the Kubernetes rules reference.
const (
	owaspKubernetesWorkloadConfigurations  = "OWASP K01:2025 Insecure Workload Configurations"
	owaspKubernetesPermissiveAuthorization = "OWASP K02:2025 Overly Permissive Authorization Configurations"
	owaspKubernetesNetworkSegmentation     = "OWASP K05:2025 Missing Network Segmentation Controls"
)

// cheatSheetKubernetes is the cheat sheet of the Kubernetes rules.
const cheatSheetKubernetes = "https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html"

// cweMissingNetworkRestriction is CWE-923: Improper Restriction of Communication Channel to Intended Endpoints.
const cweMissingNetworkRestriction = 923

// isContainerPlatform reports whether the technical asset is a container platform, like the API server of a
// Kubernetes cluster.
func isContainerPlatform(technicalAsset *types.TechnicalAsset) bool {
	return technicalAsset.Technologies.GetAttribute(types.ContainerPlatform)
}

// clusterImpact rates what an attacker who controls the cluster, through its API or a node, reaches from the
// workload: the workload itself, the technical assets that share a runtime with it, and the platform if any.
func clusterImpact(
	input *types.Model, workload *types.TechnicalAsset, platform *types.TechnicalAsset,
) types.RiskExploitationImpact {
	impact := max(assetImpact(input, workload), runtimeNeighbourImpact(input, workload))
	if platform != nil {
		impact = max(impact, assetImpact(input, platform))
	}
	return impact
}

// assetsInBoundary are the technical assets inside the trust boundary and the boundaries nested in it.
func assetsInBoundary(input *types.Model, boundary *types.TrustBoundary) []*types.TechnicalAsset {
	assets := make([]*types.TechnicalAsset, 0)
	for _, id := range input.RecursivelyAllTechnicalAssetIDsInside(boundary) {
		if asset, ok := input.TechnicalAssets[id]; ok {
			assets = append(assets, asset)
		}
	}
	return assets
}
