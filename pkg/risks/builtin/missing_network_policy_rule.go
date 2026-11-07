package builtin

import (
	"maps"
	"slices"
	"strings"

	"github.com/Pinguladora/threagile/pkg/types"
)

type MissingNetworkPolicyRule struct{}

func NewMissingNetworkPolicyRule() *MissingNetworkPolicyRule {
	return &MissingNetworkPolicyRule{}
}

func (*MissingNetworkPolicyRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-network-policy",
		Title: "Missing Network Policy",
		Description: "Without network policies, every pod of a Kubernetes cluster can reach the pods of a namespace, " +
			"and its pods can reach the rest of the cluster and beyond: the namespace separates names, not traffic.",
		Impact: "If this risk is unmitigated, attackers who compromise any pod of the cluster might move on to the " +
			"workloads of the namespace and their data, or, from a pod of the namespace, to anything it can reach.",
		ASVS:       asvsArchitecture,
		CheatSheet: cheatSheetKubernetes,
		Action:     "Network Segmentation of Namespaces",
		Mitigation: "Deny all ingress and egress traffic of the namespace by default with a network policy, allow only " +
			"the traffic that its workloads need, by namespace and pod labels and ports, and make sure the network " +
			"plugin of the cluster enforces network policies. Model the namespace with the network_policy <i>" +
			types.IngressAndEgressNetworkPolicy.String() + "</i> once they are in place.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Operations,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "Execution environment trust boundaries (Kubernetes namespaces) whose network_policy is <i>" +
			types.NoNetworkPolicy.String() + "</i>, <i>" + types.IngressNetworkPolicy.String() + "</i> or <i>" +
			types.EgressNetworkPolicy.String() + "</i>, holding in-scope technical assets that process or store data " +
			"rated at least as " + types.Confidential.String() + " or " + types.Critical.String() + ". Namespaces " +
			"whose network policy is not modelled are skipped.",
		RiskAssessment: "The risk rating depends on the most sensitive technical asset in the namespace. The attack " +
			"is likely when incoming traffic is not restricted, and unlikely when only outgoing traffic is not.",
		FalsePositives: "Namespaces whose traffic a service mesh restricts by default, with authorization policies " +
			"that allow only the intended callers, can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweMissingNetworkRestriction,
		References:                 []string{owaspKubernetesNetworkSegmentation, owaspSecurityMisconfiguration},
	}
}

func (*MissingNetworkPolicyRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingNetworkPolicyRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range slices.Sorted(maps.Keys(input.TrustBoundaries)) {
		namespace := input.TrustBoundaries[id]
		policy := namespace.NetworkPolicy
		if policy == types.UnknownNetworkPolicy || policy == types.IngressAndEgressNetworkPolicy {
			continue
		}
		sensitive := make([]string, 0)
		impact := types.LowImpact
		for _, asset := range assetsInBoundary(input, namespace) {
			if !asset.OutOfScope && isSensitive(input, asset) {
				sensitive = append(sensitive, asset.Id)
				impact = max(impact, assetImpact(input, asset))
			}
		}
		if len(sensitive) > 0 {
			slices.Sort(sensitive)
			risks = append(risks, r.createRisk(namespace, impact, sensitive))
		}
	}
	return risks, nil
}

func (r *MissingNetworkPolicyRule) createRisk(
	namespace *types.TrustBoundary, impact types.RiskExploitationImpact, sensitive []string,
) *types.Risk {
	likelihood := types.Likely
	missing := make([]string, 0)
	if !namespace.NetworkPolicy.RestrictsIngress() {
		missing = append(missing, "ingress")
	}
	if !namespace.NetworkPolicy.RestrictsEgress() {
		missing = append(missing, "egress")
	}
	if namespace.NetworkPolicy.RestrictsIngress() {
		likelihood = types.Unlikely
	}
	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: "<b>Missing Network Policy</b> risk at <b>" + namespace.Title + "</b> (no " +
			strings.Join(missing, " and no ") + " restriction)",
		MostRelevantTrustBoundaryId: namespace.Id,
		DataBreachProbability:       types.Possible,
		DataBreachTechnicalAssetIDs: sensitive,
	}
	risk.SyntheticId = risk.CategoryId + "@" + namespace.Id
	return risk
}
