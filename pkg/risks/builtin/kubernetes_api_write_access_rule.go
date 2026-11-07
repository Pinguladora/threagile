package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

type KubernetesAPIWriteAccessRule struct{}

func NewKubernetesAPIWriteAccessRule() *KubernetesAPIWriteAccessRule {
	return &KubernetesAPIWriteAccessRule{}
}

func (*KubernetesAPIWriteAccessRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "kubernetes-api-write-access",
		Title: "Kubernetes API Write Access",
		Description: "A workload whose service account may change resources through the API of its cluster, even " +
			"narrowly, like creating pods, reading secrets or patching deployments, hands that power to whoever " +
			"compromises the workload: a pod created with a mounted host path, or a secret read, opens the rest of " +
			"the cluster.",
		Impact: "If this risk is unmitigated, attackers who compromise the workload might run their own workloads in " +
			"the cluster, read its secrets and take over the other workloads and their data.",
		ASVS:       asvsAccessControl,
		CheatSheet: cheatSheetKubernetes,
		Action:     "Least Privilege for Service Accounts",
		Mitigation: "Give the workload a service account of its own, bound to a role in its namespace with only the " +
			"verbs and resources it uses (no create on pods, no get on secrets, no wildcards), disable the mounting " +
			"of its token where it does not call the API, and leave changes to the cluster to the deployment " +
			"pipeline or an operator on nodes of its own.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Operations,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "Communication links that are not readonly and not process-local to a " +
			types.ContainerPlatform + " technical asset from a technical asset that is not used by humans, where " +
			"either is in scope. Links of " + types.DevOps.String() + " usage, like deployments, are skipped.",
		RiskAssessment: "The risk rating depends on the most sensitive of the platform, the workload and the " +
			"technical assets sharing a runtime with the workload. The attack is likely when the workload is on the " +
			"internet or talks to the internet, and unlikely otherwise.",
		FalsePositives: "Operators and controllers whose job is to change the cluster, running on nodes of their own " +
			"with roles scoped to what they manage, can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweUnnecessaryPrivileges,
		References:                 []string{owaspKubernetesPermissiveAuthorization, owaspBrokenAccessControl},
	}
}

func (*KubernetesAPIWriteAccessRule) SupportedTags() []string {
	return []string{}
}

func (r *KubernetesAPIWriteAccessRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		platform := input.TechnicalAssets[id]
		if !isContainerPlatform(platform) {
			continue
		}
		for _, link := range sortedIncomingLinks(input, platform) {
			workload, ok := input.TechnicalAssets[link.SourceId]
			if !ok || !writesToCluster(workload, platform, link) {
				continue
			}
			risks = append(risks, r.createRisk(input, platform, workload, link))
		}
	}
	return risks, nil
}

// writesToCluster tells whether the link lets a workload change the cluster through its API: one that no human uses,
// in a link that is not readonly, not process-local and not a deployment, with the workload or the platform in scope.
func writesToCluster(workload, platform *types.TechnicalAsset, link *types.CommunicationLink) bool {
	return !workload.UsedAsClientByHuman && !link.Readonly && link.Usage != types.DevOps &&
		!link.Protocol.IsProcessLocal() && (!workload.OutOfScope || !platform.OutOfScope)
}

func (r *KubernetesAPIWriteAccessRule) createRisk(
	input *types.Model, platform, workload *types.TechnicalAsset, link *types.CommunicationLink,
) *types.Risk {
	likelihood := types.Unlikely
	if isInternetAdjacent(input, workload) {
		likelihood = types.Likely
	}
	impact := clusterImpact(input, workload, platform)
	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: "<b>Kubernetes API Write Access</b> risk at <b>" + workload.Title + "</b> to <b>" + platform.Title +
			"</b>",
		MostRelevantTechnicalAssetId:    workload.Id,
		MostRelevantCommunicationLinkId: link.Id,
		DataBreachProbability:           types.Possible,
		DataBreachTechnicalAssetIDs:     []string{platform.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + workload.Id + "@" + link.Id
	return risk
}
