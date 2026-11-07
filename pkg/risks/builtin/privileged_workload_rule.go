package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

type PrivilegedWorkloadRule struct{}

func NewPrivilegedWorkloadRule() *PrivilegedWorkloadRule {
	return &PrivilegedWorkloadRule{}
}

func (*PrivilegedWorkloadRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "privileged-workload",
		Title: "Privileged Workload",
		Description: "A workload that runs as a privileged container, mounts a path of its node or shares the node's " +
			"network, process or IPC namespace is not contained by its container: whoever controls the workload " +
			"controls the node, the other workloads on it and the credentials of the node's kubelet.",
		Impact: "If this risk is unmitigated, attackers who compromise the workload might take over its node and " +
			"from there the other workloads of the shared runtime and their data, and possibly the cluster.",
		ASVS:       asvsArchitecture,
		CheatSheet: cheatSheetKubernetes,
		Action:     "Unprivileged Workloads",
		Mitigation: "Run the workload unprivileged, as a non-root user with a read-only root file system, without " +
			"host paths, host namespaces and added capabilities, and enforce the restricted Pod Security Standard " +
			"on its namespace. A workload that must stay privileged, like a node agent, belongs on nodes of its own " +
			"and deserves the hardening of the node itself.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Operations,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "In-scope technical assets that are privileged (the field privileged), rated by what runs " +
			"on the same shared runtimes.",
		RiskAssessment: "The risk rating depends on the most sensitive of the workload and the technical assets " +
			"sharing a runtime with it, at least medium as the node itself is at stake. The attack is likely when " +
			"the workload is on the internet or talks to the internet, and unlikely otherwise.",
		FalsePositives: "Workloads that are privileged by design and run alone on dedicated nodes, like the agents " +
			"of the platform, can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweUnnecessaryPrivileges,
		References:                 []string{owaspKubernetesWorkloadConfigurations, owaspSecurityMisconfiguration},
	}
}

func (*PrivilegedWorkloadRule) SupportedTags() []string {
	return []string{}
}

func (r *PrivilegedWorkloadRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, workload := range input.InScopeTechnicalAssets() {
		if workload.Privileged {
			risks = append(risks, r.createRisk(input, workload))
		}
	}
	return risks, nil
}

func (r *PrivilegedWorkloadRule) createRisk(input *types.Model, workload *types.TechnicalAsset) *types.Risk {
	likelihood := types.Unlikely
	if isInternetAdjacent(input, workload) {
		likelihood = types.Likely
	}
	impact := max(types.MediumImpact, clusterImpact(input, workload, nil))
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        assetRiskTitle("Privileged Workload", workload, ""),
		MostRelevantTechnicalAssetId: workload.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{workload.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + workload.Id
	return risk
}
