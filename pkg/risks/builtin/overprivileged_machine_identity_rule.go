package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

type OverprivilegedMachineIdentityRule struct{}

func NewOverprivilegedMachineIdentityRule() *OverprivilegedMachineIdentityRule {
	return &OverprivilegedMachineIdentityRule{}
}

func (*OverprivilegedMachineIdentityRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "overprivileged-machine-identity",
		Title: "Overprivileged Machine Identity",
		Description: "A service account or workload identity that the target lets do everything, because it checks " +
			"only that the caller is authenticated, like a cluster-admin binding, a subscription-wide role or a " +
			"database owner, gives whoever controls the caller the whole target, while the caller needs only a part " +
			"of it.",
		Impact: "If this risk is unmitigated, attackers who compromise the caller, or steal its credentials, might " +
			"read, change or delete everything on the target, beyond what the caller ever does.",
		ASVS:       asvsAccessControl,
		CheatSheet: cheatSheetAuthorization,
		Action:     "Least Privilege for Machine Identities",
		Mitigation: "Grant the identity only the operations and resources the caller needs, by a role scoped to them " +
			"(a namespaced role instead of cluster-admin, a resource group instead of the subscription, a database " +
			"role instead of the owner), review the grants against what the caller uses, and model the link with " +
			"the authorization <i>" + types.FunctionLevel.String() + "</i> or <i>" + types.ObjectLevel.String() +
			"</i> once they are in place.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Operations,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "In-scope technical assets processing or storing data rated at least as " +
			types.Confidential.String() + " or " + types.Critical.String() + " with an incoming communication link " +
			"that is not process-local and not readonly, whose identity is <i>" + types.ServiceAccount.String() +
			"</i> or <i>" + types.Workload.String() + "</i> and whose authorization is <i>" +
			types.NoneAuthorization.String() + "</i> or <i>" + types.AuthenticatedOnly.String() + "</i>. Links whose " +
			"authorization is <i>" + types.UnknownAuthorization.String() + "</i> are skipped.",
		RiskAssessment: "The risk rating depends on the sensitivity of the data processed or stored by the target. " +
			"The attack is likely when the link crosses a network trust boundary, and unlikely otherwise.",
		FalsePositives: "Callers that administer the whole target by design, like the operator of a database it " +
			"creates, can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweUnnecessaryPrivileges,
		References:                 []string{owaspNHIOverprivileged, owaspBrokenAccessControl, owaspAgenticPrivilegeAbuse},
	}
}

func (*OverprivilegedMachineIdentityRule) SupportedTags() []string {
	return []string{}
}

func (r *OverprivilegedMachineIdentityRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, target := range input.InScopeTechnicalAssets() {
		if !isSensitive(input, target) {
			continue
		}
		for _, link := range sortedIncomingLinks(input, target) {
			caller, ok := input.TechnicalAssets[link.SourceId]
			if ok && isMachineIdentity(link.Identity) && !link.Readonly && !link.Protocol.IsProcessLocal() &&
				(link.Authorization == types.NoneAuthorization || link.Authorization == types.AuthenticatedOnly) {
				risks = append(risks, r.createRisk(input, target, caller, link))
			}
		}
	}
	return risks, nil
}

func (r *OverprivilegedMachineIdentityRule) createRisk(
	input *types.Model, target, caller *types.TechnicalAsset, link *types.CommunicationLink,
) *types.Risk {
	likelihood := types.Unlikely
	if isAcrossTrustBoundaryNetworkOnly(input, link) {
		likelihood = types.Likely
	}
	impact := assetImpact(input, target)

	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: assetRiskTitle("Overprivileged Machine Identity", target,
			"for <b>"+caller.Title+"</b> ("+link.Authorization.String()+")"),
		MostRelevantTechnicalAssetId:    target.Id,
		MostRelevantCommunicationLinkId: link.Id,
		DataBreachProbability:           types.Possible,
		DataBreachTechnicalAssetIDs:     []string{target.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + target.Id + "@" + link.Id
	return risk
}
