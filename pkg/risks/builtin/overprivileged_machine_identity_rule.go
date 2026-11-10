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
		DetectionLogic: "Communication links that are not process-local and not readonly, whose identity is <i>" +
			types.ServiceAccount.String() + "</i> or <i>" + types.Workload.String() + "</i> and whose authorization " +
			"is <i>" + types.NoneAuthorization.String() + "</i> or <i>" + types.AuthenticatedOnly.String() + "</i>, " +
			"to technical assets processing or storing data rated at least as " + types.Confidential.String() +
			" or " + types.Critical.String() + ". Out-of-scope targets, like the API of a cloud provider, count for " +
			"links from in-scope callers. Links whose authorization is <i>" + types.UnknownAuthorization.String() +
			"</i> are skipped.",
		RiskAssessment: "The risk rating depends on the sensitivity of the data processed or stored by the target. " +
			"An out-of-scope target is rated one level lower, as the model does not hold what else it holds. The " +
			"rating of an out-of-scope target includes the data its callers send it and its own rating, so a cloud " +
			"API rated by what the identity may change there is rated as such. The attack is likely " +
			"when the link crosses a network trust boundary or the target is on the internet, where stolen " +
			"credentials of the identity work from anywhere, and unlikely otherwise.",
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
	for _, id := range input.SortedTechnicalAssetIDs() {
		target := input.TechnicalAssets[id]
		if !isSensitive(input, target) {
			continue
		}
		for _, link := range sortedIncomingLinks(input, target) {
			caller, ok := input.TechnicalAssets[link.SourceId]
			if !ok || !grantsMoreThanNeeded(link) {
				continue
			}
			impact := assetImpact(input, target)
			if target.OutOfScope {
				if caller.OutOfScope {
					continue
				}
				impact-- // the model does not hold what else the out-of-scope target holds
			}
			risks = append(risks, r.createRisk(input, target, caller, link, impact))
		}
	}
	return risks, nil
}

// grantsMoreThanNeeded tells whether the link lets a machine identity change the target with no more than an
// authentication: one that is not readonly and not process-local, whose authorization is none or authenticated-only.
func grantsMoreThanNeeded(link *types.CommunicationLink) bool {
	return isMachineIdentity(link.Identity) && !link.Readonly && !link.Protocol.IsProcessLocal() &&
		(link.Authorization == types.NoneAuthorization || link.Authorization == types.AuthenticatedOnly)
}

func (r *OverprivilegedMachineIdentityRule) createRisk(
	input *types.Model, target, caller *types.TechnicalAsset, link *types.CommunicationLink,
	impact types.RiskExploitationImpact,
) *types.Risk {
	likelihood := types.Unlikely
	// stolen credentials of the identity work from anywhere when the target is on the internet
	if isAcrossTrustBoundaryNetworkOnly(input, link) || target.Internet {
		likelihood = types.Likely
	}

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
	if target.OutOfScope {
		risk.MostRelevantTechnicalAssetId = caller.Id // the report rates in-scope assets only
	}
	risk.SyntheticId = risk.CategoryId + "@" + target.Id + "@" + link.Id
	return risk
}
