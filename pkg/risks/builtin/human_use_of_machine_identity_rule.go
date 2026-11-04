package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

type HumanUseOfMachineIdentityRule struct{}

func NewHumanUseOfMachineIdentityRule() *HumanUseOfMachineIdentityRule {
	return &HumanUseOfMachineIdentityRule{}
}

func (*HumanUseOfMachineIdentityRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "human-use-of-machine-identity",
		Title: "Human Use of Machine Identity",
		Description: "People who call a service with the account of a machine, like an administrator using the " +
			"credentials of a service account or a client that ships with an API key of its own, act without an " +
			"identity of theirs. The service cannot tell them apart, nor require a second factor or end their " +
			"access when they leave, and the secret gets copied to wherever they work.",
		Impact: "If this risk is unmitigated, attackers might use a secret copied from a laptop, a script or a " +
			"client to access the target, and nobody can tell who did what with it.",
		ASVS:       asvsAuthentication,
		CheatSheet: cheatSheetSecretsManagement,
		Action:     "Personal Identities for People",
		Mitigation: "Let people sign in with their own identity, through single sign-on with multi-factor " +
			"authentication, and pass it on to the target, modelling the link with the identity <i>" +
			types.EndUser.String() + "</i>. Where an administrator needs the permissions of a service, grant them " +
			"for a limited time through a privileged access workflow that records who used them. Keep secrets of " +
			"service accounts out of clients.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Operations,
		STRIDE:   types.Repudiation,
		DetectionLogic: "In-scope technical assets processing or storing data rated at least as " +
			types.Confidential.String() + " or " + types.Critical.String() + " with an incoming communication link " +
			"that is not process-local, from a caller used by humans, whose identity is <i>" +
			types.ServiceAccount.String() + "</i> or <i>" + types.Workload.String() + "</i>.",
		RiskAssessment: "The risk rating depends on the sensitivity of the data processed or stored by the target. " +
			"The attack is likely, as secrets in the hands of people leak easily.",
		FalsePositives: "Clients whose users sign in with their own identity first, which a service then exchanges " +
			"for the narrowly scoped account of the client, can be considered as false positives after individual " +
			"review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweWeakAuthentication,
		References:                 []string{owaspNHIHumanUse, owaspAgenticPrivilegeAbuse},
	}
}

func (*HumanUseOfMachineIdentityRule) SupportedTags() []string {
	return []string{}
}

func (r *HumanUseOfMachineIdentityRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, target := range input.InScopeTechnicalAssets() {
		if !isSensitive(input, target) {
			continue
		}
		for _, link := range sortedIncomingLinks(input, target) {
			caller, ok := input.TechnicalAssets[link.SourceId]
			if ok && caller.UsedAsClientByHuman && isMachineIdentity(link.Identity) && !link.Protocol.IsProcessLocal() {
				risks = append(risks, r.createRisk(input, target, caller, link))
			}
		}
	}
	return risks, nil
}

func (r *HumanUseOfMachineIdentityRule) createRisk(
	input *types.Model, target, caller *types.TechnicalAsset, link *types.CommunicationLink,
) *types.Risk {
	likelihood := types.Likely
	impact := assetImpact(input, target)

	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: assetRiskTitle("Human Use of Machine Identity", target,
			"by users of <b>"+caller.Title+"</b> ("+link.Identity.String()+")"),
		MostRelevantTechnicalAssetId:    target.Id,
		MostRelevantCommunicationLinkId: link.Id,
		DataBreachProbability:           types.Possible,
		DataBreachTechnicalAssetIDs:     []string{target.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + target.Id + "@" + link.Id
	return risk
}
