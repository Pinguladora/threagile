package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

type MissingObjectLevelAuthorizationRule struct{}

func NewMissingObjectLevelAuthorizationRule() *MissingObjectLevelAuthorizationRule {
	return &MissingObjectLevelAuthorizationRule{}
}

func (*MissingObjectLevelAuthorizationRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-object-level-authorization",
		Title: "Missing Object-Level Authorization",
		Description: "A service that acts for its users must check in each request that the user may access the object " +
			"at hand, like the order or the account the request names. Checking only that the caller is logged in, or " +
			"that its role may call the operation, lets any user read or change the objects of others by changing an " +
			"id in the request (BOLA, also known as IDOR).",
		Impact: "If this risk is unmitigated, attackers with any account might read or change the data of all other " +
			"users.",
		ASVS:       asvsAccessControl,
		CheatSheet: cheatSheetAuthorization,
		Action:     "Object-Level Authorization",
		Mitigation: "Check in every operation that the user of the request may access each object it names, by the " +
			"identity of the user rather than an id the request carries, and deny by default, for example by asking " +
			"a policy decision point with the user, the action and the object. Set the authorization of the link to <i>" +
			types.ObjectLevel.String() + "</i> once this is in place.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Development,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "In-scope technical assets other than datastores and assets that forward requests without " +
			"authenticating them (like load balancers and reverse proxies), processing or storing data rated at least as " +
			types.Confidential.String() + " or " + types.Critical.String() + ", with an incoming communication link " +
			"whose authorization is <i>" + types.NoneAuthorization.String() + "</i>, <i>" +
			types.AuthenticatedOnly.String() + "</i> or <i>" + types.FunctionLevel.String() + "</i>, and whose " +
			"identity is <i>" + types.EndUser.String() + "</i> or whose caller is used by humans. DevOps links, which " +
			"administrators use by role, and links whose authorization is <i>" + types.UnknownAuthorization.String() +
			"</i> are skipped.",
		RiskAssessment: "The risk rating depends on the sensitivity of the data processed or stored by the target, one " +
			"step higher when the link has no function-level authorization either. The attack is very likely when the " +
			"caller is on the internet, and likely otherwise.",
		FalsePositives: "Services whose objects belong to all users alike, like a product catalog, can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweUserControlledKey,
		References: []string{
			owaspBrokenAccessControl, owaspAPIBrokenObjectLevelAuthorization, owaspAPIBrokenFunctionLevelAuthorization,
		},
	}
}

func (*MissingObjectLevelAuthorizationRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingObjectLevelAuthorizationRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, target := range input.InScopeTechnicalAssets() {
		if target.Type == types.Datastore || target.Technologies.GetAttribute(types.NoAuthenticationRequired) ||
			!isSensitive(input, target) {
			continue
		}
		for _, link := range sortedIncomingLinks(input, target) {
			caller, ok := input.TechnicalAssets[link.SourceId]
			if ok && actsForUsers(link, caller) && isCoarserThanObjectLevel(link.Authorization) {
				risks = append(risks, r.createRisk(input, target, caller, link))
			}
		}
	}
	return risks, nil
}

// actsForUsers reports whether the link carries the business requests of users: it propagates their identity, or
// comes from a client that humans use. Administrators work through devops links, by role.
func actsForUsers(link *types.CommunicationLink, caller *types.TechnicalAsset) bool {
	return link.Usage != types.DevOps && (link.Identity == types.EndUser || caller.UsedAsClientByHuman)
}

// isCoarserThanObjectLevel reports whether the authorization is known and does not check access per object.
func isCoarserThanObjectLevel(authorization types.Authorization) bool {
	switch authorization {
	case types.NoneAuthorization, types.AuthenticatedOnly, types.FunctionLevel:
		return true
	default:
		return false
	}
}

func (r *MissingObjectLevelAuthorizationRule) createRisk(
	input *types.Model, target, caller *types.TechnicalAsset, link *types.CommunicationLink,
) *types.Risk {
	likelihood := types.Likely
	if caller.Internet {
		likelihood = types.VeryLikely
	}
	impact := assetImpact(input, target)
	if link.Authorization != types.FunctionLevel {
		impact = raiseImpact(impact)
	}

	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: assetRiskTitle("Missing Object-Level Authorization", target,
			"for <b>"+caller.Title+"</b> ("+link.Authorization.String()+")"),
		MostRelevantTechnicalAssetId:    target.Id,
		MostRelevantCommunicationLinkId: link.Id,
		DataBreachProbability:           types.Probable,
		DataBreachTechnicalAssetIDs:     []string{target.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + target.Id + "@" + link.Id
	return risk
}
