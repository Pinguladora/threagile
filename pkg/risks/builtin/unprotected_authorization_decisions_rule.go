package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

type UnprotectedAuthorizationDecisionsRule struct{}

func NewUnprotectedAuthorizationDecisionsRule() *UnprotectedAuthorizationDecisionsRule {
	return &UnprotectedAuthorizationDecisionsRule{}
}

func (*UnprotectedAuthorizationDecisionsRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "unprotected-authorization-decisions",
		Title: "Unprotected Authorization Decisions",
		Description: "A service that asks a policy decision point whether to allow a request trusts the answer it " +
			"gets. When the link to the decision point is unauthenticated or unencrypted, attackers in the network can " +
			"answer in its place or change its answers, and so allow themselves anything the service can do.",
		Impact: "If this risk is unmitigated, attackers might forge authorization decisions and read or change all the " +
			"data of the service that asks.",
		ASVS:       asvsAccessControl,
		CheatSheet: cheatSheetAuthorization,
		Action:     "Protected Authorization Decisions",
		Mitigation: "Authenticate the policy decision point to the services that ask it and encrypt the link, for " +
			"example with mutual TLS, or run the decision point as a local instance next to each service.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Architecture,
		STRIDE:   types.Tampering,
		DetectionLogic: "In-scope technical assets with a communication link to a " + types.PolicyDecisionPoint +
			" technical asset that is not process-local and is unauthenticated or uses a protocol that is not " +
			"encrypted.",
		RiskAssessment: "The risk rating depends on the sensitivity of the data processed or stored by the service that " +
			"asks. The attack is likely when the link crosses a network trust boundary, and unlikely otherwise.",
		FalsePositives: "Links in a network that only the service and the decision point are part of can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweInsufficientAuthenticity,
		References:                 []string{openIDAuthorizationAPI, nistABAC},
	}
}

func (*UnprotectedAuthorizationDecisionsRule) SupportedTags() []string {
	return []string{}
}

func (r *UnprotectedAuthorizationDecisionsRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, service := range input.InScopeTechnicalAssets() {
		for _, link := range service.CommunicationLinksSorted() {
			decisionPoint, ok := input.TechnicalAssets[link.TargetId]
			if !ok || !isPolicyDecisionPoint(decisionPoint) || link.Protocol.IsProcessLocal() {
				continue
			}
			if link.Authentication == types.NoneAuthentication || !link.Protocol.IsEncrypted() {
				risks = append(risks, r.createRisk(input, service, decisionPoint, link))
			}
		}
	}
	return risks, nil
}

func (r *UnprotectedAuthorizationDecisionsRule) createRisk(
	input *types.Model, service, decisionPoint *types.TechnicalAsset, link *types.CommunicationLink,
) *types.Risk {
	likelihood := types.Unlikely
	if isAcrossTrustBoundaryNetworkOnly(input, link) {
		likelihood = types.Likely
	}
	impact := assetImpact(input, service)

	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: assetRiskTitle("Unprotected Authorization Decisions", service,
			"from <b>"+decisionPoint.Title+"</b>"),
		MostRelevantTechnicalAssetId:    service.Id,
		MostRelevantCommunicationLinkId: link.Id,
		DataBreachProbability:           types.Possible,
		DataBreachTechnicalAssetIDs:     []string{service.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + service.Id + "@" + link.Id
	return risk
}
