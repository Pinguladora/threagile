package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

type MissingPolicyDecisionPointRedundancyRule struct{}

func NewMissingPolicyDecisionPointRedundancyRule() *MissingPolicyDecisionPointRedundancyRule {
	return &MissingPolicyDecisionPointRedundancyRule{}
}

func (*MissingPolicyDecisionPointRedundancyRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-policy-decision-point-redundancy",
		Title: "Missing Policy Decision Point Redundancy",
		Description: "Services that externalize their authorization to a policy decision point, for example through " +
			"the AuthZEN Authorization API, cannot decide a request without it. When it fails, they either deny every " +
			"request and stop working, or, when they fail open, allow every request.",
		Impact: "If this risk is unmitigated, an outage of the policy decision point might stop every service that " +
			"asks it, or let any request through services that fail open.",
		ASVS:       asvsArchitecture,
		CheatSheet: cheatSheetAuthorization,
		Action:     "Policy Decision Point Redundancy",
		Mitigation: "Run the policy decision point redundantly, or as a local instance next to each service that asks " +
			"it, with the policies distributed to each instance. Let the services deny requests they cannot get a " +
			"decision for, and cache decisions only briefly.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Architecture,
		STRIDE:   types.DenialOfService,
		DetectionLogic: "In-scope " + types.PolicyDecisionPoint + " technical assets that are not redundant and that " +
			"in-scope technical assets ask for decisions through communication links that are not process-local.",
		RiskAssessment: "The risk rating depends on the highest availability rating of the services that ask the " +
			"policy decision point.",
		FalsePositives: "Policy decision points whose callers keep working on cached policies of their own can be " +
			"considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweFailingOpen,
		References:                 []string{openIDAuthorizationAPI, nistABAC},
	}
}

func (*MissingPolicyDecisionPointRedundancyRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingPolicyDecisionPointRedundancyRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, decisionPoint := range input.InScopeTechnicalAssets() {
		if !isPolicyDecisionPoint(decisionPoint) || decisionPoint.Redundant {
			continue
		}
		availability, asked := types.Archive, false
		for _, link := range sortedIncomingLinks(input, decisionPoint) {
			caller, ok := input.TechnicalAssets[link.SourceId]
			if !ok || caller.OutOfScope || link.Protocol.IsProcessLocal() {
				continue
			}
			availability, asked = max(availability, input.HighestAvailability(caller)), true
		}
		if asked {
			risks = append(risks, r.createRisk(decisionPoint, availability))
		}
	}
	return risks, nil
}

func (r *MissingPolicyDecisionPointRedundancyRule) createRisk(
	decisionPoint *types.TechnicalAsset, availability types.Criticality,
) *types.Risk {
	likelihood := types.Unlikely
	impact := impactOfRatings(types.Public, types.Archive, availability)

	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        assetRiskTitle("Missing Policy Decision Point Redundancy", decisionPoint, ""),
		MostRelevantTechnicalAssetId: decisionPoint.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{decisionPoint.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + decisionPoint.Id
	return risk
}
