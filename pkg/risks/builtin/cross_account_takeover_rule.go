package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

// cweConfusedDeputy is CWE-441: Unintended Proxy or Intermediary ('Confused Deputy').
const cweConfusedDeputy = 441

const awsConfusedDeputy = "https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html"

type CrossAccountTakeoverRule struct{}

func NewCrossAccountTakeoverRule() *CrossAccountTakeoverRule {
	return &CrossAccountTakeoverRule{}
}

func (*CrossAccountTakeoverRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "cross-account-takeover",
		Title: "Cross-Account Takeover",
		Description: "Cloud accounts, subscriptions, projects and VPCs isolate workloads and tenants from each " +
			"other. Access from one of them into another (account A to account B) is granted by cross-account " +
			"roles, trust policies or resource policies, and a misconfigured grant (too broad principals or " +
			"rights, or no condition on the calling account) breaks that isolation.",
		Impact: "If this risk is unmitigated, attackers who compromised one cloud account or tenant might move " +
			"laterally into the other account and take over its assets.",
		ASVS:       asvsAccessControl,
		CheatSheet: cheatSheetSecureCloudArchitecture,
		Action:     "Cross-Account Access Restrictions",
		Mitigation: "Grant cross-account access only through dedicated roles with the least privileges needed, " +
			"and restrict their trust policies to the exact calling principals. Keep tenants in separate " +
			"accounts and do not share multi-tenant resources across them, and review all cross-account " +
			"grants regularly. " +
			"<br><br>For <b>Amazon Web Services (AWS)</b>: Require an <i>sts:ExternalId</i> in the trust " +
			"policies of roles assumed by third parties, and pin resource policies with the <i>aws:SourceAccount</i>, " +
			"<i>aws:SourceArn</i> or <i>aws:SourceOrgID</i> condition keys (see " + htmlLink(awsConfusedDeputy) +
			"). Review the cross-account findings of <i>IAM Access Analyzer</i> (see " +
			htmlLink(awsIAMAccessAnalyzer) + ").",
		Check:    checkCheatSheetAndASVS,
		Function: types.Architecture,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "Communication links into in-scope technical assets from technical assets in another " +
			"cloud account, i.e. where the innermost trust boundaries of type " + types.NetworkCloudProvider.String() +
			" around the source and the target differ.",
		RiskAssessment: "The risk rating depends on the sensitivity of the target technical asset itself and of " +
			"the data assets it processes and stores. The likelihood rises when the source or the target is " +
			"multi-tenant, as another tenant can then try to abuse the cross-account access.",
		FalsePositives: "Cross-account access that is restricted to dedicated least-privilege roles, with trust " +
			"policies pinned to the calling account (and an external ID for third parties), can be considered " +
			"as a false positive after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweConfusedDeputy,
		References:                 []string{owaspBrokenAccessControl},
	}
}

func (*CrossAccountTakeoverRule) SupportedTags() []string {
	return []string{}
}

func (r *CrossAccountTakeoverRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, sourceID := range input.SortedTechnicalAssetIDs() {
		source := input.TechnicalAssets[sourceID]
		sourceAccount := cloudAccountTrustBoundary(input, source)
		if sourceAccount == nil {
			continue
		}

		for _, link := range source.CommunicationLinksSorted() {
			target, ok := input.TechnicalAssets[link.TargetId]
			if !ok || target.OutOfScope {
				continue
			}
			targetAccount := cloudAccountTrustBoundary(input, target)
			if targetAccount == nil || targetAccount.Id == sourceAccount.Id {
				continue
			}
			risks = append(risks, r.createRisk(input, link, source, sourceAccount, target, targetAccount))
		}
	}
	return risks, nil
}

func (r *CrossAccountTakeoverRule) createRisk(input *types.Model, link *types.CommunicationLink,
	source *types.TechnicalAsset, sourceAccount *types.TrustBoundary,
	target *types.TechnicalAsset, targetAccount *types.TrustBoundary,
) *types.Risk {
	likelihood := types.Unlikely
	if source.MultiTenant || target.MultiTenant {
		likelihood = types.Likely
	}
	impact := cloudRiskImpact(
		input.HighestTechnicalAssetConfidentiality(target),
		input.HighestIntegrity(target),
		input.HighestAvailability(target),
	)

	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: "<b>Cross-Account Takeover</b> risk at <b>" + target.Title + "</b> in <b>" + targetAccount.Title +
			"</b> from <b>" + source.Title + "</b> in <b>" + sourceAccount.Title + "</b> via <b>" + link.Title + "</b>",
		MostRelevantTechnicalAssetId:    target.Id,
		MostRelevantTrustBoundaryId:     targetAccount.Id,
		MostRelevantCommunicationLinkId: link.Id,
		DataBreachProbability:           types.Possible,
		DataBreachTechnicalAssetIDs:     []string{target.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + target.Id + "@" + source.Id + "@" + link.Id
	return risk
}
