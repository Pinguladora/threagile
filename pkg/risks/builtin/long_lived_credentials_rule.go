package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

type LongLivedCredentialsRule struct{}

func NewLongLivedCredentialsRule() *LongLivedCredentialsRule {
	return &LongLivedCredentialsRule{}
}

func (*LongLivedCredentialsRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "long-lived-credentials",
		Title: "Long-Lived Credentials",
		Description: "Passwords of service accounts, API keys and personal access tokens stay valid for months or for " +
			"good. Once one leaks, from a repository, a log, a build system or a laptop, it lets anyone in until " +
			"someone notices and rotates it.",
		Impact: "If this risk is unmitigated, attackers who find a leaked secret might use it for a long time to access " +
			"the target with the permissions of the caller.",
		ASVS:       asvsAuthentication,
		CheatSheet: cheatSheetSecretsManagement,
		Action:     "Short-Lived Credentials",
		Mitigation: "Replace static secrets between services with a workload identity issued by the platform (cloud " +
			"IAM roles, Kubernetes service account tokens, SPIFFE), or with short-lived tokens obtained through OAuth " +
			"2.0 client credentials or token exchange, and model the link with the identity <i>" +
			types.Workload.String() + "</i> or the authentication <i>" + types.ShortLivedToken.String() + "</i>. " +
			"Where a long-lived secret remains, keep it in a vault, scope it narrowly, rotate it automatically and " +
			"detect its use from unexpected places.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Operations,
		STRIDE:   types.Spoofing,
		DetectionLogic: "In-scope technical assets processing or storing data rated at least as " +
			types.Confidential.String() + " or " + types.Critical.String() + " with an incoming communication link " +
			"that is not process-local and is authenticated with <i>" + types.LongLivedToken.String() + "</i>, or " +
			"with <i>" + types.Credentials.String() + "</i> by a caller not used by humans, unless the identity of " +
			"the link is <i>" + types.Workload.String() + "</i>. Links authenticated with <i>" + types.Token.String() +
			"</i> are skipped, as the lifetime of the token is not modelled.",
		RiskAssessment: "The risk rating depends on the sensitivity of the data processed or stored by the target. The " +
			"attack is likely when the caller is on the internet, is used by humans or calls across a network trust " +
			"boundary, where secrets leak more easily, and unlikely otherwise.",
		FalsePositives: "Secrets that are rotated automatically within hours can be considered as false positives " +
			"after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweInsufficientlyProtectedCredentials,
		References:                 []string{owaspNHILongLivedSecrets, owaspNHISecretLeakage},
	}
}

func (*LongLivedCredentialsRule) SupportedTags() []string {
	return []string{}
}

func (r *LongLivedCredentialsRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, target := range input.InScopeTechnicalAssets() {
		if !isSensitive(input, target) {
			continue
		}
		for _, link := range sortedIncomingLinks(input, target) {
			caller, ok := input.TechnicalAssets[link.SourceId]
			if ok && hasLongLivedCredentials(link, caller) {
				risks = append(risks, r.createRisk(input, target, caller, link))
			}
		}
	}
	return risks, nil
}

// hasLongLivedCredentials reports whether the caller authenticates the link with a secret that stays valid for long:
// a long-lived token, or the password of an account that no human uses.
func hasLongLivedCredentials(link *types.CommunicationLink, caller *types.TechnicalAsset) bool {
	if link.Protocol.IsProcessLocal() || link.Identity == types.Workload {
		return false
	}
	return link.Authentication == types.LongLivedToken ||
		link.Authentication == types.Credentials && !caller.UsedAsClientByHuman
}

func (r *LongLivedCredentialsRule) createRisk(
	input *types.Model, target, caller *types.TechnicalAsset, link *types.CommunicationLink,
) *types.Risk {
	likelihood := types.Unlikely
	if caller.Internet || caller.UsedAsClientByHuman || isAcrossTrustBoundaryNetworkOnly(input, link) {
		likelihood = types.Likely
	}
	impact := assetImpact(input, target)

	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: assetRiskTitle("Long-Lived Credentials", target,
			"used by <b>"+caller.Title+"</b> ("+link.Authentication.String()+")"),
		MostRelevantTechnicalAssetId:    target.Id,
		MostRelevantCommunicationLinkId: link.Id,
		DataBreachProbability:           types.Possible,
		DataBreachTechnicalAssetIDs:     []string{target.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + target.Id + "@" + link.Id
	return risk
}
