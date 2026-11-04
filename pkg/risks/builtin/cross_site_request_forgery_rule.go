package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

type CrossSiteRequestForgeryRule struct{}

func NewCrossSiteRequestForgeryRule() *CrossSiteRequestForgeryRule {
	return &CrossSiteRequestForgeryRule{}
}

func (*CrossSiteRequestForgeryRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "cross-site-request-forgery",
		Title: "Cross-Site Request Forgery (CSRF)",
		Description: "When a web application is accessed via web protocols Cross-Site Request Forgery (CSRF) risks might " +
			"arise.",
		Impact: "If this risk remains unmitigated, attackers might be able to trick logged-in victim users into unwanted " +
			"actions within the web application by visiting an attacker controlled web site.",
		ASVS:       "V4 - Access Control Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
		Action:     "CSRF Prevention",
		Mitigation: "Try to use anti-CSRF tokens ot the double-submit patterns (at least for logged-in requests). " +
			"When your authentication scheme depends on cookies (like session or token cookies), consider marking them with " +
			"the same-site flag. " +
			"When a third-party product is used instead of custom developed software, check if the product applies the proper " +
			"mitigation and ensure a reasonable patch-level.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Development,
		STRIDE:   types.Spoofing,
		DetectionLogic: "In-scope web applications accessed via typical web access protocols by a caller used by " +
			"humans or a browser, directly or through technical assets forwarding the traffic, like load balancers, " +
			"reverse proxies and WAFs. Requests of other callers, like a backend or a batch job, come from no browser " +
			"a forged request could use, and are skipped.",
		RiskAssessment: "The risk rating depends on the integrity rating of the data sent across the communication link. " +
			"The attack is very likely, likely for DevOps usage, and unlikely when the link is authenticated with a token " +
			"(<i>" + types.Token.String() + "</i>, <i>" + types.ShortLivedToken.String() + "</i> or <i>" +
			types.LongLivedToken.String() + "</i>), which a browser does not send on its own like a cookie.",
		FalsePositives: "Web applications passing the authentication state via custom headers instead of cookies can " +
			"eventually be false positives; model their links with a token authentication. Clients used by humans that are " +
			"no browser and render no web content, like a command-line tool, can be considered as false positives " +
			"after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweCrossSiteRequestForgery,
		References:                 []string{owaspBrokenAccessControl},
	}
}

func (*CrossSiteRequestForgeryRule) SupportedTags() []string {
	return []string{}
}

func (r *CrossSiteRequestForgeryRule) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if r.skipAsset(technicalAsset) {
			continue
		}
		incomingFlows := parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		for _, incomingFlow := range incomingFlows {
			if !incomingFlow.Protocol.IsPotentialWebAccessProtocol() ||
				!r.comesFromBrowser(parsedModel, incomingFlow, make(map[string]bool)) {
				continue
			}
			risks = append(risks, r.createRisk(parsedModel, technicalAsset, incomingFlow))
		}
	}
	return risks, nil
}

// comesFromBrowser reports whether the requests of the link can come from the browser of a user, which a forged
// request needs: its caller is used by humans or is a browser, or forwards the web requests of such a caller, like a
// load balancer or a reverse proxy does.
func (r *CrossSiteRequestForgeryRule) comesFromBrowser(
	parsedModel *types.Model, link *types.CommunicationLink, visited map[string]bool,
) bool {
	caller, ok := parsedModel.TechnicalAssets[link.SourceId]
	if !ok || visited[caller.Id] {
		return false
	}
	if caller.UsedAsClientByHuman || caller.Technologies.GetAttribute(types.Browser) {
		return true
	}
	if !caller.Technologies.GetAttribute(types.IsTrafficForwarding) {
		return false
	}
	visited[caller.Id] = true
	for _, forwarded := range parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[caller.Id] {
		if forwarded.Protocol.IsPotentialWebAccessProtocol() && r.comesFromBrowser(parsedModel, forwarded, visited) {
			return true
		}
	}
	return false
}

func (csrf *CrossSiteRequestForgeryRule) skipAsset(technicalAsset *types.TechnicalAsset) bool {
	return technicalAsset.OutOfScope || !technicalAsset.Technologies.GetAttribute(types.IsWebApplication)
}

func (r *CrossSiteRequestForgeryRule) createRisk(
	parsedModel *types.Model, technicalAsset *types.TechnicalAsset, incomingFlow *types.CommunicationLink,
) *types.Risk {
	sourceAsset := parsedModel.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>Cross-Site Request Forgery (CSRF)</b> risk at <b>" + technicalAsset.Title + "</b> via <b>" +
		incomingFlow.Title + "</b> from <b>" + sourceAsset.Title + "</b>"
	impact := types.LowImpact
	if parsedModel.HighestCommunicationLinkIntegrity(incomingFlow) == types.MissionCritical {
		impact = types.MediumImpact
	}
	likelihood := r.likelihood(incomingFlow)
	risk := &types.Risk{
		CategoryId:                      r.Category().ID,
		Severity:                        types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: incomingFlow.Id,
		DataBreachProbability:           types.Improbable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id + "@" + incomingFlow.Id
	return risk
}

// likelihood rates a CSRF attack over the link: a browser sends cookies and client certificates along with a
// forged request, but no token that the application passes in a header.
func (*CrossSiteRequestForgeryRule) likelihood(cl *types.CommunicationLink) types.RiskExploitationLikelihood {
	switch cl.Authentication {
	case types.Token, types.ShortLivedToken, types.LongLivedToken:
		return types.Unlikely
	default:
	}
	if cl.Usage == types.DevOps {
		return types.Likely
	}
	return types.VeryLikely
}
