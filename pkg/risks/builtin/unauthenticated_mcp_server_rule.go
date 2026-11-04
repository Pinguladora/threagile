package builtin

import (
	"sort"

	"github.com/Pinguladora/threagile/pkg/types"
)

type UnauthenticatedMCPServerRule struct{}

func NewUnauthenticatedMCPServerRule() *UnauthenticatedMCPServerRule {
	return &UnauthenticatedMCPServerRule{}
}

func (*UnauthenticatedMCPServerRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "unauthenticated-mcp-server",
		Title: "Unauthenticated MCP Server",
		Description: "An MCP server, or another server exposing tools to AI agents, acts on the systems behind its " +
			"tools with its own permissions. When it does not authenticate its callers, anyone who can reach it " +
			"can call those tools, and it cannot tell one agent or user from another to limit what each may do.",
		Impact: "If this risk is unmitigated, attackers who reach the server might call its tools directly and " +
			"read or change what they reach, bypassing the agents and their controls.",
		ASVS:       asvsAuthentication,
		CheatSheet: cheatSheetAuthentication,
		Action:     "Tool Server Authentication",
		Mitigation: "Authenticate every caller of the server, for example with OAuth 2.1 as the MCP specification " +
			"describes for HTTP transports, and pass on the identity of the user an agent acts for, so that each " +
			"tool call is authorized for that user. Expose the server only to the agents that need it.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Architecture,
		STRIDE:   types.Spoofing,
		DetectionLogic: "In-scope " + types.MCPServer + " technical assets with an incoming communication link " +
			"without authentication that is not process-local, whose tools (the outgoing communication links) " +
			"reach technical assets processing or storing data rated at least as " + types.Confidential.String() +
			" or " + types.Critical.String() + ".",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical assets the tools reach. The " +
			"attack is very likely when the caller is on the internet, likely when it takes untrusted input or " +
			"sits across a network trust boundary, and unlikely otherwise.",
		FalsePositives: "Servers whose tools only ever act with the permissions of an authenticated user, checked " +
			"by the systems behind them, can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweMissingAuthentication,
		References: []string{
			owaspAgenticToolMisuse, owaspAgenticPrivilegeAbuse, owaspLLMExcessiveAgency, maestroAgentEcosystem,
			maestroDeploymentAndInfrastucture,
		},
	}
}

func (*UnauthenticatedMCPServerRule) SupportedTags() []string {
	return []string{}
}

func (r *UnauthenticatedMCPServerRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	untrusted := untrustedAssets(input)
	for _, server := range input.InScopeTechnicalAssets() {
		if !server.Technologies.GetAttribute(types.MCPServer) {
			continue
		}
		impact, reachesSensitive := toolReachImpact(input, server)
		if !reachesSensitive {
			continue
		}
		for _, link := range sortedIncomingLinks(input, server) {
			if link.Authentication != types.NoneAuthentication || link.Protocol.IsProcessLocal() {
				continue
			}
			risks = append(risks, r.createRisk(input, untrusted, server, link, impact))
		}
	}
	return risks, nil
}

// toolReachImpact rates the impact by the most sensitive technical asset the server's outgoing links reach, and
// reports whether any of them is rated at least as confidential or critical.
func toolReachImpact(input *types.Model, server *types.TechnicalAsset) (types.RiskExploitationImpact, bool) {
	impact, reachesSensitive := types.LowImpact, false
	for _, link := range server.CommunicationLinksSorted() {
		target, ok := input.TechnicalAssets[link.TargetId]
		if !ok {
			continue
		}
		targetImpact := aiRiskImpact(input.HighestTechnicalAssetConfidentiality(target),
			input.HighestIntegrity(target), input.HighestAvailability(target))
		if targetImpact >= types.MediumImpact {
			reachesSensitive = true
		}
		impact = max(impact, targetImpact)
	}
	return impact, reachesSensitive
}

// sortedIncomingLinks returns the incoming links of the technical asset sorted by id.
func sortedIncomingLinks(input *types.Model, technicalAsset *types.TechnicalAsset) []*types.CommunicationLink {
	links := append([]*types.CommunicationLink{},
		input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]...)
	sort.Slice(links, func(i, j int) bool { return links[i].Id < links[j].Id })
	return links
}

func (r *UnauthenticatedMCPServerRule) createRisk(
	input *types.Model, untrusted map[string]bool, server *types.TechnicalAsset, link *types.CommunicationLink,
	impact types.RiskExploitationImpact,
) *types.Risk {
	caller := input.TechnicalAssets[link.SourceId]
	likelihood := types.Unlikely
	switch {
	case caller != nil && caller.Internet:
		likelihood = types.VeryLikely
	case untrusted[link.SourceId], isAcrossTrustBoundaryNetworkOnly(input, link):
		likelihood = types.Likely
	}
	callerTitle := link.SourceId
	if caller != nil {
		callerTitle = caller.Title
	}

	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: aiRiskTitle("Unauthenticated MCP Server", server,
			"called by <b>"+callerTitle+"</b>"),
		MostRelevantTechnicalAssetId:    server.Id,
		MostRelevantCommunicationLinkId: link.Id,
		DataBreachProbability:           types.Possible,
		DataBreachTechnicalAssetIDs:     []string{server.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + server.Id + "@" + link.Id
	return risk
}
