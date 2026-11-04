package builtin

import (
	"strings"

	"github.com/Pinguladora/threagile/pkg/types"
)

type InsecureInterAgentCommunicationRule struct{}

func NewInsecureInterAgentCommunicationRule() *InsecureInterAgentCommunicationRule {
	return &InsecureInterAgentCommunicationRule{}
}

func (*InsecureInterAgentCommunicationRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "insecure-inter-agent-communication",
		Title: "Insecure Inter-Agent Communication",
		Description: "An AI agent takes the messages of another agent as tasks to act on. When it cannot verify " +
			"which agent sent a message, because the link is not authenticated or only with a static secret, or " +
			"cannot rely on the message being unchanged, because the link is not encrypted, anyone who reaches " +
			"the link can make it act, and a prompt injection in one agent passes on to the next.",
		Impact: "If this risk is unmitigated, attackers might spoof, change or replay messages between agents and " +
			"so make the receiving agent use its tools and permissions for their goals.",
		ASVS:       asvsAuthentication,
		CheatSheet: cheatSheetLLMPromptInjection,
		Action:     "Authenticated Agent Messages",
		Mitigation: "Authenticate the agents to each other with short-lived tokens bound to the workload identity " +
			"of each agent or with mutual TLS, encrypt the link, and sign the messages, or the agent cards of A2A, " +
			"where they pass through intermediaries. Pass on the identity of the user the task is for, and let " +
			"the receiving agent check that the sending agent may ask for the task.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Architecture,
		STRIDE:   types.Spoofing,
		DetectionLogic: "Communication links that are not process-local between " + types.AIAgent + " technical " +
			"assets, into an in-scope agent, whose authentication is <i>" + types.NoneAuthentication.String() +
			"</i>, <i>" + types.Credentials.String() + "</i>, <i>" + types.SessionId.String() + "</i> or <i>" +
			types.LongLivedToken.String() + "</i>, or whose protocol is not encrypted, when the receiving agent " +
			"processes data rated at least as " + types.Confidential.String() + " or " + types.Critical.String() +
			" or can change such an asset, directly or through the tools of an " + types.MCPServer +
			" technical asset.",
		RiskAssessment: "The risk rating depends on what the receiving agent can do: the most sensitive data it " +
			"processes or asset it can change. The attack is likely across a network trust boundary, and " +
			"unlikely otherwise. The rules on missing authentication, long-lived credentials and unencrypted " +
			"communication may report the same link for the data it carries.",
		FalsePositives: "Agents that verify each message on its own, for example by a signature of the sending " +
			"agent, can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweInsufficientAuthenticity,
		References: []string{
			owaspAgenticInterAgent, owaspAgenticCascadingFailures, maestroAgentEcosystem,
		},
	}
}

func (*InsecureInterAgentCommunicationRule) SupportedTags() []string {
	return []string{}
}

func (r *InsecureInterAgentCommunicationRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, agent := range input.InScopeTechnicalAssets() {
		if !isAIAgent(agent) {
			continue
		}
		reach := agentReach(input, agent)
		if reach < types.MediumImpact {
			continue
		}
		for _, link := range sortedIncomingLinks(input, agent) {
			sender, ok := input.TechnicalAssets[link.SourceId]
			if !ok || !isAIAgent(sender) || link.Protocol.IsProcessLocal() {
				continue
			}
			if weaknesses := r.weaknesses(link); len(weaknesses) > 0 {
				risks = append(risks, r.createRisk(input, agent, sender, link, reach, weaknesses))
			}
		}
	}
	return risks, nil
}

// weaknesses returns what keeps the receiving agent from relying on the messages of the link: an authentication
// that cannot tell the sending agent, or a static secret that can be replayed, and a missing encryption.
func (r *InsecureInterAgentCommunicationRule) weaknesses(link *types.CommunicationLink) []string {
	weaknesses := make([]string, 0)
	switch link.Authentication {
	case types.NoneAuthentication:
		weaknesses = append(weaknesses, "unauthenticated")
	case types.Credentials, types.SessionId, types.LongLivedToken:
		weaknesses = append(weaknesses, link.Authentication.String())
	default:
	}
	if !link.Protocol.IsEncrypted() {
		weaknesses = append(weaknesses, "unencrypted")
	}
	return weaknesses
}

// agentReach rates what an agent can do: the impact of the data it processes, or of the most sensitive asset it
// can change through its non-readonly links, directly or through the tools of an MCP server. Language models are
// no targets: calling one changes nothing.
func agentReach(input *types.Model, agent *types.TechnicalAsset) types.RiskExploitationImpact {
	reach := processedImpact(input, agent)
	for _, link := range agent.CommunicationLinksSorted() {
		target, ok := input.TechnicalAssets[link.TargetId]
		if !ok || link.Readonly || isLanguageModel(target) {
			continue
		}
		targets := []*types.TechnicalAsset{target}
		if target.Technologies.GetAttribute(types.MCPServer) {
			targets = toolTargets(input, target)
		}
		for _, changed := range targets {
			reach = max(reach, assetImpact(input, changed))
		}
	}
	return reach
}

func (r *InsecureInterAgentCommunicationRule) createRisk(
	input *types.Model, agent, sender *types.TechnicalAsset, link *types.CommunicationLink,
	reach types.RiskExploitationImpact, weaknesses []string,
) *types.Risk {
	likelihood := types.Unlikely
	if isAcrossTrustBoundaryNetworkOnly(input, link) {
		likelihood = types.Likely
	}

	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(likelihood, reach),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     reach,
		Title: assetRiskTitle("Insecure Inter-Agent Communication", agent,
			"from <b>"+sender.Title+"</b> ("+strings.Join(weaknesses, ", ")+")"),
		MostRelevantTechnicalAssetId:    agent.Id,
		MostRelevantCommunicationLinkId: link.Id,
		DataBreachProbability:           types.Improbable,
		DataBreachTechnicalAssetIDs:     []string{agent.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + agent.Id + "@" + link.Id
	return risk
}
