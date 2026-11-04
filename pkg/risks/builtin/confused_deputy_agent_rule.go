package builtin

import (
	"slices"

	"github.com/Pinguladora/threagile/pkg/types"
)

type ConfusedDeputyAgentRule struct{}

func NewConfusedDeputyAgentRule() *ConfusedDeputyAgentRule {
	return &ConfusedDeputyAgentRule{}
}

func (*ConfusedDeputyAgentRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "confused-deputy-agent",
		Title: "Confused Deputy Agent",
		Description: "An AI agent that acts for its users but reaches data and tools with an identity of its own, " +
			"a service account or a workload, can do for any user what the agent may do for all of them. The " +
			"targets check the agent, not the user, so whatever a user asks for, or a prompt injection makes the " +
			"agent ask for, is allowed.",
		Impact: "If this risk is unmitigated, users and attackers who steer the agent might read or change the data " +
			"of other users through it.",
		ASVS:       asvsAccessControl,
		CheatSheet: cheatSheetAuthorization,
		Action:     "Act with the Identity of the User",
		Mitigation: "Let the agent call data and tools with the identity of the user it acts for, for example " +
			"through OAuth 2.0 token exchange or on-behalf-of flows, scoped to the task, and model those links with " +
			"the identity <i>" + types.EndUser.String() + "</i>. Where the agent must use its own identity, " +
			"authorize each call by the user in the agent and keep its own permissions to what every user may do.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Architecture,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "In-scope " + types.AIAgent + " technical assets that act for users, through an incoming " +
			"communication link with the identity <i>" + types.EndUser.String() + "</i> or from a caller used by " +
			"humans (other than devops links), and reach a technical asset (other than an " + types.LLM + ") " +
			"processing or storing data rated at least as " + types.Confidential.String() + " or " +
			types.Critical.String() + " with the identity <i>" + types.ServiceAccount.String() + "</i> or <i>" +
			types.Workload.String() + "</i>, either directly or through the tools of an " + types.MCPServer +
			" technical asset.",
		RiskAssessment: "The risk rating depends on the sensitivity of the most sensitive technical asset the agent " +
			"reaches with its own identity. The attack is likely when the agent takes untrusted input, and unlikely " +
			"otherwise.",
		FalsePositives: "Agents whose data and tools hold nothing that any one user may not see or change, or that " +
			"authorize each call by the user themselves, can be considered as false positives after individual " +
			"review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweConfusedDeputy,
		References: []string{
			owaspAgenticPrivilegeAbuse, owaspLLMExcessiveAgency, owaspNHIReuse, maestroAgentFrameworks,
		},
	}
}

func (*ConfusedDeputyAgentRule) SupportedTags() []string {
	return []string{}
}

func (r *ConfusedDeputyAgentRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	untrusted := untrustedAssets(input)
	for _, agent := range input.InScopeTechnicalAssets() {
		if !isAIAgent(agent) || !r.actsForUsers(input, agent) {
			continue
		}
		reached := r.reachedWithOwnIdentity(input, agent)
		if len(reached) == 0 {
			continue
		}
		risks = append(risks, r.createRisk(input, agent, reached, takesUntrustedInput(input, untrusted, agent)))
	}
	return risks, nil
}

// actsForUsers reports whether the agent carries the requests of users: an incoming link propagates their identity
// or comes from a client that humans use.
func (r *ConfusedDeputyAgentRule) actsForUsers(input *types.Model, agent *types.TechnicalAsset) bool {
	for _, link := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[agent.Id] {
		if caller, ok := input.TechnicalAssets[link.SourceId]; ok && actsForUsers(link, caller) {
			return true
		}
	}
	return false
}

// reachedAsset is a sensitive technical asset that the agent reaches with its own identity, and the link of the
// agent it goes through.
type reachedAsset struct {
	target *types.TechnicalAsset
	link   *types.CommunicationLink
}

// reachedWithOwnIdentity returns the sensitive technical assets that the agent reaches with an identity of its own:
// the targets of its links with a machine identity, and, for an MCP server, the targets of the server's links with
// one, which its tools reach. Language models are no targets: they hold no data of the users.
func (r *ConfusedDeputyAgentRule) reachedWithOwnIdentity(
	input *types.Model, agent *types.TechnicalAsset,
) []reachedAsset {
	reached := make([]reachedAsset, 0)
	add := func(target *types.TechnicalAsset, link *types.CommunicationLink) {
		if !isLanguageModel(target) && isSensitive(input, target) {
			reached = append(reached, reachedAsset{target: target, link: link})
		}
	}
	for _, link := range agent.CommunicationLinksSorted() {
		target, ok := input.TechnicalAssets[link.TargetId]
		if !ok {
			continue
		}
		if !target.Technologies.GetAttribute(types.MCPServer) {
			if isMachineIdentity(link.Identity) {
				add(target, link)
			}
			continue
		}
		for _, toolLink := range target.CommunicationLinksSorted() {
			if toolTarget, found := input.TechnicalAssets[toolLink.TargetId]; found && isMachineIdentity(toolLink.Identity) {
				add(toolTarget, link)
			}
		}
	}
	return reached
}

func (r *ConfusedDeputyAgentRule) createRisk(
	input *types.Model, agent *types.TechnicalAsset, reached []reachedAsset, untrustedInput bool,
) *types.Risk {
	likelihood := types.Unlikely
	if untrustedInput {
		likelihood = types.Likely
	}

	mostSensitive := reached[0]
	targets := make([]string, 0, len(reached))
	for _, candidate := range reached {
		if assetImpact(input, candidate.target) > assetImpact(input, mostSensitive.target) {
			mostSensitive = candidate
		}
		targets = append(targets, candidate.target.Id)
	}
	slices.Sort(targets)
	impact := assetImpact(input, mostSensitive.target)

	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: assetRiskTitle("Confused Deputy Agent", agent,
			"reaching <b>"+mostSensitive.target.Title+"</b> with its own identity"),
		MostRelevantTechnicalAssetId:    agent.Id,
		MostRelevantCommunicationLinkId: mostSensitive.link.Id,
		DataBreachProbability:           types.Probable,
		DataBreachTechnicalAssetIDs:     slices.Compact(targets),
	}
	risk.SyntheticId = risk.CategoryId + "@" + agent.Id
	return risk
}
