package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

type ExcessiveAgencyRule struct{}

func NewExcessiveAgencyRule() *ExcessiveAgencyRule {
	return &ExcessiveAgencyRule{}
}

func (*ExcessiveAgencyRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "excessive-agency",
		Title: "Excessive Agency",
		Description: "An AI agent decides on its own which tools to call and with which arguments. An agent that " +
			"can change critical systems, directly or through the tools of an MCP server, without a human " +
			"approving the change, does whatever a prompt injection, a hallucination or a misunderstanding makes " +
			"it do.",
		Impact: "If this risk is unmitigated, attackers who steer the agent, or the agent's own mistakes, might " +
			"change or delete critical data and trigger actions with real-world effects.",
		ASVS:       asvsAccessControl,
		CheatSheet: cheatSheetAuthorization,
		Action:     "Least Agency",
		Mitigation: "Give the agent only the tools and the permissions its task needs, read-only where possible, " +
			"and with the identity of the user it acts for rather than a broad technical one. Require a human " +
			"approval for changes to critical systems and tag the agent or the link with <i>" + humanInTheLoopTag +
			"</i> when it is in place. Limit the rate and the scope of actions and log every tool call.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Architecture,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "In-scope " + types.AIAgent + " technical assets with a non-readonly communication link to a " +
			"technical asset (other than an " + types.LLM + ") processing or storing data rated at least as " +
			types.Critical.String() + " in integrity, either directly or through the tools of an " + types.MCPServer +
			" technical asset. Agents and links " +
			"tagged with <i>" + humanInTheLoopTag + "</i> are skipped.",
		RiskAssessment: "The risk rating depends on the integrity rating of the technical asset the agent can " +
			"change. The attack is likely when the agent takes untrusted input, and unlikely otherwise.",
		FalsePositives: "Agents whose changes are reviewed by a human or are limited by other controls to what " +
			"is safe can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweUnnecessaryPrivileges,
		References: []string{
			owaspLLMExcessiveAgency, owaspAgenticToolMisuse, owaspAgenticPrivilegeAbuse, maestroAgentFrameworks,
		},
	}
}

func (*ExcessiveAgencyRule) SupportedTags() []string {
	return []string{humanInTheLoopTag}
}

func (r *ExcessiveAgencyRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	untrusted := untrustedAssets(input)
	for _, agent := range input.InScopeTechnicalAssets() {
		if !isAIAgent(agent) || agent.IsTaggedWithAny(humanInTheLoopTag) {
			continue
		}
		for _, link := range agent.CommunicationLinksSorted() {
			if link.Readonly || link.IsTaggedWithAny(humanInTheLoopTag) {
				continue
			}
			if target := r.criticalTarget(input, link); target != nil {
				risks = append(risks, r.createRisk(input, agent, link, target, takesUntrustedInput(input, untrusted, agent)))
			}
		}
	}
	return risks, nil
}

// criticalTarget returns the technical asset of the highest integrity that the agent can change through the
// link: its target, or, for an MCP server, the targets of the server's non-readonly links, which its tools
// change. Language models are no targets: calling one changes nothing. It returns nil when no target is rated
// at least as critical in integrity.
func (r *ExcessiveAgencyRule) criticalTarget(input *types.Model, link *types.CommunicationLink) *types.TechnicalAsset {
	target, ok := input.TechnicalAssets[link.TargetId]
	if !ok || isLanguageModel(target) {
		return nil
	}
	candidates := []*types.TechnicalAsset{target}
	if target.Technologies.GetAttribute(types.MCPServer) {
		candidates = toolTargets(input, target)
	}

	var critical *types.TechnicalAsset
	for _, candidate := range candidates {
		if input.HighestIntegrity(candidate) < types.Critical {
			continue
		}
		if critical == nil || input.HighestIntegrity(candidate) > input.HighestIntegrity(critical) {
			critical = candidate
		}
	}
	return critical
}

// toolTargets returns the technical assets the tools of an MCP server change: the targets of its non-readonly
// links.
func toolTargets(input *types.Model, server *types.TechnicalAsset) []*types.TechnicalAsset {
	targets := make([]*types.TechnicalAsset, 0)
	for _, toolLink := range server.CommunicationLinksSorted() {
		if toolTarget, ok := input.TechnicalAssets[toolLink.TargetId]; ok && !toolLink.Readonly {
			targets = append(targets, toolTarget)
		}
	}
	return targets
}

func (r *ExcessiveAgencyRule) createRisk(
	input *types.Model, agent *types.TechnicalAsset, link *types.CommunicationLink, target *types.TechnicalAsset,
	untrustedInput bool,
) *types.Risk {
	likelihood := types.Unlikely
	if untrustedInput {
		likelihood = types.Likely
	}
	impact := impactOfRatings(types.Public, input.HighestIntegrity(target), types.Archive)

	risk := &types.Risk{
		CategoryId:                      r.Category().ID,
		Severity:                        types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           assetRiskTitle("Excessive Agency", agent, "changing <b>"+target.Title+"</b>"),
		MostRelevantTechnicalAssetId:    agent.Id,
		MostRelevantCommunicationLinkId: link.Id,
		DataBreachProbability:           types.Improbable,
		DataBreachTechnicalAssetIDs:     []string{target.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + agent.Id + "@" + link.Id
	return risk
}
