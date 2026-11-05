package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

type UnboundedModelConsumptionRule struct{}

func NewUnboundedModelConsumptionRule() *UnboundedModelConsumptionRule {
	return &UnboundedModelConsumptionRule{}
}

func (*UnboundedModelConsumptionRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "unbounded-model-consumption",
		Title: "Unbounded Model Consumption",
		Description: "Every request to a language model or an agent costs compute and tokens, and an agent can turn " +
			"one request into many model calls. Users who reach a model or an agent without a gateway that limits " +
			"their requests and tokens can exhaust its capacity, or the budget of a model paid for by use.",
		Impact: "If this risk is unmitigated, attackers, or a runaway agent, might make the model or the agent " +
			"unavailable for others, or run up its costs (denial of wallet).",
		ASVS:       asvsBusinessLogic,
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html",
		Action:     "Rate Limits and Token Budgets",
		Mitigation: "Put a gateway between the users and the model or agent, like an API gateway or an AI gateway, " +
			"that limits the requests and the tokens per user and per period, caps the length of inputs and outputs, " +
			"and alerts on spending, and limit the number of model calls and tool calls per task in the agent. Model " +
			"the gateway as a " + types.Gateway + " technical asset in the path from the users, or between the agent " +
			"and its language models.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Architecture,
		STRIDE:   types.DenialOfService,
		DetectionLogic: "In-scope " + types.LLM + " and " + types.AIAgent + " technical assets that users reach, " +
			"from the internet or from clients used by humans, through communication links that pass no " +
			types.Gateway + " technical asset. An agent that calls all its language models through a " + types.Gateway +
			" technical asset is skipped, as the gateway can limit its tokens.",
		RiskAssessment: "The risk rating depends on the availability rating of the data processed by the model or " +
			"agent, at least medium for the costs. The attack is very likely when users on the internet reach it, " +
			"and likely otherwise.",
		FalsePositives: "Models and agents whose platform enforces quotas per user, like a managed model service with " +
			"rate limits, can be considered as false positives after individual review.",
		ModelFailurePossibleReason: true,
		CWE:                        cweUnlimitedAllocation,
		References: []string{
			owaspLLMUnboundedConsumption, owaspAPIUnrestrictedResourceConsumption, maestroDeploymentAndInfrastucture,
		},
	}
}

func (*UnboundedModelConsumptionRule) SupportedTags() []string {
	return []string{}
}

func (r *UnboundedModelConsumptionRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, technicalAsset := range input.InScopeTechnicalAssets() {
		if !isPromptedAsset(technicalAsset) || callsModelsThroughGateway(input, technicalAsset) {
			continue
		}
		if reached, fromInternet := reachedByUsersWithoutGateway(input, technicalAsset); reached {
			risks = append(risks, r.createRisk(input, technicalAsset, fromInternet))
		}
	}
	return risks, nil
}

// callsModelsThroughGateway reports whether the agent calls its language models only through a gateway, which can
// limit the tokens it uses: it has a link to a gateway and none to a language model directly.
func callsModelsThroughGateway(input *types.Model, agent *types.TechnicalAsset) bool {
	if !isAIAgent(agent) {
		return false
	}
	throughGateway := false
	for _, link := range agent.CommunicationLinks {
		target, ok := input.TechnicalAssets[link.TargetId]
		if !ok {
			continue
		}
		if isLanguageModel(target) {
			return false
		}
		throughGateway = throughGateway || target.Technologies.GetAttribute(types.Gateway)
	}
	return throughGateway
}

// reachedByUsersWithoutGateway reports whether users reach the technical asset through links that pass no gateway:
// it follows the incoming links back from caller to caller, stopping at gateways, to a client used by humans or an
// asset on the internet, and reports whether one is on the internet.
func reachedByUsersWithoutGateway(input *types.Model, technicalAsset *types.TechnicalAsset) (bool, bool) {
	reached, fromInternet := false, false
	visited := map[string]bool{technicalAsset.Id: true}
	queue := []string{technicalAsset.Id}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, link := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[id] {
			caller, ok := input.TechnicalAssets[link.SourceId]
			if !ok || visited[caller.Id] || caller.Technologies.GetAttribute(types.Gateway) {
				continue
			}
			visited[caller.Id] = true
			if caller.Internet || caller.UsedAsClientByHuman {
				reached = true
				fromInternet = fromInternet || caller.Internet
				continue
			}
			queue = append(queue, caller.Id)
		}
	}
	return reached, fromInternet
}

func (r *UnboundedModelConsumptionRule) createRisk(
	input *types.Model, technicalAsset *types.TechnicalAsset, fromInternet bool,
) *types.Risk {
	likelihood := types.Likely
	if fromInternet {
		likelihood = types.VeryLikely
	}
	impact := max(types.MediumImpact,
		impactOfRatings(types.Public, types.Archive, input.HighestProcessedAvailability(technicalAsset)))

	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        assetRiskTitle("Unbounded Model Consumption", technicalAsset, ""),
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
