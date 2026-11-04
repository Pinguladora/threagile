package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

type MissingAIMonitoringRule struct{}

func NewMissingAIMonitoringRule() *MissingAIMonitoringRule {
	return &MissingAIMonitoringRule{}
}

func (*MissingAIMonitoringRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-ai-monitoring",
		Title: "Missing AI Monitoring",
		Description: "What an AI agent or a language model does depends on what it reads, so it cannot be tested " +
			"in full before it runs. Without a record of its prompts, its tool calls and its answers in a " +
			"monitoring system, nobody sees a prompt injection, an agent going astray or a model that drifts, nor " +
			"can tell afterwards what it did.",
		Impact: "If this risk is unmitigated, attacks through the model or the agent, and its own mistakes, might " +
			"go on unnoticed, and their effects could not be traced.",
		ASVS:       "V7 - Error Handling and Logging Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
		Action:     "AI Observability",
		Mitigation: "Send the prompts, tool calls, answers and decisions of the agent or model, with the user they " +
			"were for, to a monitoring system, for example as OpenTelemetry traces, and alert on anomalies like " +
			"injection attempts, unusual tool use and spikes in cost. Evaluate the quality and the safety of the " +
			"answers continuously, and model the monitoring system as a " + types.Monitoring + " technical asset " +
			"with a link to or from the agent or model.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Operations,
		STRIDE:   types.Repudiation,
		DetectionLogic: "In-scope " + types.AIAgent + " technical assets, and in-scope " + types.LLM + " technical " +
			"assets not on the internet (self-hosted models), with no communication link to or from a " +
			types.Monitoring + " technical asset.",
		RiskAssessment: "The risk rating depends on the sensitivity of the data processed by the agent or model. " +
			"The attack is likely when the agent or model takes untrusted content, and unlikely otherwise.",
		FalsePositives: "Agents and models whose platform records their prompts, tool calls and answers without a " +
			"modelled link, like a managed agent service with built-in tracing, can be considered as false " +
			"positives after individual review.",
		ModelFailurePossibleReason: true,
		CWE:                        cweInsufficientLogging,
		References:                 []string{maestroEvaluationAndObservability, owaspAgenticRogueAgents},
	}
}

func (*MissingAIMonitoringRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingAIMonitoringRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	untrusted := untrustedAssets(input)
	for _, technicalAsset := range input.InScopeTechnicalAssets() {
		if !isAIAgent(technicalAsset) && (!isLanguageModel(technicalAsset) || technicalAsset.Internet) {
			continue
		}
		if !isMonitored(input, technicalAsset) {
			risks = append(risks, r.createRisk(input, technicalAsset, takesUntrustedInput(input, untrusted, technicalAsset)))
		}
	}
	return risks, nil
}

// isMonitored reports whether the technical asset has a communication link to or from a monitoring system.
func isMonitored(input *types.Model, technicalAsset *types.TechnicalAsset) bool {
	for _, link := range technicalAsset.CommunicationLinks {
		if target, ok := input.TechnicalAssets[link.TargetId]; ok && target.Technologies.GetAttribute(types.Monitoring) {
			return true
		}
	}
	for _, link := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
		if source, ok := input.TechnicalAssets[link.SourceId]; ok && source.Technologies.GetAttribute(types.Monitoring) {
			return true
		}
	}
	return false
}

func (r *MissingAIMonitoringRule) createRisk(
	input *types.Model, technicalAsset *types.TechnicalAsset, untrustedInput bool,
) *types.Risk {
	likelihood := types.Unlikely
	if untrustedInput {
		likelihood = types.Likely
	}
	impact := processedImpact(input, technicalAsset)

	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        assetRiskTitle("Missing AI Monitoring", technicalAsset, ""),
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
