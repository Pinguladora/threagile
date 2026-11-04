package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

type PushInsteadPullDeploymentRule struct{}

func NewPushInsteadPullDeploymentRule() *PushInsteadPullDeploymentRule {
	return &PushInsteadPullDeploymentRule{}
}

func (*PushInsteadPullDeploymentRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "push-instead-of-pull-deployment",
		Title: "Push instead of Pull Deployment",
		Description: "When comparing push-based vs. pull-based deployments from a security perspective, pull-based " +
			"deployments improve the overall security of the deployment targets. Every exposed interface of a production system to accept a deployment " +
			"increases the attack surface of the production system, thus a pull-based approach exposes less attack surface relevant " +
			"interfaces.",
		Impact: "If this risk is unmitigated, attackers might have more potential target vectors for attacks, as the overall attack surface is " +
			"unnecessarily increased.",
		ASVS:       asvsArchitecture,
		CheatSheet: cheatSheetAttackSurfaceAnalysis,
		Action:     actionBuildPipelineHardening,
		Mitigation: "Try to prefer pull-based deployments (like GitOps scenarios offer) over push-based deployments to reduce the attack surface of the production system.",
		Check:      checkCheatSheetAndASVS,
		Function:   types.Architecture,
		STRIDE:     types.Tampering,
		DetectionLogic: "Models with build pipeline components accessing in-scope targets of deployment (in a non-readonly way) which " +
			"are not build-related components themselves.",
		RiskAssessment: "The risk rating depends on the highest sensitivity of the deployment targets running custom-developed parts.",
		FalsePositives: "Communication links that are not deployment paths " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: true,
		CWE:                        1127,
	}
}

func (*PushInsteadPullDeploymentRule) SupportedTags() []string {
	return []string{}
}

func (r *PushInsteadPullDeploymentRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, buildPipeline := range input.TechnicalAssets {
		if !buildPipeline.Technologies.GetAttribute(types.BuildPipeline) {
			continue
		}
		for _, deploymentLink := range buildPipeline.CommunicationLinks {
			targetAsset := input.TechnicalAssets[deploymentLink.TargetId]
			if deploymentLink.Readonly || deploymentLink.Usage != types.DevOps {
				continue
			}
			if targetAsset.OutOfScope {
				continue
			}
			if targetAsset.Technologies.GetAttribute(types.IsDevelopmentRelevant) || targetAsset.Usage == types.DevOps {
				continue
			}
			// rated per deployment target, so one sensitive target does not raise the others
			impact := types.LowImpact
			if input.HighestProcessedConfidentiality(targetAsset) >= types.Confidential ||
				input.HighestProcessedIntegrity(targetAsset) >= types.Critical ||
				input.HighestProcessedAvailability(targetAsset) >= types.Critical {
				impact = types.MediumImpact
			}
			risks = append(risks, r.createRisk(buildPipeline, targetAsset, deploymentLink, impact))
		}
	}
	return risks, nil
}

func (r *PushInsteadPullDeploymentRule) createRisk(buildPipeline *types.TechnicalAsset, deploymentTarget *types.TechnicalAsset, deploymentCommLink *types.CommunicationLink, impact types.RiskExploitationImpact) *types.Risk {
	title := "<b>Push instead of Pull Deployment</b> at <b>" + deploymentTarget.Title + "</b> via build pipeline asset <b>" + buildPipeline.Title + "</b>"
	risk := &types.Risk{
		CategoryId:                      r.Category().ID,
		Severity:                        types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood:          types.Unlikely,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    deploymentTarget.Id,
		MostRelevantCommunicationLinkId: deploymentCommLink.Id,
		DataBreachProbability:           types.Improbable,
		DataBreachTechnicalAssetIDs:     []string{deploymentTarget.Id},
	}
	// One risk per deployment target, so the target is part of the id; the build pipeline comes
	// first, so that "<category>@<pipeline>@*" tracks all of a pipeline's targets.
	risk.SyntheticId = risk.CategoryId + "@" + buildPipeline.Id + "@" + deploymentTarget.Id
	return risk
}
