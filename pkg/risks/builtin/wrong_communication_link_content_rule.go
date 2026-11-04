package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

type WrongCommunicationLinkContentRule struct{}

func NewWrongCommunicationLinkContentRule() *WrongCommunicationLinkContentRule {
	return &WrongCommunicationLinkContentRule{}
}

func (*WrongCommunicationLinkContentRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "wrong-communication-link-content",
		Title: "Wrong Communication Link Content",
		Description: "When a communication link is defined as readonly, but does not receive any data asset, " +
			"or when it is defined as not readonly, but does not send any data asset, it is likely to be a model failure.",
		Impact:     "If this potential model error is not fixed, some risks might not be visible.",
		ASVS:       asvsArchitecture,
		CheatSheet: cheatSheetThreatModeling,
		Action:     "Model Consistency",
		Mitigation: "Try to model the correct readonly flag and/or data sent/received of communication links. " +
			"Also try to use  communication link types matching the target technology/machine types.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Architecture,
		STRIDE:   types.InformationDisclosure,
		DetectionLogic: "Communication links with inconsistent data assets being sent/received not matching " +
			"their readonly flag or otherwise inconsistent protocols not matching the target technology type.",
		RiskAssessment:             types.LowSeverity.String(),
		FalsePositives:             falsePositivesIncompleteModel,
		ModelFailurePossibleReason: true,
		CWE:                        cweArchitecturalConcepts,
	}
}

func (*WrongCommunicationLinkContentRule) SupportedTags() []string {
	return []string{}
}

func (r *WrongCommunicationLinkContentRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, techAsset := range input.TechnicalAssets {
		for _, commLink := range techAsset.CommunicationLinks {
			// check readonly consistency
			if hasReadonlyMismatch(commLink) {
				risks = append(risks, r.createRisk(techAsset, commLink,
					"(data assets sent/received not matching the communication link's readonly flag)"))
			}
			// check for protocol inconsistencies
			targetAsset := input.TechnicalAssets[commLink.TargetId]
			if reason := protocolMismatch(commLink, targetAsset); reason != "" {
				risks = append(risks, r.createRisk(techAsset, commLink, reason))
			}
		}
	}
	return risks, nil
}

func hasReadonlyMismatch(commLink *types.CommunicationLink) bool {
	if commLink.Readonly {
		return len(commLink.DataAssetsReceived) == 0 && len(commLink.DataAssetsSent) > 0
	}
	return len(commLink.DataAssetsSent) == 0 && len(commLink.DataAssetsReceived) > 0
}

// protocolMismatch returns why the protocol of the communication link does not match its target, or "" when it
// matches.
func protocolMismatch(commLink *types.CommunicationLink, targetAsset *types.TechnicalAsset) string {
	switch commLink.Protocol {
	case types.InterProcessCommunication:
		if targetAsset.Type != types.Process {
			return "(protocol type \"" + types.InterProcessCommunication.String() +
				"\" does not match target technology type \"" + targetAsset.Technologies.String() +
				"\": expected \"" + types.Process.String() + "\")"
		}
	case types.InProcessLibraryCall:
		if !targetAsset.Technologies.GetAttribute(types.Library) {
			return "(protocol type \"" + types.InProcessLibraryCall.String() +
				"\" does not match target technology type \"" + targetAsset.Technologies.String() +
				"\": expected \"" + types.Library + "\")"
		}
	case types.LocalFileAccess:
		if !targetAsset.Technologies.GetAttribute(types.LocalFileSystem) {
			return "(protocol type \"" + types.LocalFileAccess.String() +
				"\" does not match target technology type \"" + targetAsset.Technologies.String() +
				"\": expected \"" + types.LocalFileSystem + "\")"
		}
	case types.ContainerSpawning:
		if targetAsset.Machine != types.Container {
			return "(protocol type \"" + types.ContainerSpawning.String() +
				"\" does not match target machine type \"" + targetAsset.Machine.String() +
				"\": expected \"" + types.Container.String() + "\")"
		}
	}
	return ""
}

func (r *WrongCommunicationLinkContentRule) createRisk(
	technicalAsset *types.TechnicalAsset, commLink *types.CommunicationLink, reason string,
) *types.Risk {
	title := "<b>Wrong Communication Link Content</b> " + reason + " at <b>" + technicalAsset.Title + "</b> " +
		"regarding communication link <b>" + commLink.Title + "</b>"
	risk := &types.Risk{
		CategoryId:                      r.Category().ID,
		Severity:                        types.CalculateSeverity(types.Unlikely, types.LowImpact),
		ExploitationLikelihood:          types.Unlikely,
		ExploitationImpact:              types.LowImpact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: commLink.Id,
		DataBreachProbability:           types.Improbable,
		DataBreachTechnicalAssetIDs:     []string{},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id + "@" + commLink.Id
	return risk
}
