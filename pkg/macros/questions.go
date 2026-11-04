package macros

import (
	"sort"

	"github.com/Pinguladora/threagile/pkg/types"
)

// technicalAssetsQuestion asks to select some of the technical assets of the model; without any, there
// are no more questions.
func technicalAssetsQuestion(model *types.Model, id string, title string) MacroQuestion {
	possibleAnswers := make([]string, 0, len(model.TechnicalAssets))
	for assetID := range model.TechnicalAssets {
		possibleAnswers = append(possibleAnswers, assetID)
	}
	sort.Strings(possibleAnswers)
	if len(possibleAnswers) == 0 {
		return NoMoreQuestions()
	}
	return MacroQuestion{
		ID:              id,
		Title:           title,
		Description:     "This affects the communication links being generated.",
		PossibleAnswers: possibleAnswers,
		MultiSelect:     true,
		DefaultAnswer:   "",
	}
}

// selectTrustBoundaryQuestion asks for one of the network trust boundaries of the model, or for a new one.
func selectTrustBoundaryQuestion(model *types.Model) MacroQuestion {
	possibleAnswers := []string{createNewTrustBoundaryLabel}
	for id, trustBoundary := range model.TrustBoundaries {
		if trustBoundary.Type.IsNetworkBoundary() {
			possibleAnswers = append(possibleAnswers, id)
		}
	}
	sort.Strings(possibleAnswers)
	return MacroQuestion{
		ID:              selectedTrustBoundaryQuestion,
		Title:           "Choose from the list of existing network trust boundaries or create a new one?",
		Description:     "",
		PossibleAnswers: possibleAnswers,
		MultiSelect:     false,
		DefaultAnswer:   "",
	}
}

// newTrustBoundaryTypeQuestion asks for the type of a new trust boundary.
var newTrustBoundaryTypeQuestion = MacroQuestion{
	ID:          "new-trust-boundary-type",
	Title:       "Of which type shall the new trust boundary be?",
	Description: "",
	PossibleAnswers: []string{
		types.NetworkOnPrem.String(),
		types.NetworkDedicatedHoster.String(),
		types.NetworkVirtualLAN.String(),
		types.NetworkCloudProvider.String(),
		types.NetworkCloudSecurityGroup.String(),
		types.NetworkPolicyNamespaceIsolation.String(),
	},
	MultiSelect:   false,
	DefaultAnswer: types.NetworkOnPrem.String(),
}
