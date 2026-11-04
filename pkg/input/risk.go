package input

import "fmt"

type RiskIdentified struct {
	Severity                      string   `json:"severity,omitempty"                         yaml:"severity,omitempty"`
	ExploitationLikelihood        string   `json:"exploitation_likelihood,omitempty"          yaml:"exploitation_likelihood,omitempty"`
	ExploitationImpact            string   `json:"exploitation_impact,omitempty"              yaml:"exploitation_impact,omitempty"`
	DataBreachProbability         string   `json:"data_breach_probability,omitempty"          yaml:"data_breach_probability,omitempty"`
	DataBreachTechnicalAssets     []string `json:"data_breach_technical_assets,omitempty"     yaml:"data_breach_technical_assets,omitempty"`
	MostRelevantDataAsset         string   `json:"most_relevant_data_asset,omitempty"         yaml:"most_relevant_data_asset,omitempty"`
	MostRelevantTechnicalAsset    string   `json:"most_relevant_technical_asset,omitempty"    yaml:"most_relevant_technical_asset,omitempty"`
	MostRelevantCommunicationLink string   `json:"most_relevant_communication_link,omitempty" yaml:"most_relevant_communication_link,omitempty"`
	MostRelevantTrustBoundary     string   `json:"most_relevant_trust_boundary,omitempty"     yaml:"most_relevant_trust_boundary,omitempty"`
	MostRelevantSharedRuntime     string   `json:"most_relevant_shared_runtime,omitempty"     yaml:"most_relevant_shared_runtime,omitempty"`
}

func (what *RiskIdentified) Merge(other RiskIdentified) error {
	mergeError := mergeSingletons(
		singleton("severity", &what.Severity, other.Severity),
		singleton("exploitation_likelihood", &what.ExploitationLikelihood, other.ExploitationLikelihood),
		singleton("exploitation_impact", &what.ExploitationImpact, other.ExploitationImpact),
		// the merge error has always called this field "date"
		singleton("date", &what.DataBreachProbability, other.DataBreachProbability),
	)
	if mergeError != nil {
		return mergeError
	}

	what.DataBreachTechnicalAssets = new(Strings).MergeUniqueSlice(what.DataBreachTechnicalAssets,
		other.DataBreachTechnicalAssets)

	return mergeSingletons(
		singleton("most_relevant_data_asset", &what.MostRelevantDataAsset, other.MostRelevantDataAsset),
		singleton("most_relevant_technical_asset", &what.MostRelevantTechnicalAsset, other.MostRelevantTechnicalAsset),
		singleton("most_relevant_communication_link", &what.MostRelevantCommunicationLink,
			other.MostRelevantCommunicationLink),
		singleton("most_relevant_trust_boundary", &what.MostRelevantTrustBoundary, other.MostRelevantTrustBoundary),
		singleton("most_relevant_shared_runtime", &what.MostRelevantSharedRuntime, other.MostRelevantSharedRuntime),
	)
}

func (what *RiskIdentified) MergeMap(
	first map[string]RiskIdentified, second map[string]RiskIdentified,
) (map[string]RiskIdentified, error) {
	if first == nil {
		// first is nil for a section that is missing, or a key left without a value, in the model merged into
		first = make(map[string]RiskIdentified, len(second))
	}

	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			mergeError := mapItem.Merge(mapValue)
			if mergeError != nil {
				return first, fmt.Errorf("failed to merge risk %q: %w", mapKey, mergeError)
			}

			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}

	return first, nil
}
