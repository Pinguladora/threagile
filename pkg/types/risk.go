package types

type Risk struct {
	CategoryId                      string                     `json:"category,omitempty"                         yaml:"category,omitempty"`    // used for better JSON marshalling, is assigned in risk evaluation phase automatically
	RiskStatus                      RiskStatus                 `json:"risk_status"                                yaml:"risk_status,omitempty"` // used for better JSON marshalling, is assigned in risk evaluation phase automatically
	Severity                        RiskSeverity               `json:"severity"                                   yaml:"severity,omitempty"`
	ExploitationLikelihood          RiskExploitationLikelihood `json:"exploitation_likelihood"                    yaml:"exploitation_likelihood,omitempty"`
	ExploitationImpact              RiskExploitationImpact     `json:"exploitation_impact"                        yaml:"exploitation_impact,omitempty"`
	Title                           string                     `json:"title,omitempty"                            yaml:"title,omitempty"`
	SyntheticId                     string                     `json:"synthetic_id,omitempty"                     yaml:"synthetic_id,omitempty"`
	MostRelevantDataAssetId         string                     `json:"most_relevant_data_asset,omitempty"         yaml:"most_relevant_data_asset,omitempty"`
	MostRelevantTechnicalAssetId    string                     `json:"most_relevant_technical_asset,omitempty"    yaml:"most_relevant_technical_asset,omitempty"`
	MostRelevantTrustBoundaryId     string                     `json:"most_relevant_trust_boundary,omitempty"     yaml:"most_relevant_trust_boundary,omitempty"`
	MostRelevantSharedRuntimeId     string                     `json:"most_relevant_shared_runtime,omitempty"     yaml:"most_relevant_shared_runtime,omitempty"`
	MostRelevantCommunicationLinkId string                     `json:"most_relevant_communication_link,omitempty" yaml:"most_relevant_communication_link,omitempty"`
	DataBreachProbability           DataBreachProbability      `json:"data_breach_probability"                    yaml:"data_breach_probability,omitempty"`
	DataBreachTechnicalAssetIDs     []string                   `json:"data_breach_technical_assets,omitempty"     yaml:"data_breach_technical_assets,omitempty"`
	RiskExplanation                 []string                   `json:"risk_explanation,omitempty"                 yaml:"risk_explanation,omitempty"`
	RatingExplanation               []string                   `json:"rating_explanation,omitempty"               yaml:"rating_explanation,omitempty"`
	// The fields spell ID and Id inconsistently; renaming them would change the exported API.
}
