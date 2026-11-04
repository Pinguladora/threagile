package types

import "maps"

type RiskRule interface {
	Category() *RiskCategory
	SupportedTags() []string
	GenerateRisks(*Model) ([]*Risk, error)
}

// RiskExplainer is a risk rule that can explain in detail why it found a risk: ExplainRisk returns the lines of
// the explanation of the risk with the synthetic id, or none when it did not find the risk.
type RiskExplainer interface {
	ExplainRisk(model *Model, syntheticRiskId string) []string
}

type RiskRules map[string]RiskRule

func (what RiskRules) Merge(rules RiskRules) RiskRules {
	maps.Copy(what, rules)

	return what
}
