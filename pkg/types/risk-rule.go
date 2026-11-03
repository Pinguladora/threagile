package types

import "maps"

type RiskRule interface {
	Category() *RiskCategory
	SupportedTags() []string
	GenerateRisks(*Model) ([]*Risk, error)
}

type RiskRules map[string]RiskRule

func (what RiskRules) Merge(rules RiskRules) RiskRules {
	maps.Copy(what, rules)

	return what
}
