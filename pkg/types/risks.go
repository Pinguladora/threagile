/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import "sort"

func ReduceToOnlyStillAtRisk(risks []*Risk) []*Risk {
	filteredRisks := make([]*Risk, 0)
	for _, risk := range risks {
		if risk.RiskStatus.IsStillAtRisk() {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func HighestSeverityStillAtRisk(risks []*Risk) RiskSeverity {
	result := LowSeverity
	for _, risk := range risks {
		if risk.Severity > result && risk.RiskStatus.IsStillAtRisk() {
			result = risk.Severity
		}
	}
	return result
}

func SortByRiskSeverity(risks []*Risk) {
	sort.Slice(risks, func(i, j int) bool {
		if risks[i].Severity == risks[j].Severity {
			trackingStatusLeft := risks[i].RiskStatus
			trackingStatusRight := risks[j].RiskStatus
			if trackingStatusLeft == trackingStatusRight {
				impactLeft := risks[i].ExploitationImpact
				impactRight := risks[j].ExploitationImpact
				if impactLeft == impactRight {
					likelihoodLeft := risks[i].ExploitationLikelihood
					likelihoodRight := risks[j].ExploitationLikelihood
					if likelihoodLeft == likelihoodRight {
						if risks[i].Title == risks[j].Title {
							return risks[i].SyntheticId < risks[j].SyntheticId
						}
						return risks[i].Title < risks[j].Title
					} else {
						return likelihoodLeft > likelihoodRight
					}
				} else {
					return impactLeft > impactRight
				}
			} else {
				return trackingStatusLeft < trackingStatusRight
			}
		}
		return risks[i].Severity > risks[j].Severity
	})
}

type ByRiskCategoryTitleSort []*RiskCategory

func (what ByRiskCategoryTitleSort) Len() int { return len(what) }
func (what ByRiskCategoryTitleSort) Swap(i, j int) {
	what[i], what[j] = what[j], what[i]
}

func (what ByRiskCategoryTitleSort) Less(i, j int) bool {
	if what[i].Title == what[j].Title {
		return what[i].ID < what[j].ID
	}
	return what[i].Title < what[j].Title
}
