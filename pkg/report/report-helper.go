package report

import (
	"maps"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/Pinguladora/threagile/pkg/types"
)

func filteredByRiskStatus(parsedModel *types.Model, status types.RiskStatus) []*types.Risk {
	filteredRisks := make([]*types.Risk, 0)
	for _, risks := range sortedByCategory(parsedModel.GeneratedRisksByCategoryWithCurrentStatus()) {
		for _, risk := range risks {
			if risk.RiskStatus == status {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func filteredByRiskFunction(parsedModel *types.Model, function types.RiskFunction) []*types.Risk {
	filteredRisks := make([]*types.Risk, 0)
	for _, categoryId := range slices.Sorted(maps.Keys(parsedModel.GeneratedRisksByCategory)) {
		category := parsedModel.GetRiskCategory(categoryId)
		for _, risk := range parsedModel.GeneratedRisksByCategory[categoryId] {
			if category.Function == function {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

// sortedByCategory returns the risk lists of a by-category map in category id order.
func sortedByCategory(risksByCategory map[string][]*types.Risk) [][]*types.Risk {
	result := make([][]*types.Risk, 0, len(risksByCategory))
	for _, categoryId := range slices.Sorted(maps.Keys(risksByCategory)) {
		result = append(result, risksByCategory[categoryId])
	}
	return result
}

func reduceToRiskStatus(risks []*types.Risk, status types.RiskStatus) []*types.Risk {
	filteredRisks := make([]*types.Risk, 0)
	for _, risk := range risks {
		if risk.RiskStatus == status {
			filteredRisks = append(filteredRisks, risk)
		}
	}
	return filteredRisks
}

func reduceToFunctionRisk(parsedModel *types.Model, risksByCategory map[string][]*types.Risk, function types.RiskFunction) map[string][]*types.Risk {
	result := make(map[string][]*types.Risk)
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			category := parsedModel.GetRiskCategory(categoryId)
			if category.Function == function {
				result[categoryId] = append(result[categoryId], risk)
			}
		}
	}
	return result
}

func reduceToSTRIDERisk(parsedModel *types.Model, risksByCategory map[string][]*types.Risk, stride types.STRIDE) map[string][]*types.Risk {
	result := make(map[string][]*types.Risk)
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			category := parsedModel.GetRiskCategory(categoryId)
			if category != nil && category.STRIDE == stride {
				result[categoryId] = append(result[categoryId], risk)
			}
		}
	}
	return result
}

func countRisks(risksByCategory map[string][]*types.Risk) int {
	result := 0
	for _, risks := range risksByCategory {
		result += len(risks)
	}
	return result
}

func totalRiskCount(parsedModel *types.Model) int {
	count := 0
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		count += len(risks)
	}
	return count
}

func sortedTechnicalAssetsByRAAAndTitle(parsedModel *types.Model) []*types.TechnicalAsset {
	assets := make([]*types.TechnicalAsset, 0)
	for _, asset := range parsedModel.TechnicalAssets {
		assets = append(assets, asset)
	}
	sort.Sort(types.ByTechnicalAssetRAAAndTitleSort(assets))
	return assets
}

func sortedKeysOfQuestions(parsedModel *types.Model) []string {
	keys := make([]string, 0)
	for k := range parsedModel.Questions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func filteredBySeverity(parsedModel *types.Model, severity types.RiskSeverity) []*types.Risk {
	filteredRisks := make([]*types.Risk, 0)
	for _, risks := range sortedByCategory(parsedModel.GeneratedRisksByCategoryWithCurrentStatus()) {
		for _, risk := range risks {
			if risk.Severity == severity {
				filteredRisks = append(filteredRisks, risk)
			}
		}
	}
	return filteredRisks
}

func sortedTechnicalAssetsByRiskSeverityAndTitle(parsedModel *types.Model) []*types.TechnicalAsset {
	assets := make([]*types.TechnicalAsset, 0)
	for _, asset := range parsedModel.TechnicalAssets {
		assets = append(assets, asset)
	}
	sortByTechnicalAssetRiskSeverityAndTitleStillAtRisk(assets, parsedModel)
	return assets
}

func filteredByStillAtRisk(parsedModel *types.Model) []*types.Risk {
	filteredRisks := make([]*types.Risk, 0)
	for _, risks := range sortedByCategory(parsedModel.GeneratedRisksByCategoryWithCurrentStatus()) {
		stillAtRisk := types.ReduceToOnlyStillAtRisk(risks)
		filteredRisks = append(filteredRisks, stillAtRisk...)
	}
	return filteredRisks
}

func identifiedDataBreachProbabilityStillAtRisk(parsedModel *types.Model, dataAsset *types.DataAsset) types.DataBreachProbability {
	highestProbability := types.Improbable
	for _, risk := range filteredByStillAtRisk(parsedModel) {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsProcessed, dataAsset.Id) {
				if risk.DataBreachProbability > highestProbability {
					highestProbability = risk.DataBreachProbability
					break
				}
			}
		}
	}
	return highestProbability
}

func sortByTechnicalAssetRiskSeverityAndTitleStillAtRisk(assets []*types.TechnicalAsset, parsedModel *types.Model) {
	sort.Slice(assets, func(i, j int) bool {
		risksLeft := types.ReduceToOnlyStillAtRisk(parsedModel.GeneratedRisks(assets[i]))
		risksRight := types.ReduceToOnlyStillAtRisk(parsedModel.GeneratedRisks(assets[j]))
		highestSeverityLeft := types.HighestSeverityStillAtRisk(risksLeft)
		highestSeverityRight := types.HighestSeverityStillAtRisk(risksRight)
		if highestSeverityLeft == highestSeverityRight {
			if len(risksLeft) == 0 && len(risksRight) > 0 {
				return false
			}
			if len(risksLeft) > 0 && len(risksRight) == 0 {
				return true
			}
			return outOfScopeLast(assets[i], assets[j], assets[i].Title < assets[j].Title)
		}
		return outOfScopeLast(assets[i], assets[j], highestSeverityLeft > highestSeverityRight)
	})
}

// outOfScopeLast orders out-of-scope technical assets after the others, and by title among
// themselves; less decides the order of two assets in scope.
func outOfScopeLast(left, right *types.TechnicalAsset, less bool) bool {
	switch {
	case left.OutOfScope && right.OutOfScope:
		return left.Title < right.Title
	case left.OutOfScope:
		return false
	case right.OutOfScope:
		return true
	}
	return less
}

func sortedDataAssetsByDataBreachProbabilityAndTitle(parsedModel *types.Model) []*types.DataAsset {
	assets := sortedValues(parsedModel.DataAssets)

	sortByDataAssetDataBreachProbabilityAndTitleStillAtRisk(parsedModel, assets)
	return assets
}

func sortByDataAssetDataBreachProbabilityAndTitleStillAtRisk(parsedModel *types.Model, assets []*types.DataAsset) {
	sort.Slice(assets, func(i, j int) bool {
		risksLeft := identifiedDataBreachProbabilityRisksStillAtRisk(parsedModel, assets[i])
		risksRight := identifiedDataBreachProbabilityRisksStillAtRisk(parsedModel, assets[j])
		highestDataBreachProbabilityLeft := identifiedDataBreachProbabilityStillAtRisk(parsedModel, assets[i])
		highestDataBreachProbabilityRight := identifiedDataBreachProbabilityStillAtRisk(parsedModel, assets[j])
		if highestDataBreachProbabilityLeft == highestDataBreachProbabilityRight {
			if len(risksLeft) == 0 && len(risksRight) > 0 {
				return false
			}
			if len(risksLeft) > 0 && len(risksRight) == 0 {
				return true
			}
			return assets[i].Title < assets[j].Title
		}
		return highestDataBreachProbabilityLeft > highestDataBreachProbabilityRight
	})
}

func filterByModelFailures(parsedModel *types.Model, risksByCat map[string][]*types.Risk) map[string][]*types.Risk {
	result := make(map[string][]*types.Risk)
	for categoryId, risks := range risksByCat {
		category := parsedModel.GetRiskCategory(categoryId)
		if category.ModelFailurePossibleReason {
			result[categoryId] = risks
		}
	}

	return result
}

func flattenRiskSlice(risksByCat map[string][]*types.Risk) []*types.Risk {
	result := make([]*types.Risk, 0)
	for _, categoryId := range slices.Sorted(maps.Keys(risksByCat)) {
		result = append(result, risksByCat[categoryId]...)
	}
	return result
}

func highestExploitationLikelihood(risks []*types.Risk) types.RiskExploitationLikelihood {
	result := types.Unlikely
	for _, risk := range risks {
		if risk.ExploitationLikelihood > result {
			result = risk.ExploitationLikelihood
		}
	}
	return result
}

func highestExploitationImpact(risks []*types.Risk) types.RiskExploitationImpact {
	result := types.LowImpact
	for _, risk := range risks {
		if risk.ExploitationImpact > result {
			result = risk.ExploitationImpact
		}
	}
	return result
}

func firstParagraph(text string) string {
	firstParagraphRegEx := regexp.MustCompile(`(.*?)((<br>)|(<p>))`)
	match := firstParagraphRegEx.FindStringSubmatch(text)
	if len(match) == 0 {
		return text
	}
	return match[1]
}

func getRiskCategories(parsedModel *types.Model, categoryIDs []string) []*types.RiskCategory {
	categories := make([]*types.RiskCategory, 0)
	seen := make(map[string]bool)
	for _, categoryId := range categoryIDs {
		category := parsedModel.GetRiskCategory(categoryId)
		if category != nil && !seen[categoryId] {
			seen[categoryId] = true
			categories = append(categories, category)
		}
	}

	return categories
}

func reduceToSeverityRisk(risksByCategory map[string][]*types.Risk, initialRisks bool,
	severity types.RiskSeverity,
) []string {
	categories := make(map[string]struct{}) // Go's trick of unique elements is a map
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			if !initialRisks && !risk.RiskStatus.IsStillAtRisk() {
				continue
			}
			if risk.Severity == severity {
				categories[categoryId] = struct{}{}
			}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func reduceToOnlyStillAtRisk(risksByCategory map[string][]*types.Risk) []string {
	categories := make(map[string]struct{}) // Go's trick of unique elements is a map
	for categoryId, risks := range risksByCategory {
		for _, risk := range risks {
			if !risk.RiskStatus.IsStillAtRisk() {
				continue
			}
			categories[categoryId] = struct{}{}
		}
	}
	// return as slice (of now unique values)
	return keysAsSlice(categories)
}

func keysAsSlice(categories map[string]struct{}) []string {
	return slices.Sorted(maps.Keys(categories))
}

func sortedKeysOfSecurityRequirements(parsedModel *types.Model) []string {
	return slices.Sorted(maps.Keys(parsedModel.SecurityRequirements))
}

func sortedKeysOfAbuseCases(parsedModel *types.Model) []string {
	return slices.Sorted(maps.Keys(parsedModel.AbuseCases))
}

func sortedSharedRuntimesByTitle(parsedModel *types.Model) []*types.SharedRuntime {
	result := sortedValues(parsedModel.SharedRuntimes)
	sort.Stable(bySharedRuntimeTitleSort(result))
	return result
}

type bySharedRuntimeTitleSort []*types.SharedRuntime

func (what bySharedRuntimeTitleSort) Len() int      { return len(what) }
func (what bySharedRuntimeTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what bySharedRuntimeTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}

func sortedTechnicalAssetsByTitle(parsedModel *types.Model) []*types.TechnicalAsset {
	assets := sortedValues(parsedModel.TechnicalAssets)
	sort.Stable(types.ByTechnicalAssetTitleSort(assets))
	return assets
}

func sortByDataBreachProbability(risks []*types.Risk) {
	sort.Slice(risks, func(i, j int) bool {
		if risks[i].DataBreachProbability == risks[j].DataBreachProbability {
			trackingStatusLeft := risks[i].RiskStatus
			trackingStatusRight := risks[j].RiskStatus
			if trackingStatusLeft == trackingStatusRight {
				return risks[i].Title < risks[j].Title
			}
			return trackingStatusLeft < trackingStatusRight
		}
		return risks[i].DataBreachProbability > risks[j].DataBreachProbability
	})
}

func identifiedDataBreachProbabilityRisksStillAtRisk(parsedModel *types.Model,
	dataAsset *types.DataAsset,
) []*types.Risk {
	result := make([]*types.Risk, 0)
	for _, risk := range filteredByStillAtRisk(parsedModel) {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsProcessed, dataAsset.Id) {
				result = append(result, risk)
				break
			}
		}
	}
	return result
}

func isDataBreachPotentialStillAtRisk(parsedModel *types.Model, dataAsset *types.DataAsset) bool {
	for _, risk := range filteredByStillAtRisk(parsedModel) {
		for _, techAsset := range risk.DataBreachTechnicalAssetIDs {
			if contains(parsedModel.TechnicalAssets[techAsset].DataAssetsProcessed, dataAsset.Id) {
				return true
			}
		}
	}
	return false
}

func questionsUnanswered(parsedModel *types.Model) int {
	result := 0
	for _, answer := range parsedModel.Questions {
		if len(strings.TrimSpace(answer)) == 0 {
			result++
		}
	}
	return result
}

func titleOfSeverity(severity types.RiskSeverity) string {
	switch severity {
	case types.CriticalSeverity:
		return "Critical Risk Severity"
	case types.HighSeverity:
		return "High Risk Severity"
	case types.ElevatedSeverity:
		return "Elevated Risk Severity"
	case types.MediumSeverity:
		return "Medium Risk Severity"
	case types.LowSeverity:
		return "Low Risk Severity"
	default:
		return ""
	}
}

func riskSuffix(remainingRisks int, totalRisks int) string {
	suffix := ""
	if remainingRisks > 0 {
		suffix = strconv.Itoa(remainingRisks) + "/" + strconv.Itoa(totalRisks) + " unmitigated Risk"
	} else {
		suffix = strconv.Itoa(totalRisks) + " mitigated Risk"
	}
	if totalRisks != 1 {
		suffix += "s"
	}

	return suffix
}

func sortedTrustBoundariesByTitle(parsedModel *types.Model) []*types.TrustBoundary {
	boundaries := sortedValues(parsedModel.TrustBoundaries)
	sort.Stable(byTrustBoundaryTitleSort(boundaries))
	return boundaries
}

type byTrustBoundaryTitleSort []*types.TrustBoundary

func (what byTrustBoundaryTitleSort) Len() int      { return len(what) }
func (what byTrustBoundaryTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what byTrustBoundaryTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}

func sortedDataAssetsByTitle(parsedModel *types.Model) []*types.DataAsset {
	assets := sortedValues(parsedModel.DataAssets)
	sort.Stable(types.ByDataAssetTitleSort(assets))
	return assets
}

// sortedValues returns the values of a map in the order of their keys, so that sorting them by
// title afterwards with a stable sort keeps assets of the same title in a reproducible order.
func sortedValues[V any](values map[string]V) []V {
	result := make([]V, 0, len(values))
	for _, key := range slices.Sorted(maps.Keys(values)) {
		result = append(result, values[key])
	}
	return result
}
