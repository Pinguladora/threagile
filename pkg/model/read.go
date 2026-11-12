package model

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Pinguladora/threagile/pkg/baseline"
	"github.com/Pinguladora/threagile/pkg/input"
	"github.com/Pinguladora/threagile/pkg/types"
	"go.yaml.in/yaml/v4"
)

type ReadResult struct {
	ModelInput       *input.Model
	ParsedModel      *types.Model
	IntroTextRAA     string
	BuiltinRiskRules types.RiskRules
	CustomRiskRules  types.RiskRules
	// Baseline compares the risks with those of an earlier analysis; nil when there is none to compare with.
	Baseline *baseline.Comparison
}

type configReader interface {
	GetBuildTimestamp() string
	GetVerbose() bool
	GetInteractive() bool
	GetAppFolder() string
	GetPluginFolder() string
	GetDataFolder() string
	GetOutputFolder() string
	GetServerFolder() string
	GetTempFolder() string
	GetKeyFolder() string
	GetInputFile() string
	GetImportedInputFile() string
	GetDataFlowDiagramFilenamePNG() string
	GetDataAssetDiagramFilenamePNG() string
	GetDataFlowDiagramFilenameDOT() string
	GetDataAssetDiagramFilenameDOT() string
	GetReportFilename() string
	GetExcelRisksFilename() string
	GetExcelTagsFilename() string
	GetJsonRisksFilename() string
	GetJsonTechnicalAssetsFilename() string
	GetJsonStatsFilename() string
	GetTemplateFilename() string
	GetTechnologyFilename() string
	GetRiskRulePlugins() []string
	GetSkipRiskRules() []string
	GetExecuteModelMacro() string
	GetRiskExcelConfigHideColumns() []string
	GetRiskExcelConfigSortByColumns() []string
	GetRiskExcelConfigWidthOfColumns() map[string]float64
	GetServerMode() bool
	GetDiagramDPI() int
	GetServerPort() int
	GetGraphvizDPI() int
	GetMaxGraphvizDPI() int
	GetBackupHistoryFilesToKeep() int
	GetAddModelTitle() bool
	GetAddLegend() bool
	GetKeepDiagramSourceFiles() bool
	GetIgnoreOrphanedRiskTracking() bool
	GetThreagileVersion() string
	GetProgressReporter() types.ProgressReporter
}

func ReadAndAnalyzeModel(
	config configReader, builtinRiskRules types.RiskRules, progressReporter types.ProgressReporter,
) (*ReadResult, error) {
	progressReporter.Infof("Writing into output directory: %v", config.GetOutputFolder())
	progressReporter.Infof("Parsing model: %v", config.GetInputFile())

	customRiskRules := LoadCustomRiskRules(config.GetPluginFolder(), config.GetRiskRulePlugins(), progressReporter)

	modelInput := new(input.Model).Defaults()
	loadError := modelInput.Load(config.GetInputFile())
	if loadError != nil {
		return nil, fmt.Errorf("unable to load model yaml: %w", loadError)
	}

	result, analysisError := AnalyzeModel(modelInput, config, builtinRiskRules, customRiskRules, progressReporter)
	if analysisError == nil {
		writeToFile("model yaml", result.ParsedModel, config.GetImportedInputFile(), progressReporter)
	}

	return result, analysisError
}

func AnalyzeModel(
	modelInput *input.Model, config configReader, builtinRiskRules types.RiskRules, customRiskRules types.RiskRules,
	progressReporter types.ProgressReporter,
) (*ReadResult, error) {
	converted, convertError := modelInput.ConvertIndividualRiskCategories()
	if convertError != nil {
		return nil, fmt.Errorf("unable to parse model yaml: %w", convertError)
	}
	if converted > 0 {
		progressReporter.Warnf("individual_risk_categories is deprecated, use custom_risk_categories instead: "+
			"a list of risk categories, each with its title in a title field (converted %d risk categories)", converted)
	}

	if converted := ConvertLegacyIdentities(modelInput); converted > 0 {
		progressReporter.Warnf("the authorization of %d communication links holds their identity (none, technical-user "+
			"or end-user-identity-propagation), as earlier versions of the model did: read it as their identity, "+
			"and their authorization as not modelled; set identity and authorization to remove this warning",
			converted)
	}

	parsedModel, parseError := ParseModel(config, modelInput, builtinRiskRules, customRiskRules)
	if parseError != nil {
		return nil, fmt.Errorf("unable to parse model yaml: %w", parseError)
	}

	introTextRAA := applyRAA(parsedModel, progressReporter)

	applyRiskGeneration(parsedModel, builtinRiskRules.Merge(customRiskRules), config.GetSkipRiskRules(), progressReporter)
	parsedModel.ApplyWildcardRiskTrackingEvaluation(progressReporter)
	err := parsedModel.CheckRiskTracking(config.GetIgnoreOrphanedRiskTracking(), progressReporter)
	if err != nil {
		return nil, fmt.Errorf("unable to check risk tracking: %w", err)
	}

	return &ReadResult{
		ModelInput:       modelInput,
		ParsedModel:      parsedModel,
		IntroTextRAA:     introTextRAA,
		BuiltinRiskRules: builtinRiskRules,
		CustomRiskRules:  customRiskRules,
	}, nil
}

func applyRiskGeneration(parsedModel *types.Model, rules types.RiskRules,
	skipRiskRules []string,
	progressReporter types.ProgressReporter,
) {
	progressReporter.Info("Applying risk generation")

	skippedRules := make(map[string]bool)
	if len(skipRiskRules) > 0 {
		for _, id := range skipRiskRules {
			skippedRules[id] = true
		}
	}

	for _, id := range slices.Sorted(maps.Keys(rules)) {
		rule := rules[id]
		_, ok := skippedRules[id]
		if ok {
			progressReporter.Infof("Skipping risk rule: %v", id)
			delete(skippedRules, id)
			continue
		}

		parsedModel.AddToListOfSupportedTags(rule.SupportedTags())
		newRisks, riskError := rule.GenerateRisks(parsedModel)
		if riskError != nil {
			progressReporter.Warnf("Error generating risks for %q: %v", id, riskError)
			continue
		}

		if len(newRisks) > 0 {
			// rules collect their risks while ranging over model maps; keep them in the order the reports use
			types.SortByRiskSeverity(newRisks)
			parsedModel.GeneratedRisksByCategory[id] = newRisks
		}
	}

	if len(skippedRules) > 0 {
		progressReporter.Infof("Unknown risk rules to skip: %v", slices.Sorted(maps.Keys(skippedRules)))
	}

	// save also in map keyed by synthetic risk-id
	for _, category := range parsedModel.SortedRiskCategories() {
		someRisks := parsedModel.SortedRisksOfCategory(category)
		for _, risk := range someRisks {
			parsedModel.GeneratedRisksBySyntheticId[strings.ToLower(risk.SyntheticId)] = risk
		}
	}
}

func writeToFile(name string, item any, filename string, progressReporter types.ProgressReporter) {
	if item == nil {
		return
	}

	if filename == "" {
		return
	}

	exported, exportError := yaml.Marshal(item)
	if exportError != nil {
		progressReporter.Warnf("Unable to export %v: %v", name, exportError)
		return
	}

	_ = os.MkdirAll(filepath.Dir(filename), 0o750)

	writeError := os.WriteFile(filename, exported, 0o600)
	if writeError != nil {
		progressReporter.Warnf("Unable to write %v to %q: %v", name, filename, writeError)
		return
	}

	progressReporter.Infof("Wrote %v to %q", name, filename)
}
