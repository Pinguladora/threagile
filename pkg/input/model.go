/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package input

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/mpvl/unique"
	"gopkg.in/yaml.v3"
)

// === Model Type Stuff ======================================

type Model struct { // TODO: Eventually remove this and directly use ParsedModelRoot? But then the error messages for model errors are not quite as good anymore...
	ThreagileVersion                              string                    `json:"threagile_version,omitempty"                                  yaml:"threagile_version,omitempty"`
	Includes                                      []string                  `json:"includes,omitempty"                                           yaml:"includes,omitempty"`
	Title                                         string                    `json:"title,omitempty"                                              yaml:"title,omitempty"`
	Author                                        Author                    `json:"author,omitempty"                                             yaml:"author,omitempty"`
	Contributors                                  []Author                  `json:"contributors,omitempty"                                       yaml:"contributors,omitempty"`
	Date                                          string                    `json:"date,omitempty"                                               yaml:"date,omitempty"`
	AppDescription                                Overview                  `json:"application_description,omitempty"                            yaml:"application_description,omitempty"`
	BusinessOverview                              Overview                  `json:"business_overview,omitempty"                                  yaml:"business_overview,omitempty"`
	TechnicalOverview                             Overview                  `json:"technical_overview,omitempty"                                 yaml:"technical_overview,omitempty"`
	BusinessCriticality                           string                    `json:"business_criticality,omitempty"                               yaml:"business_criticality,omitempty"`
	ManagementSummaryComment                      string                    `json:"management_summary_comment,omitempty"                         yaml:"management_summary_comment,omitempty"`
	SecurityRequirements                          map[string]string         `json:"security_requirements,omitempty"                              yaml:"security_requirements,omitempty"`
	Questions                                     map[string]string         `json:"questions,omitempty"                                          yaml:"questions,omitempty"`
	AbuseCases                                    map[string]string         `json:"abuse_cases,omitempty"                                        yaml:"abuse_cases,omitempty"`
	TagsAvailable                                 []string                  `json:"tags_available,omitempty"                                     yaml:"tags_available,omitempty"`
	DataAssets                                    map[string]DataAsset      `json:"data_assets,omitempty"                                        yaml:"data_assets,omitempty"`
	TechnicalAssets                               map[string]TechnicalAsset `json:"technical_assets,omitempty"                                   yaml:"technical_assets,omitempty"`
	TrustBoundaries                               map[string]TrustBoundary  `json:"trust_boundaries,omitempty"                                   yaml:"trust_boundaries,omitempty"`
	SharedRuntimes                                map[string]SharedRuntime  `json:"shared_runtimes,omitempty"                                    yaml:"shared_runtimes,omitempty"`
	CustomRiskCategories                          RiskCategories            `json:"custom_risk_categories,omitempty"                             yaml:"custom_risk_categories,omitempty"`
	RiskTracking                                  map[string]RiskTracking   `json:"risk_tracking,omitempty"                                      yaml:"risk_tracking,omitempty"`
	DiagramTweakNodesep                           int                       `json:"diagram_tweak_nodesep,omitempty"                              yaml:"diagram_tweak_nodesep,omitempty"`
	DiagramTweakRanksep                           int                       `json:"diagram_tweak_ranksep,omitempty"                              yaml:"diagram_tweak_ranksep,omitempty"`
	DiagramTweakEdgeLayout                        string                    `json:"diagram_tweak_edge_layout,omitempty"                          yaml:"diagram_tweak_edge_layout,omitempty"`
	DiagramTweakSuppressEdgeLabels                bool                      `json:"diagram_tweak_suppress_edge_labels,omitempty"                 yaml:"diagram_tweak_suppress_edge_labels,omitempty"`
	DiagramTweakLayoutLeftToRight                 bool                      `json:"diagram_tweak_layout_left_to_right,omitempty"                 yaml:"diagram_tweak_layout_left_to_right,omitempty"`
	DiagramTweakInvisibleConnectionsBetweenAssets []string                  `json:"diagram_tweak_invisible_connections_between_assets,omitempty" yaml:"diagram_tweak_invisible_connections_between_assets,omitempty"`
	DiagramTweakSameRankAssets                    []string                  `json:"diagram_tweak_same_rank_assets,omitempty"                     yaml:"diagram_tweak_same_rank_assets,omitempty"`
}

func (model *Model) Defaults() *Model {
	*model = Model{
		Questions:            make(map[string]string),
		AbuseCases:           make(map[string]string),
		SecurityRequirements: make(map[string]string),
		DataAssets:           make(map[string]DataAsset),
		TechnicalAssets:      make(map[string]TechnicalAsset),
		TrustBoundaries:      make(map[string]TrustBoundary),
		SharedRuntimes:       make(map[string]SharedRuntime),
		CustomRiskCategories: make(RiskCategories, 0),
		RiskTracking:         make(map[string]RiskTracking),
	}

	return model
}

func (model *Model) Load(inputFilename string) error {
	modelYaml, readError := os.ReadFile(filepath.Clean(inputFilename))
	if readError != nil {
		log.Fatal("Unable to read model file: ", readError)
	}

	unmarshalError := yaml.Unmarshal(modelYaml, &model)
	if unmarshalError != nil {
		log.Fatal("Unable to parse model yaml: ", unmarshalError)
	}

	for _, includeFile := range model.Includes {
		mergeError := model.Merge(filepath.Dir(inputFilename), includeFile)
		if mergeError != nil {
			log.Fatalf("Unable to merge model include %q: %v", includeFile, mergeError)
		}
	}

	return nil
}

func (model *Model) Merge(dir string, includeFilename string) error {
	modelYaml, readError := os.ReadFile(filepath.Clean(filepath.Join(dir, includeFilename)))
	if readError != nil {
		return fmt.Errorf("unable to read model file: %w", readError)
	}

	var fileStructure map[string]any
	unmarshalStructureError := yaml.Unmarshal(modelYaml, &fileStructure)
	if unmarshalStructureError != nil {
		return fmt.Errorf("unable to parse model structure: %w", unmarshalStructureError)
	}

	var includedModel Model
	unmarshalError := yaml.Unmarshal(modelYaml, &includedModel)
	if unmarshalError != nil {
		return fmt.Errorf("unable to parse model yaml: %w", unmarshalError)
	}

	var mergeError error
	for item := range fileStructure {
		switch strings.ToLower(item) {
		case strings.ToLower("includes"):
			for _, includeFile := range includedModel.Includes {
				mergeError = model.Merge(filepath.Join(dir, filepath.Dir(includeFilename)), includeFile)
				if mergeError != nil {
					return fmt.Errorf("failed to merge model include %q: %w", includeFile, mergeError)
				}
			}

		case strings.ToLower("threagile_version"):
			model.ThreagileVersion, mergeError = new(Strings).MergeSingleton(model.ThreagileVersion, includedModel.ThreagileVersion)
			if mergeError != nil {
				return fmt.Errorf("failed to merge threagile version: %w", mergeError)
			}

		case strings.ToLower("title"):
			model.Title, mergeError = new(Strings).MergeSingleton(model.Title, includedModel.Title)
			if mergeError != nil {
				return fmt.Errorf("failed to merge title: %w", mergeError)
			}

		case strings.ToLower("author"):
			mergeError = model.Author.Merge(includedModel.Author)
			if mergeError != nil {
				return fmt.Errorf("failed to merge author: %w", mergeError)
			}

		case strings.ToLower("contributors"):
			model.Contributors, mergeError = new(Author).MergeList(append(model.Contributors, includedModel.Author))
			if mergeError != nil {
				return fmt.Errorf("failed to merge contributors: %w", mergeError)
			}

		case strings.ToLower("date"):
			model.Date, mergeError = new(Strings).MergeSingleton(model.Date, includedModel.Date)
			if mergeError != nil {
				return fmt.Errorf("failed to merge date: %w", mergeError)
			}

		case strings.ToLower("application_description"):
			mergeError = model.AppDescription.Merge(includedModel.AppDescription)
			if mergeError != nil {
				return fmt.Errorf("failed to merge application description: %w", mergeError)
			}

		case strings.ToLower("business_overview"):
			mergeError = model.BusinessOverview.Merge(includedModel.BusinessOverview)
			if mergeError != nil {
				return fmt.Errorf("failed to merge business overview: %w", mergeError)
			}

		case strings.ToLower("technical_overview"):
			mergeError = model.TechnicalOverview.Merge(includedModel.TechnicalOverview)
			if mergeError != nil {
				return fmt.Errorf("failed to merge technical overview: %w", mergeError)
			}

		case strings.ToLower("business_criticality"):
			model.BusinessCriticality, mergeError = new(Strings).MergeSingleton(model.BusinessCriticality, includedModel.BusinessCriticality)
			if mergeError != nil {
				return fmt.Errorf("failed to merge business criticality: %w", mergeError)
			}

		case strings.ToLower("management_summary_comment"):
			model.ManagementSummaryComment = new(Strings).MergeMultiline(model.ManagementSummaryComment, includedModel.ManagementSummaryComment)

		case strings.ToLower("security_requirements"):
			model.SecurityRequirements, mergeError = new(Strings).MergeMap(model.SecurityRequirements, includedModel.SecurityRequirements)
			if mergeError != nil {
				return fmt.Errorf("failed to merge security requirements: %w", mergeError)
			}

		case strings.ToLower("questions"):
			model.Questions, mergeError = new(Strings).MergeMap(model.Questions, includedModel.Questions)
			if mergeError != nil {
				return fmt.Errorf("failed to merge questions: %w", mergeError)
			}

		case strings.ToLower("abuse_cases"):
			model.AbuseCases, mergeError = new(Strings).MergeMap(model.AbuseCases, includedModel.AbuseCases)
			if mergeError != nil {
				return fmt.Errorf("failed to merge abuse cases: %w", mergeError)
			}

		case strings.ToLower("tags_available"):
			model.TagsAvailable = new(Strings).MergeUniqueSlice(model.TagsAvailable, includedModel.TagsAvailable)

		case strings.ToLower("data_assets"):
			model.DataAssets, mergeError = new(DataAsset).MergeMap(model.DataAssets, includedModel.DataAssets)
			if mergeError != nil {
				return fmt.Errorf("failed to merge data assets: %w", mergeError)
			}

		case strings.ToLower("technical_assets"):
			model.TechnicalAssets, mergeError = new(TechnicalAsset).MergeMap(model.TechnicalAssets, includedModel.TechnicalAssets)
			if mergeError != nil {
				return fmt.Errorf("failed to merge technical assets: %w", mergeError)
			}

		case strings.ToLower("trust_boundaries"):
			model.TrustBoundaries, mergeError = new(TrustBoundary).MergeMap(model.TrustBoundaries, includedModel.TrustBoundaries)
			if mergeError != nil {
				return fmt.Errorf("failed to merge trust boundaries: %w", mergeError)
			}

		case strings.ToLower("shared_runtimes"):
			model.SharedRuntimes, mergeError = new(SharedRuntime).MergeMap(model.SharedRuntimes, includedModel.SharedRuntimes)
			if mergeError != nil {
				return fmt.Errorf("failed to merge shared runtimes: %w", mergeError)
			}

		case strings.ToLower("custom_risk_categories"):
			mergeError = model.CustomRiskCategories.Add(includedModel.CustomRiskCategories...)
			if mergeError != nil {
				return fmt.Errorf("failed to merge risk categories: %w", mergeError)
			}

		case strings.ToLower("risk_tracking"):
			model.RiskTracking, mergeError = new(RiskTracking).MergeMap(model.RiskTracking, includedModel.RiskTracking)
			if mergeError != nil {
				return fmt.Errorf("failed to merge risk tracking: %w", mergeError)
			}

		case "diagram_tweak_nodesep":
			model.DiagramTweakNodesep = includedModel.DiagramTweakNodesep

		case "diagram_tweak_ranksep":
			model.DiagramTweakRanksep = includedModel.DiagramTweakRanksep

		case "diagram_tweak_edge_layout":
			model.DiagramTweakEdgeLayout = includedModel.DiagramTweakEdgeLayout

		case "diagram_tweak_suppress_edge_labels":
			model.DiagramTweakSuppressEdgeLabels = includedModel.DiagramTweakSuppressEdgeLabels

		case "diagram_tweak_layout_left_to_right":
			model.DiagramTweakLayoutLeftToRight = includedModel.DiagramTweakLayoutLeftToRight

		case "diagram_tweak_invisible_connections_between_assets":
			model.DiagramTweakInvisibleConnectionsBetweenAssets = append(model.DiagramTweakInvisibleConnectionsBetweenAssets, includedModel.DiagramTweakInvisibleConnectionsBetweenAssets...)
			sort.Strings(model.DiagramTweakInvisibleConnectionsBetweenAssets)
			unique.Strings(&model.DiagramTweakInvisibleConnectionsBetweenAssets)

		case "diagram_tweak_same_rank_assets":
			model.DiagramTweakSameRankAssets = append(model.DiagramTweakSameRankAssets, includedModel.DiagramTweakSameRankAssets...)
			sort.Strings(model.DiagramTweakSameRankAssets)
			unique.Strings(&model.DiagramTweakSameRankAssets)
		}
	}

	return nil
}

func (model *Model) AddTagToModelInput(tag string, dryRun bool, changes *[]string) {
	tag = NormalizeTag(tag)

	if !slices.Contains(model.TagsAvailable, tag) {
		*changes = append(*changes, "adding tag: "+tag)
		if !dryRun {
			model.TagsAvailable = append(model.TagsAvailable, tag)
		}
	}
}

func NormalizeTag(tag string) string {
	return strings.TrimSpace(strings.ToLower(tag))
}
