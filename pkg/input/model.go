/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package input

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v4"
)

// === Model Type Stuff ======================================

// Model is the model as written in the YAML input. It is kept apart from types.Model, which the parsed
// model would otherwise be read into directly, because it gives better error messages for model errors.
type Model struct {
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

	// IndividualRiskCategories is the deprecated map of custom risk categories keyed by title that
	// CustomRiskCategories replaced; see ConvertIndividualRiskCategories.
	IndividualRiskCategories map[string]RiskCategory `json:"individual_risk_categories,omitempty" yaml:"individual_risk_categories,omitempty"`
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
		return fmt.Errorf("unable to read model file: %w", readError)
	}

	unmarshalError := yaml.Unmarshal(modelYaml, &model)
	if unmarshalError != nil {
		return fmt.Errorf("unable to parse model yaml: %w", unmarshalError)
	}

	for _, includeFile := range model.Includes {
		mergeError := model.Merge(filepath.Dir(inputFilename), includeFile)
		if mergeError != nil {
			return fmt.Errorf("unable to merge model include %q: %w", includeFile, mergeError)
		}
	}

	return nil
}

// Merge reads the model file includeFilename, relative to dir unless it is an absolute path, and
// merges it (and the files it includes in turn, relative to its own folder) into model.
func (model *Model) Merge(dir string, includeFilename string) error {
	includePath := includeFilename
	if !filepath.IsAbs(includePath) {
		includePath = filepath.Join(dir, includePath)
	}

	modelYaml, readError := os.ReadFile(filepath.Clean(includePath))
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

	// the sections of the file itself first, in a fixed order, then the files it includes
	for _, item := range slices.Sorted(maps.Keys(fileStructure)) {
		mergeSection, ok := modelSectionMergers[strings.ToLower(item)]
		if !ok {
			continue
		}

		mergeError := mergeSection(model, &includedModel)
		if mergeError != nil {
			return mergeError
		}
	}

	return model.mergeIncludes(filepath.Dir(includePath), includedModel.Includes)
}

// mergeIncludes merges the model files that an included model file includes in turn, relative to dir.
func (model *Model) mergeIncludes(dir string, includes []string) error {
	for _, includeFile := range includes {
		mergeError := model.Merge(dir, includeFile)
		if mergeError != nil {
			return fmt.Errorf("failed to merge model include %q: %w", includeFile, mergeError)
		}
	}

	return nil
}

// modelSectionMergers merge a top-level section of an included model file into the model, keyed by the
// lower-cased section name. Merge handles the includes section itself.
var modelSectionMergers = map[string]func(model *Model, included *Model) error{
	"threagile_version": func(model *Model, included *Model) error {
		return mergeSingletons(singleton("threagile version", &model.ThreagileVersion, included.ThreagileVersion))
	},
	"title": func(model *Model, included *Model) error {
		return mergeSingletons(singleton("title", &model.Title, included.Title))
	},
	"author": func(model *Model, included *Model) error {
		return wrapMergeError("author", model.Author.Merge(included.Author))
	},
	"contributors": func(model *Model, included *Model) error {
		var mergeError error
		model.Contributors, mergeError = new(Author).MergeList(append(model.Contributors, included.Contributors...))
		return wrapMergeError("contributors", mergeError)
	},
	"date": func(model *Model, included *Model) error {
		return mergeSingletons(singleton("date", &model.Date, included.Date))
	},
	"application_description": func(model *Model, included *Model) error {
		return wrapMergeError("application description", model.AppDescription.Merge(included.AppDescription))
	},
	"business_overview": func(model *Model, included *Model) error {
		return wrapMergeError("business overview", model.BusinessOverview.Merge(included.BusinessOverview))
	},
	"technical_overview": func(model *Model, included *Model) error {
		return wrapMergeError("technical overview", model.TechnicalOverview.Merge(included.TechnicalOverview))
	},
	"business_criticality": func(model *Model, included *Model) error {
		return mergeSingletons(singleton("business criticality", &model.BusinessCriticality, included.BusinessCriticality))
	},
	"management_summary_comment": func(model *Model, included *Model) error {
		model.ManagementSummaryComment = new(Strings).MergeMultiline(model.ManagementSummaryComment,
			included.ManagementSummaryComment)
		return nil
	},
	"security_requirements": func(model *Model, included *Model) error {
		var mergeError error
		model.SecurityRequirements, mergeError = new(Strings).MergeMap(model.SecurityRequirements,
			included.SecurityRequirements)
		return wrapMergeError("security requirements", mergeError)
	},
	"questions": func(model *Model, included *Model) error {
		var mergeError error
		model.Questions, mergeError = new(Strings).MergeMap(model.Questions, included.Questions)
		return wrapMergeError("questions", mergeError)
	},
	"abuse_cases": func(model *Model, included *Model) error {
		var mergeError error
		model.AbuseCases, mergeError = new(Strings).MergeMap(model.AbuseCases, included.AbuseCases)
		return wrapMergeError("abuse cases", mergeError)
	},
	"tags_available": func(model *Model, included *Model) error {
		model.TagsAvailable = new(Strings).MergeUniqueSlice(model.TagsAvailable, included.TagsAvailable)
		return nil
	},
	"data_assets": func(model *Model, included *Model) error {
		var mergeError error
		model.DataAssets, mergeError = new(DataAsset).MergeMap(model.DataAssets, included.DataAssets)
		return wrapMergeError("data assets", mergeError)
	},
	"technical_assets": func(model *Model, included *Model) error {
		var mergeError error
		model.TechnicalAssets, mergeError = new(TechnicalAsset).MergeMap(model.TechnicalAssets, included.TechnicalAssets)
		return wrapMergeError("technical assets", mergeError)
	},
	"trust_boundaries": func(model *Model, included *Model) error {
		var mergeError error
		model.TrustBoundaries, mergeError = new(TrustBoundary).MergeMap(model.TrustBoundaries, included.TrustBoundaries)
		return wrapMergeError("trust boundaries", mergeError)
	},
	"shared_runtimes": func(model *Model, included *Model) error {
		var mergeError error
		model.SharedRuntimes, mergeError = new(SharedRuntime).MergeMap(model.SharedRuntimes, included.SharedRuntimes)
		return wrapMergeError("shared runtimes", mergeError)
	},
	"custom_risk_categories": func(model *Model, included *Model) error {
		return wrapMergeError("risk categories", model.CustomRiskCategories.Add(included.CustomRiskCategories...))
	},
	"individual_risk_categories": func(model *Model, included *Model) error {
		var mergeError error
		model.IndividualRiskCategories, mergeError = new(RiskCategory).MergeMap(model.IndividualRiskCategories,
			included.IndividualRiskCategories)
		return wrapMergeError("individual risk categories", mergeError)
	},
	"risk_tracking": func(model *Model, included *Model) error {
		var mergeError error
		model.RiskTracking, mergeError = new(RiskTracking).MergeMap(model.RiskTracking, included.RiskTracking)
		return wrapMergeError("risk tracking", mergeError)
	},
	"diagram_tweak_nodesep": func(model *Model, included *Model) error {
		model.DiagramTweakNodesep = included.DiagramTweakNodesep
		return nil
	},
	"diagram_tweak_ranksep": func(model *Model, included *Model) error {
		model.DiagramTweakRanksep = included.DiagramTweakRanksep
		return nil
	},
	"diagram_tweak_edge_layout": func(model *Model, included *Model) error {
		model.DiagramTweakEdgeLayout = included.DiagramTweakEdgeLayout
		return nil
	},
	"diagram_tweak_suppress_edge_labels": func(model *Model, included *Model) error {
		model.DiagramTweakSuppressEdgeLabels = included.DiagramTweakSuppressEdgeLabels
		return nil
	},
	"diagram_tweak_layout_left_to_right": func(model *Model, included *Model) error {
		model.DiagramTweakLayoutLeftToRight = included.DiagramTweakLayoutLeftToRight
		return nil
	},
	"diagram_tweak_invisible_connections_between_assets": func(model *Model, included *Model) error {
		merged := slices.Concat(model.DiagramTweakInvisibleConnectionsBetweenAssets,
			included.DiagramTweakInvisibleConnectionsBetweenAssets)
		slices.Sort(merged)
		model.DiagramTweakInvisibleConnectionsBetweenAssets = slices.Compact(merged)
		return nil
	},
	"diagram_tweak_same_rank_assets": func(model *Model, included *Model) error {
		merged := slices.Concat(model.DiagramTweakSameRankAssets, included.DiagramTweakSameRankAssets)
		slices.Sort(merged)
		model.DiagramTweakSameRankAssets = slices.Compact(merged)
		return nil
	},
}

// wrapMergeError adds the merged section to a merge error; it returns nil for no error.
func wrapMergeError(section string, mergeError error) error {
	if mergeError != nil {
		return fmt.Errorf("failed to merge %s: %w", section, mergeError)
	}

	return nil
}

// ConvertIndividualRiskCategories moves the risk categories of the deprecated
// individual_risk_categories map into CustomRiskCategories, in title order, so that models written
// before the rename keep their custom risks (threagile#130). A category without a title gets its
// map key as title. It returns how many categories it moved.
func (model *Model) ConvertIndividualRiskCategories() (int, error) {
	titles := slices.Sorted(maps.Keys(model.IndividualRiskCategories))
	for _, title := range titles {
		category := model.IndividualRiskCategories[title]
		if category.Title == "" {
			category.Title = title
		}

		addError := model.CustomRiskCategories.Add(&category)
		if addError != nil {
			return 0, fmt.Errorf("failed to convert individual risk category %q: %w", title, addError)
		}
	}

	model.IndividualRiskCategories = nil

	return len(titles), nil
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
