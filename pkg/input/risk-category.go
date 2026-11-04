package input

import (
	"fmt"
	"strings"
)

type RiskCategory struct {
	ID                         string                    `json:"id,omitempty"                            yaml:"id,omitempty"`
	Title                      string                    `json:"title,omitempty"                         yaml:"title,omitempty"`
	Description                string                    `json:"description,omitempty"                   yaml:"description,omitempty"`
	Impact                     string                    `json:"impact,omitempty"                        yaml:"impact,omitempty"`
	ASVS                       string                    `json:"asvs,omitempty"                          yaml:"asvs,omitempty"`
	CheatSheet                 string                    `json:"cheat_sheet,omitempty"                   yaml:"cheat_sheet,omitempty"`
	Action                     string                    `json:"action,omitempty"                        yaml:"action,omitempty"`
	Mitigation                 string                    `json:"mitigation,omitempty"                    yaml:"mitigation,omitempty"`
	Check                      string                    `json:"check,omitempty"                         yaml:"check,omitempty"`
	Function                   string                    `json:"function,omitempty"                      yaml:"function,omitempty"`
	STRIDE                     string                    `json:"stride,omitempty"                        yaml:"stride,omitempty"`
	DetectionLogic             string                    `json:"detection_logic,omitempty"               yaml:"detection_logic,omitempty"`
	RiskAssessment             string                    `json:"risk_assessment,omitempty"               yaml:"risk_assessment,omitempty"`
	FalsePositives             string                    `json:"false_positives,omitempty"               yaml:"false_positives,omitempty"`
	ModelFailurePossibleReason bool                      `json:"model_failure_possible_reason,omitempty" yaml:"model_failure_possible_reason,omitempty"`
	CWE                        int                       `json:"cwe,omitempty"                           yaml:"cwe,omitempty"`
	RisksIdentified            map[string]RiskIdentified `json:"risks_identified,omitempty"              yaml:"risks_identified,omitempty"`
}

type RiskCategories []*RiskCategory

func (what *RiskCategory) Merge(other RiskCategory) error {
	mergeError := mergeSingletons(
		singleton("id", &what.ID, other.ID),
		singleton("title", &what.Title, other.Title),
		singleton("description", &what.Description, other.Description),
		singleton("impact", &what.Impact, other.Impact),
		singleton("asvs", &what.ASVS, other.ASVS),
		singleton("cheat_sheet", &what.CheatSheet, other.CheatSheet),
		singleton("action", &what.Action, other.Action),
		singleton("mitigation", &what.Mitigation, other.Mitigation),
		singleton("check", &what.Check, other.Check),
		singleton("function", &what.Function, other.Function),
		singleton("STRIDE", &what.STRIDE, other.STRIDE),
		singleton("detection_logic", &what.DetectionLogic, other.DetectionLogic),
		singleton("risk_assessment", &what.RiskAssessment, other.RiskAssessment),
		singleton("false_positives", &what.FalsePositives, other.FalsePositives),
	)
	if mergeError != nil {
		return mergeError
	}

	mergeFlag(&what.ModelFailurePossibleReason, other.ModelFailurePossibleReason)

	if what.CWE == 0 {
		what.CWE = other.CWE
	}

	what.RisksIdentified, mergeError = new(RiskIdentified).MergeMap(what.RisksIdentified, other.RisksIdentified)
	if mergeError != nil {
		return fmt.Errorf("failed to merge identified risks: %w", mergeError)
	}

	return nil
}

func (what *RiskCategory) MergeMap(first, second map[string]RiskCategory) (map[string]RiskCategory, error) {
	if first == nil {
		// first is nil for a section that is missing, or a key left without a value, in the model merged into
		first = make(map[string]RiskCategory, len(second))
	}

	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			mergeError := mapItem.Merge(mapValue)
			if mergeError != nil {
				return first, fmt.Errorf("failed to merge risk category %q: %w", mapKey, mergeError)
			}

			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}

	return first, nil
}

func (what *RiskCategories) Add(items ...*RiskCategory) error {
	for _, item := range items {
		for _, value := range *what {
			if strings.EqualFold(value.ID, item.ID) {
				return fmt.Errorf("duplicate item %q in risk category list", value.ID)
			}
		}

		*what = append(*what, item)
	}

	return nil
}
