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
	var mergeError error
	what.ID, mergeError = new(Strings).MergeSingleton(what.ID, other.ID)
	if mergeError != nil {
		return fmt.Errorf("failed to merge id: %w", mergeError)
	}

	what.Description, mergeError = new(Strings).MergeSingleton(what.Description, other.Description)
	if mergeError != nil {
		return fmt.Errorf("failed to merge description: %w", mergeError)
	}

	what.Impact, mergeError = new(Strings).MergeSingleton(what.Impact, other.Impact)
	if mergeError != nil {
		return fmt.Errorf("failed to merge impact: %w", mergeError)
	}

	what.ASVS, mergeError = new(Strings).MergeSingleton(what.ASVS, other.ASVS)
	if mergeError != nil {
		return fmt.Errorf("failed to merge asvs: %w", mergeError)
	}

	what.CheatSheet, mergeError = new(Strings).MergeSingleton(what.CheatSheet, other.CheatSheet)
	if mergeError != nil {
		return fmt.Errorf("failed to merge cheat_sheet: %w", mergeError)
	}

	what.Action, mergeError = new(Strings).MergeSingleton(what.Action, other.Action)
	if mergeError != nil {
		return fmt.Errorf("failed to merge action: %w", mergeError)
	}

	what.Mitigation, mergeError = new(Strings).MergeSingleton(what.Mitigation, other.Mitigation)
	if mergeError != nil {
		return fmt.Errorf("failed to merge mitigation: %w", mergeError)
	}

	what.Check, mergeError = new(Strings).MergeSingleton(what.Check, other.Check)
	if mergeError != nil {
		return fmt.Errorf("failed to merge check: %w", mergeError)
	}

	what.Function, mergeError = new(Strings).MergeSingleton(what.Function, other.Function)
	if mergeError != nil {
		return fmt.Errorf("failed to merge function: %w", mergeError)
	}

	what.STRIDE, mergeError = new(Strings).MergeSingleton(what.STRIDE, other.STRIDE)
	if mergeError != nil {
		return fmt.Errorf("failed to merge STRIDE: %w", mergeError)
	}

	what.DetectionLogic, mergeError = new(Strings).MergeSingleton(what.DetectionLogic, other.DetectionLogic)
	if mergeError != nil {
		return fmt.Errorf("failed to merge detection_logic: %w", mergeError)
	}

	what.RiskAssessment, mergeError = new(Strings).MergeSingleton(what.RiskAssessment, other.RiskAssessment)
	if mergeError != nil {
		return fmt.Errorf("failed to merge risk_assessment: %w", mergeError)
	}

	what.FalsePositives, mergeError = new(Strings).MergeSingleton(what.FalsePositives, other.FalsePositives)
	if mergeError != nil {
		return fmt.Errorf("failed to merge false_positives: %w", mergeError)
	}

	if !what.ModelFailurePossibleReason {
		what.ModelFailurePossibleReason = other.ModelFailurePossibleReason
	}

	if what.CWE == 0 {
		what.CWE = other.CWE
	}

	what.RisksIdentified, mergeError = new(RiskIdentified).MergeMap(what.RisksIdentified, other.RisksIdentified)
	if mergeError != nil {
		return fmt.Errorf("failed to merge identified risks: %w", mergeError)
	}

	return nil
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
