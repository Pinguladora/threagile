package report

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Pinguladora/threagile/pkg/interchange"
	"github.com/Pinguladora/threagile/pkg/otm"
	"github.com/Pinguladora/threagile/pkg/types"
)

// riskJSON is a risk as risks.json writes it: the risk's own fields, followed by the details that
// the risks.xlsx columns show as well. The details only ever get added to, never renamed or
// removed, so that existing consumers of the file keep working.
type riskJSON struct {
	*types.Risk

	PlainTitle                         string             `json:"plain_title"`
	CategoryTitle                      string             `json:"category_title"`
	STRIDE                             types.STRIDE       `json:"stride"`
	Function                           types.RiskFunction `json:"function"`
	CWE                                int                `json:"cwe"`
	Action                             string             `json:"action"`
	Mitigation                         string             `json:"mitigation"`
	Check                              string             `json:"check"`
	MostRelevantTechnicalAssetTitle    string             `json:"most_relevant_technical_asset_title,omitempty"`
	MostRelevantTechnicalAssetRAA      *float64           `json:"most_relevant_technical_asset_raa,omitempty"`
	MostRelevantCommunicationLinkTitle string             `json:"most_relevant_communication_link_title,omitempty"`
	TrackingJustification              string             `json:"tracking_justification,omitempty"`
	TrackingTicket                     string             `json:"tracking_ticket,omitempty"`
	TrackingDate                       string             `json:"tracking_date,omitempty"`
	TrackingCheckedBy                  string             `json:"tracking_checked_by,omitempty"`
}

func newRiskJSON(parsedModel *types.Model, risk *types.Risk) riskJSON {
	details := newRiskDetails(parsedModel, parsedModel.GetRiskCategory(risk.CategoryId), risk)
	result := riskJSON{
		Risk:                               risk,
		PlainTitle:                         removeFormattingTags(risk.Title),
		CategoryTitle:                      details.category.Title,
		STRIDE:                             details.category.STRIDE,
		Function:                           details.category.Function,
		CWE:                                details.category.CWE,
		Action:                             details.category.Action,
		Mitigation:                         details.category.Mitigation,
		Check:                              details.category.Check,
		MostRelevantTechnicalAssetTitle:    details.technicalAssetTitle(),
		MostRelevantCommunicationLinkTitle: details.communicationLinkTitle(),
		TrackingJustification:              details.tracking.Justification,
		TrackingTicket:                     details.tracking.Ticket,
		TrackingDate:                       details.trackingDate(),
		TrackingCheckedBy:                  details.tracking.CheckedBy,
	}
	if details.technicalAsset != nil {
		raa := details.technicalAssetRAA()
		result.MostRelevantTechnicalAssetRAA = &raa
	}
	return result
}

// WriteRisksJSON writes all risks of the model, in category id order, as a JSON array.
func WriteRisksJSON(parsedModel *types.Model, filename string) error {
	allRisks := parsedModel.AllRisks()
	risks := make([]riskJSON, 0, len(allRisks))
	for _, risk := range allRisks {
		risks = append(risks, newRiskJSON(parsedModel, risk))
	}
	jsonBytes, err := json.Marshal(risks)
	if err != nil {
		return fmt.Errorf("failed to marshal risks to JSON: %w", err)
	}
	err = os.WriteFile(filename, jsonBytes, 0o600)
	if err != nil {
		return fmt.Errorf("failed to write risks to JSON file: %w", err)
	}
	return nil
}

// TODO: also a "data assets" json?

func WriteTechnicalAssetsJSON(parsedModel *types.Model, filename string) error {
	jsonBytes, err := json.Marshal(parsedModel.TechnicalAssets)
	if err != nil {
		return fmt.Errorf("failed to marshal technical assets to JSON: %w", err)
	}
	err = os.WriteFile(filename, jsonBytes, 0o600)
	if err != nil {
		return fmt.Errorf("failed to write technical assets to JSON file: %w", err)
	}
	return nil
}

func WriteStatsJSON(parsedModel *types.Model, filename string) error {
	jsonBytes, err := json.Marshal(overallRiskStatistics(parsedModel))
	if err != nil {
		return fmt.Errorf("failed to marshal stats to JSON: %w", err)
	}
	err = os.WriteFile(filename, jsonBytes, 0o600)
	if err != nil {
		return fmt.Errorf("failed to write stats to JSON file: %w", err)
	}
	return nil
}

// WriteOTMJSON writes the model, with the risk categories it found risks of as threats and each
// risk as a threat instance, as an Open Threat Model (OTM) document.
func WriteOTMJSON(parsedModel *types.Model, filename string) error {
	jsonBytes, err := json.Marshal(otm.FromInterchange(interchange.FromModel(parsedModel)))
	if err != nil {
		return fmt.Errorf("failed to marshal OTM to JSON: %w", err)
	}
	err = os.WriteFile(filename, jsonBytes, 0o600)
	if err != nil {
		return fmt.Errorf("failed to write OTM to JSON file: %w", err)
	}
	return nil
}

func overallRiskStatistics(parsedModel *types.Model) riskStatistics {
	result := riskStatistics{}
	result.Risks = make(map[string]map[string]int)
	result.Risks[types.CriticalSeverity.String()] = make(map[string]int)
	result.Risks[types.CriticalSeverity.String()][types.Unchecked.String()] = 0
	result.Risks[types.CriticalSeverity.String()][types.InDiscussion.String()] = 0
	result.Risks[types.CriticalSeverity.String()][types.Accepted.String()] = 0
	result.Risks[types.CriticalSeverity.String()][types.InProgress.String()] = 0
	result.Risks[types.CriticalSeverity.String()][types.Mitigated.String()] = 0
	result.Risks[types.CriticalSeverity.String()][types.FalsePositive.String()] = 0
	result.Risks[types.HighSeverity.String()] = make(map[string]int)
	result.Risks[types.HighSeverity.String()][types.Unchecked.String()] = 0
	result.Risks[types.HighSeverity.String()][types.InDiscussion.String()] = 0
	result.Risks[types.HighSeverity.String()][types.Accepted.String()] = 0
	result.Risks[types.HighSeverity.String()][types.InProgress.String()] = 0
	result.Risks[types.HighSeverity.String()][types.Mitigated.String()] = 0
	result.Risks[types.HighSeverity.String()][types.FalsePositive.String()] = 0
	result.Risks[types.ElevatedSeverity.String()] = make(map[string]int)
	result.Risks[types.ElevatedSeverity.String()][types.Unchecked.String()] = 0
	result.Risks[types.ElevatedSeverity.String()][types.InDiscussion.String()] = 0
	result.Risks[types.ElevatedSeverity.String()][types.Accepted.String()] = 0
	result.Risks[types.ElevatedSeverity.String()][types.InProgress.String()] = 0
	result.Risks[types.ElevatedSeverity.String()][types.Mitigated.String()] = 0
	result.Risks[types.ElevatedSeverity.String()][types.FalsePositive.String()] = 0
	result.Risks[types.MediumSeverity.String()] = make(map[string]int)
	result.Risks[types.MediumSeverity.String()][types.Unchecked.String()] = 0
	result.Risks[types.MediumSeverity.String()][types.InDiscussion.String()] = 0
	result.Risks[types.MediumSeverity.String()][types.Accepted.String()] = 0
	result.Risks[types.MediumSeverity.String()][types.InProgress.String()] = 0
	result.Risks[types.MediumSeverity.String()][types.Mitigated.String()] = 0
	result.Risks[types.MediumSeverity.String()][types.FalsePositive.String()] = 0
	result.Risks[types.LowSeverity.String()] = make(map[string]int)
	result.Risks[types.LowSeverity.String()][types.Unchecked.String()] = 0
	result.Risks[types.LowSeverity.String()][types.InDiscussion.String()] = 0
	result.Risks[types.LowSeverity.String()][types.Accepted.String()] = 0
	result.Risks[types.LowSeverity.String()][types.InProgress.String()] = 0
	result.Risks[types.LowSeverity.String()][types.Mitigated.String()] = 0
	result.Risks[types.LowSeverity.String()][types.FalsePositive.String()] = 0
	for _, risks := range parsedModel.GeneratedRisksByCategory {
		for _, risk := range risks {
			result.Risks[risk.Severity.String()][risk.RiskStatus.String()]++
		}
	}
	return result
}

type riskStatistics struct {
	// TODO add also some more like before / after (i.e. with mitigation applied)
	Risks map[string]map[string]int `json:"risks" yaml:"risks"`
}
