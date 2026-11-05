package threagile

import (
	"errors"
	"fmt"

	"github.com/Pinguladora/threagile/pkg/baseline"
	"github.com/Pinguladora/threagile/pkg/types"
)

// riskGateExitCode is the exit status when the risk gate fails, distinct from
// the status 1 of any other error so that CI can tell the two apart.
const riskGateExitCode = 2

// riskGateError reports the risks that failed the --fail-on gate.
type riskGateError struct {
	threshold     types.RiskSeverity
	risks         []*types.Risk
	sinceBaseline bool
}

func (e *riskGateError) Error() string {
	return fmt.Sprintf("%d %v risk(s) of severity %v or higher", len(e.risks), e.kind(), e.threshold)
}

// kind is what the failing risks are: unchecked ones, and new or escalated ones when compared with a baseline.
func (e *riskGateError) kind() string {
	if e.sinceBaseline {
		return "new or escalated unchecked"
	}
	return "unchecked"
}

// parseRiskGate returns the severity threshold of the --fail-on gate, and false
// when the gate is off.
func parseRiskGate(failOn string) (types.RiskSeverity, bool, error) {
	if failOn == "" {
		return 0, false, nil
	}

	threshold, err := types.ParseRiskSeverity(failOn)
	if err != nil {
		return 0, false, fmt.Errorf("invalid --%s value: %w", failOnFlagName, err)
	}

	return threshold, true, nil
}

// checkRiskGate fails when a risk of the threshold severity or higher is still
// unchecked, that is it has no risk tracking entry or one with status unchecked.
// Risks that are in discussion, accepted, in progress, mitigated or false
// positives have been looked at and do not fail the gate. Compared with a
// baseline, only the risks that were not at the threshold in the baseline fail
// it: the new ones and those whose severity rose to it.
func checkRiskGate(parsedModel *types.Model, threshold types.RiskSeverity, comparison *baseline.Comparison) error {
	failed := make([]*types.Risk, 0)
	for _, risk := range parsedModel.AllRisks() {
		if risk.Severity < threshold || parsedModel.GetRiskTrackingWithDefault(risk).Status != types.Unchecked {
			continue
		}
		if comparison != nil {
			if previous, known := comparison.Previous(risk.SyntheticId); known && previous >= threshold {
				continue
			}
		}
		failed = append(failed, risk)
	}

	if len(failed) == 0 {
		return nil
	}

	return &riskGateError{threshold: threshold, risks: failed, sinceBaseline: comparison != nil}
}

// riskGateFailure returns the gate error wrapped in err, if any.
func riskGateFailure(err error) (*riskGateError, bool) {
	var gateError *riskGateError
	ok := errors.As(err, &gateError)

	return gateError, ok
}
