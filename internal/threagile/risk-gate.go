package threagile

import (
	"errors"
	"fmt"

	"github.com/Pinguladora/threagile/pkg/types"
)

// riskGateExitCode is the exit status when the risk gate fails, distinct from
// the status 1 of any other error so that CI can tell the two apart.
const riskGateExitCode = 2

// riskGateError reports the risks that failed the --fail-on gate.
type riskGateError struct {
	threshold types.RiskSeverity
	risks     []*types.Risk
}

func (e *riskGateError) Error() string {
	return fmt.Sprintf("%d unchecked risk(s) of severity %v or higher", len(e.risks), e.threshold)
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
// positives have been looked at and do not fail the gate.
func checkRiskGate(parsedModel *types.Model, threshold types.RiskSeverity) error {
	failed := make([]*types.Risk, 0)
	for _, risk := range parsedModel.AllRisks() {
		if risk.Severity >= threshold && parsedModel.GetRiskTrackingWithDefault(risk).Status == types.Unchecked {
			failed = append(failed, risk)
		}
	}

	if len(failed) == 0 {
		return nil
	}

	return &riskGateError{threshold: threshold, risks: failed}
}

// riskGateFailure returns the gate error wrapped in err, if any.
func riskGateFailure(err error) (*riskGateError, bool) {
	var gateError *riskGateError
	ok := errors.As(err, &gateError)

	return gateError, ok
}
