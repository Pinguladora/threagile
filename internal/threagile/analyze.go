package threagile

import (
	"fmt"

	"github.com/Pinguladora/threagile/pkg/baseline"
	"github.com/Pinguladora/threagile/pkg/model"
	"github.com/Pinguladora/threagile/pkg/report"
	"github.com/Pinguladora/threagile/pkg/risks"
	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/spf13/cobra"
)

func (what *Threagile) initAnalyze() *Threagile {
	analyze := &cobra.Command{
		Use:     AnalyzeModelCommand,
		Short:   "Analyze model",
		Aliases: []string{"analyze", "analyse", "run", "analyse-model"},
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			commands := what.readCommands()
			progressReporter := DefaultProgressReporter{Verbose: what.config.GetVerbose()}

			// Validate the gate before the analysis, so a typo fails fast.
			threshold, gateEnabled, err := parseRiskGate(what.config.GetFailOn())
			if err != nil {
				return err
			}

			// Read the baseline first too: it may well be the risks json that this analysis overwrites.
			baselineRisks, err := loadBaseline(what.config.GetBaseline())
			if err != nil {
				return err
			}

			r, err := model.ReadAndAnalyzeModel(what.config, risks.GetBuiltInRiskRules(), progressReporter)
			if err != nil {
				return fmt.Errorf("failed to read and analyze model: %w", err)
			}
			if baselineRisks != nil {
				r.Baseline = baseline.Compare(what.config.GetBaseline(), baselineRisks, r.ParsedModel.AllRisks())
			}

			err = report.Generate(what.config, r, commands, risks.GetBuiltInRiskRules(), progressReporter)
			if err != nil {
				return fmt.Errorf("failed to generate reports: %w", err)
			}

			if r.Baseline != nil {
				printBaselineComparison(cmd, r.Baseline)
			}

			// The gate runs after the reports are written, so they are there to look at.
			if !gateEnabled {
				return nil
			}
			return runRiskGate(cmd, r.ParsedModel, threshold, r.Baseline)
		},
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	what.rootCmd.AddCommand(analyze)

	return what
}

// printBaselineComparison prints how the risks differ from those of the baseline: the counts, then the new and the
// escalated risks.
func printBaselineComparison(cmd *cobra.Command, comparison *baseline.Comparison) {
	cmd.Printf("Compared with the baseline %v: %d new, %d resolved, %d escalated, %d de-escalated, %d unchanged risk(s)\n",
		comparison.Filename, len(comparison.New), len(comparison.Resolved), len(comparison.Escalated),
		len(comparison.Deescalated), comparison.Unchanged)
	for _, risk := range comparison.New {
		cmd.Printf("  new        %-8v %v\n", risk.Severity, risk.SyntheticId)
	}
	for _, change := range comparison.Escalated {
		cmd.Printf("  escalated  %-8v %v (was %v)\n", change.Risk.Severity, change.Risk.SyntheticId, change.Previous)
	}
}

// loadBaseline reads the risks of the baseline, if there is one: nil when the filename is empty.
func loadBaseline(filename string) ([]baseline.Risk, error) {
	if filename == "" {
		return nil, nil
	}
	return baseline.Load(filename)
}

// runRiskGate checks the risk gate and, when it fails, lists the risks that failed it.
func runRiskGate(
	cmd *cobra.Command, parsedModel *types.Model, threshold types.RiskSeverity, comparison *baseline.Comparison,
) error {
	gateErr := checkRiskGate(parsedModel, threshold, comparison)
	if gateError, failed := riskGateFailure(gateErr); failed {
		cmd.Printf("Risk gate failed, %v risks of severity %v or higher:\n", gateError.kind(), threshold)
		for _, risk := range gateError.risks {
			cmd.Printf("  %-8v %v\n", risk.Severity, risk.SyntheticId)
		}
	}
	return gateErr
}
