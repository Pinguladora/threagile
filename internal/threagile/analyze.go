package threagile

import (
	"fmt"

	"github.com/Pinguladora/threagile/pkg/model"
	"github.com/Pinguladora/threagile/pkg/report"
	"github.com/Pinguladora/threagile/pkg/risks"
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

			r, err := model.ReadAndAnalyzeModel(what.config, risks.GetBuiltInRiskRules(), progressReporter)
			if err != nil {
				return fmt.Errorf("failed to read and analyze model: %w", err)
			}

			err = report.Generate(what.config, r, commands, risks.GetBuiltInRiskRules(), progressReporter)
			if err != nil {
				return fmt.Errorf("failed to generate reports: %w", err)
			}

			// The gate runs after the reports are written, so they are there to look at.
			if !gateEnabled {
				return nil
			}

			gateErr := checkRiskGate(r.ParsedModel, threshold)
			if gateError, failed := riskGateFailure(gateErr); failed {
				cmd.Printf("Risk gate failed, unchecked risks of severity %v or higher:\n", threshold)
				for _, risk := range gateError.risks {
					cmd.Printf("  %-8v %v\n", risk.Severity, risk.SyntheticId)
				}
			}

			return gateErr
		},
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	what.rootCmd.AddCommand(analyze)

	return what
}
