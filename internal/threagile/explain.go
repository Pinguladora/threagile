package threagile

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/Pinguladora/threagile/pkg/macros"
	"github.com/Pinguladora/threagile/pkg/model"
	"github.com/Pinguladora/threagile/pkg/risks"
	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/spf13/cobra"
)

func (what *Threagile) initExplain() *Threagile {
	return what.initExplainNew()
}

func (what *Threagile) initExplainNew() *Threagile {
	explainCmd := &cobra.Command{
		Use:   ExplainCommand,
		Short: "Explain an item",
	}

	what.rootCmd.AddCommand(explainCmd)

	explainCmd.AddCommand(
		&cobra.Command{
			Use:        RiskItem,
			Short:      "Detailed explanation of why a risk was flagged",
			Args:       cobra.MinimumNArgs(1),
			ArgAliases: []string{"risk_id", "..."},
			RunE:       what.explainRisk,
		},
		&cobra.Command{
			Use:   RulesItem,
			Short: "Detailed explanation of all the risk rules",
			RunE:  what.explainRules,
		},
		&cobra.Command{
			Use:   MacrosItem,
			Short: "Explain model macros",
			Run:   what.explainMacros,
		},
		&cobra.Command{
			Use:   TypesItem,
			Short: "Print type information (enum values to be used in models)",
			Run:   what.explainTypes,
		})

	return what
}

func (what *Threagile) explainRisk(cmd *cobra.Command, args []string) error {
	what.processArgs(cmd, args)

	progressReporter := DefaultProgressReporter{Verbose: what.config.GetVerbose()}

	// the model is read and analyzed again, even if it is loaded already

	result, runError := model.ReadAndAnalyzeModel(what.config, risks.GetBuiltInRiskRules(), progressReporter)
	if runError != nil {
		cmd.Printf("Failed to read and analyze model: %v", runError)
		return fmt.Errorf("failed to read and analyze model: %w", runError)
	}

	// explaining a single risk is not implemented yet

	_ = result
	return errors.New("not implemented yet")
}

func (what *Threagile) explainRules(cmd *cobra.Command, args []string) error {
	what.processArgs(cmd, args)

	cmd.Println(Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp))
	cmd.Println("Explanation for risk rules:")
	cmd.Println()
	cmd.Println("----------------------")
	cmd.Println("Custom risk rules:")
	cmd.Println("----------------------")
	customRiskRules := model.LoadCustomRiskRules(what.config.GetPluginFolder(), what.config.GetRiskRulePlugins(), DefaultProgressReporter{Verbose: what.config.GetVerbose()})
	for _, id := range slices.Sorted(maps.Keys(customRiskRules)) {
		rule := customRiskRules[id]
		cmd.Printf("%v: %v\n", rule.Category().ID, rule.Category().Description)
	}
	cmd.Println()
	cmd.Println("--------------------")
	cmd.Println("Built-in risk rules:")
	cmd.Println("--------------------")
	cmd.Println()
	builtInRiskRules := risks.GetBuiltInRiskRules()
	for _, id := range slices.Sorted(maps.Keys(builtInRiskRules)) {
		rule := builtInRiskRules[id]
		cmd.Printf("%v: %v\n", rule.Category().ID, rule.Category().Description)
	}
	cmd.Println()

	return nil
}

func (what *Threagile) explainMacros(cmd *cobra.Command, args []string) {
	what.processArgs(cmd, args)

	cmd.Println(Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp))
	cmd.Println("Explanation for the model macros:")
	cmd.Println()
	/* custom model macros are not supported yet; once they are, explain them like this:
	cmd.Println("Custom model macros:")
	for _, macros := range macros.ListCustomMacros() {
		details := macros.GetMacroDetails()
		cmd.Println(details.ID, "-->", details.Title)
	}
	cmd.Println()
	*/
	cmd.Println("----------------------")
	cmd.Println("Built-in model macros:")
	cmd.Println("----------------------")
	for _, macroList := range macros.ListBuiltInMacros() {
		details := macroList.GetMacroDetails()
		cmd.Printf("%v: %v\n", details.ID, details.Title)
	}

	cmd.Println()
}

func (what *Threagile) explainTypes(cmd *cobra.Command, args []string) {
	what.processArgs(cmd, args)

	cmd.Println(Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp))
	fmt.Println("Explanation for the types:")
	cmd.Println()
	cmd.Println("The following types are available (can be extended for custom rules):")
	cmd.Println()
	typeValues := types.GetBuiltinTypeValues(what.config)
	for _, name := range slices.Sorted(maps.Keys(typeValues)) {
		cmd.Println(name)
		for _, candidate := range typeValues[name] {
			cmd.Printf("\t %v: %v\n", candidate, candidate.Explain())
		}
	}
}
