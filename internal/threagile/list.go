package threagile

import (
	"fmt"
	"maps"
	"slices"

	"github.com/Pinguladora/threagile/pkg/macros"
	"github.com/Pinguladora/threagile/pkg/model"
	"github.com/Pinguladora/threagile/pkg/risks"
	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/spf13/cobra"
)

func (what *Threagile) initList() *Threagile {
	what.rootCmd.AddCommand(&cobra.Command{
		Use:   ListRiskRulesCommand,
		Short: "Print available risk rules",
		RunE:  what.listRiskRules,
	})

	what.rootCmd.AddCommand(&cobra.Command{
		Use:   ListModelMacrosCommand,
		Short: "Print model macros",
		Run:   what.listModelMacros,
	})

	what.rootCmd.AddCommand(&cobra.Command{
		Use:   ListTypesCommand,
		Short: "Print type information (enum values to be used in models)",
		Run:   what.listTypes,
	})

	return what
}

func (what *Threagile) listRiskRules(cmd *cobra.Command, args []string) error {
	what.processArgs(cmd, args)

	cmd.Println(Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp))
	cmd.Println("The following risk rules are available (can be extended via custom risk rules):")
	cmd.Println()
	cmd.Println("----------------------")
	cmd.Println("Custom risk rules:")
	cmd.Println("----------------------")
	customRiskRules := model.LoadCustomRiskRules(what.config.GetPluginFolder(), what.config.GetRiskRulePlugins(),
		DefaultProgressReporter{Verbose: what.config.GetVerbose()})
	for _, id := range slices.Sorted(maps.Keys(customRiskRules)) {
		customRule := customRiskRules[id]
		cmd.Println(id, "-->", customRule.Category().Title, "--> with tags:", customRule.SupportedTags())
	}
	cmd.Println()
	cmd.Println("--------------------")
	cmd.Println("Built-in risk rules:")
	cmd.Println("--------------------")
	cmd.Println()
	builtInRiskRules := risks.GetBuiltInRiskRules()
	for _, id := range slices.Sorted(maps.Keys(builtInRiskRules)) {
		rule := builtInRiskRules[id]
		cmd.Println(rule.Category().ID, "-->", rule.Category().Title, "--> with tags:", rule.SupportedTags())
	}

	return nil
}

func (what *Threagile) listModelMacros(cmd *cobra.Command, args []string) {
	what.processArgs(cmd, args)

	cmd.Println(Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp))
	cmd.Println("The following model macros are available (can be extended via custom model macros):")
	cmd.Println()
	/* custom model macros are not supported yet; once they are, list them like this:
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
		cmd.Println(details.ID, "-->", details.Title)
	}
	cmd.Println()
}

func (what *Threagile) listTypes(cmd *cobra.Command, args []string) {
	what.processArgs(cmd, args)

	cmd.Println(Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp))
	cmd.Println()
	cmd.Println()
	cmd.Println("The following types are available (can be extended for custom rules):")
	cmd.Println()
	typeValues := types.GetBuiltinTypeValues(what.config)
	for _, name := range slices.Sorted(maps.Keys(typeValues)) {
		cmd.Println(fmt.Sprintf("  %v: %v", name, typeValues[name]))
	}
}
