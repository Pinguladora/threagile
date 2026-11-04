package threagile

import (
	"fmt"
	"html"
	"maps"
	"regexp"
	"slices"
	"strings"

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
	result, runError := model.ReadAndAnalyzeModel(what.config, risks.GetBuiltInRiskRules(), progressReporter)
	if runError != nil {
		return fmt.Errorf("failed to read and analyze model: %w", runError)
	}

	rules := maps.Clone(result.BuiltinRiskRules)
	maps.Copy(rules, result.CustomRiskRules)
	for _, pattern := range args {
		matching := result.ParsedModel.RisksMatching(pattern)
		if len(matching) == 0 {
			return fmt.Errorf("no risk matches %q", pattern)
		}
		for _, risk := range matching {
			for _, line := range explainRiskLines(result.ParsedModel, rules, risk) {
				cmd.Println(line)
			}
			cmd.Println()
		}
	}
	return nil
}

// explainRiskLines explains why a risk was found and how it is rated: its category, the model elements it is
// about, its rating and tracking, and what the rule checks, followed by the detailed explanation of the rule
// when it gives one.
func explainRiskLines(parsedModel *types.Model, rules types.RiskRules, risk *types.Risk) []string {
	category := parsedModel.GetRiskCategory(risk.CategoryId)
	tracking := parsedModel.GetRiskTrackingWithDefault(risk)
	lines := []string{
		"Risk " + risk.SyntheticId + ": " + plainText(risk.Title),
		fmt.Sprintf("  Severity: %v (exploitation likelihood %v, impact %v)",
			risk.Severity, risk.ExploitationLikelihood, risk.ExploitationImpact),
		fmt.Sprintf("  Status: %v", tracking.Status),
	}
	if tracking.Justification != "" {
		lines = append(lines, "  Justification: "+tracking.Justification)
	}
	lines = append(lines, riskElementLines(parsedModel, risk)...)
	if category != nil {
		lines = append(lines, riskCategoryLines(category)...)
	}
	if explainer, ok := rules[risk.CategoryId].(types.RiskExplainer); ok {
		if explanation := explainer.ExplainRisk(parsedModel, risk.SyntheticId); len(explanation) > 0 {
			lines = append(lines, "  Explanation:")
			for _, line := range explanation {
				lines = append(lines, "    "+line)
			}
		}
	}
	return lines
}

// riskElementLines names the model elements a risk is about, and where data may be breached.
func riskElementLines(parsedModel *types.Model, risk *types.Risk) []string {
	lines := make([]string, 0)
	named := func(label string, id string, title func() string) {
		if id != "" {
			lines = append(lines, "  "+label+": "+title()+" ("+id+")")
		}
	}
	named("Technical asset", risk.MostRelevantTechnicalAssetId, func() string {
		return titleOf(parsedModel.TechnicalAssets[risk.MostRelevantTechnicalAssetId])
	})
	named("Communication link", risk.MostRelevantCommunicationLinkId, func() string {
		if link, ok := parsedModel.CommunicationLinks[risk.MostRelevantCommunicationLinkId]; ok {
			return link.Title
		}
		return risk.MostRelevantCommunicationLinkId
	})
	named("Data asset", risk.MostRelevantDataAssetId, func() string {
		if dataAsset, ok := parsedModel.DataAssets[risk.MostRelevantDataAssetId]; ok {
			return dataAsset.Title
		}
		return risk.MostRelevantDataAssetId
	})
	named("Trust boundary", risk.MostRelevantTrustBoundaryId, func() string {
		if trustBoundary, ok := parsedModel.TrustBoundaries[risk.MostRelevantTrustBoundaryId]; ok {
			return trustBoundary.Title
		}
		return risk.MostRelevantTrustBoundaryId
	})
	named("Shared runtime", risk.MostRelevantSharedRuntimeId, func() string {
		if sharedRuntime, ok := parsedModel.SharedRuntimes[risk.MostRelevantSharedRuntimeId]; ok {
			return sharedRuntime.Title
		}
		return risk.MostRelevantSharedRuntimeId
	})
	if len(risk.DataBreachTechnicalAssetIDs) > 0 {
		lines = append(lines, fmt.Sprintf("  Data breach: %v, at %v", risk.DataBreachProbability,
			strings.Join(risk.DataBreachTechnicalAssetIDs, ", ")))
	}
	return lines
}

// titleOf is the title of a technical asset, or "unknown" when there is none.
func titleOf(technicalAsset *types.TechnicalAsset) string {
	if technicalAsset == nil {
		return "unknown"
	}
	return technicalAsset.Title
}

// riskCategoryLines describes the category of a risk: what the rule checks, how it rates and how to mitigate.
func riskCategoryLines(category *types.RiskCategory) []string {
	lines := []string{"  Category: " + category.Title + " (" + category.ID + "), " + category.STRIDE.Title()}
	if category.CWE > 0 {
		lines[0] += fmt.Sprintf(", CWE-%d", category.CWE)
	}
	if len(category.References) > 0 {
		lines = append(lines, "  References: "+strings.Join(category.References, "; "))
	}
	for _, field := range []struct{ label, text string }{
		{"Detection logic", category.DetectionLogic},
		{"Risk rating", category.RiskAssessment},
		{"False positives", category.FalsePositives},
		{"Mitigation", category.Mitigation},
	} {
		if field.text != "" {
			lines = append(lines, "  "+field.label+": "+plainText(field.text))
		}
	}
	return lines
}

// htmlTag matches the HTML tags that the titles and the texts of the rules use for formatting.
var htmlTag = regexp.MustCompile(`<[^>]*>`)

// plainText is the text without its HTML tags, for the terminal.
func plainText(text string) string {
	return html.UnescapeString(htmlTag.ReplaceAllString(text, ""))
}

func (what *Threagile) explainRules(cmd *cobra.Command, args []string) error {
	what.processArgs(cmd, args)

	cmd.Println(Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp))
	cmd.Println("Explanation for risk rules:")
	cmd.Println()
	cmd.Println("----------------------")
	cmd.Println("Custom risk rules:")
	cmd.Println("----------------------")
	customRiskRules := model.LoadCustomRiskRules(what.config.GetPluginFolder(), what.config.GetRiskRulePlugins(),
		DefaultProgressReporter{Verbose: what.config.GetVerbose()})
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
