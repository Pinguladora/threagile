/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package threagile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Pinguladora/threagile/pkg/report"
	"github.com/chzyer/readline"
	"github.com/mattn/go-shellwords"
	"github.com/spf13/cobra"
)

const (
	UsageTemplate = `Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
 {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Title "help"))}}
  {{rpad .Title .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}
`
)

func (what *Threagile) initRoot() *Threagile {
	what.rootCmd = &cobra.Command{
		Use:           "threagile",
		Version:       ThreagileVersion,
		Short:         "\n" + Logo,
		Long:          "\n" + Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp) + "\n\n" + Examples,
		SilenceErrors: true,
		SilenceUsage:  true,
		Run:           what.run,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	what.config = new(Config).Defaults(what.buildTimestamp)
	return what.initFlags()
}

func (what *Threagile) initFlags() *Threagile {
	what.rootCmd.ResetFlags()

	flags := what.rootCmd.PersistentFlags()
	flags.StringVar(&what.flags.configFlag, configFlagName, "", "config file")

	flags.BoolVarP(&what.flags.VerboseValue, verboseFlagName, verboseFlagShorthand, what.config.GetVerbose(),
		"Verbose output")
	flags.BoolVarP(&what.flags.InteractiveValue, interactiveFlagName, interactiveFlagShorthand,
		what.config.GetInteractive(), "interactive mode")

	flags.StringVar(&what.flags.AppFolderValue, appDirFlagName, what.config.GetAppFolder(),
		"optional folder with files that override the ones embedded in the binary")
	flags.StringVar(&what.flags.PluginFolderValue, pluginDirFlagName, what.config.GetPluginFolder(), "plugin directory")
	flags.StringVar(&what.flags.DataFolderValue, dataDirFlagName, what.config.GetDataFolder(), "data directory")
	flags.StringVar(&what.flags.OutputFolderValue, outputFlagName, what.config.GetOutputFolder(), "output directory")
	flags.StringVar(&what.flags.TempFolderValue, tempDirFlagName, what.config.GetTempFolder(), "temporary folder location")
	flags.StringVar(&what.flags.KeyFolderValue, keyDirFlagName, what.config.GetKeyFolder(), "key folder location")

	what.initFileFlags()
	what.initOptionFlags()
	what.initSkipFlags()

	// AttractivenessValue not available as flags
	// ReportConfigurationValue not available as flags

	return what
}

// initFileFlags adds the flags of the files that threagile reads and writes.
func (what *Threagile) initFileFlags() {
	flags := what.rootCmd.PersistentFlags()
	flags.StringVar(&what.flags.InputFileValue, inputFileFlagName, what.config.GetInputFile(), "input model yaml file")
	flags.StringVar(&what.flags.ImportedInputFileValue, importedFileFlagName, what.config.GetImportedInputFile(),
		"imported input model yaml file")
	flags.StringVar(&what.flags.OTMFileValue, otmFileFlagName, what.config.GetOTMFile(),
		"Open Threat Model (OTM) file to import with "+ImportOTMCommand)
	flags.StringVar(&what.flags.DataFlowDiagramFilenamePNGValue, dataFlowDiagramPNGFileFlagName,
		what.config.GetDataFlowDiagramFilenamePNG(), "data flow diagram PNG file")
	flags.StringVar(&what.flags.DataAssetDiagramFilenamePNGValue, dataAssetDiagramPNGFileFlagName,
		what.config.GetDataAssetDiagramFilenamePNG(), "data asset diagram PNG file")
	flags.StringVar(&what.flags.DataFlowDiagramFilenameDOTValue, dataFlowDiagramDOTFileFlagName,
		what.config.GetDataFlowDiagramFilenameDOT(), "data flow diagram DOT file")
	flags.StringVar(&what.flags.DataAssetDiagramFilenameDOTValue, dataAssetDiagramDOTFileFlagName,
		what.config.GetDataAssetDiagramFilenameDOT(), "data asset diagram DOT file")
	flags.StringVar(&what.flags.ReportFilenameValue, reportFileFlagName, what.config.GetReportFilename(), "report file")
	flags.StringVar(&what.flags.ExcelRisksFilenameValue, risksExcelFileFlagName, what.config.GetExcelRisksFilename(),
		"risks Excel file")
	flags.StringVar(&what.flags.ExcelTagsFilenameValue, tagsExcelFileFlagName, what.config.GetExcelTagsFilename(),
		"tags Excel file")
	flags.StringVar(&what.flags.JsonRisksFilenameValue, risksJsonFileFlagName, what.config.GetJsonRisksFilename(),
		"risks JSON file")
	flags.StringVar(&what.flags.JsonTechnicalAssetsFilenameValue, technicalAssetsJsonFileFlagName,
		what.config.GetJsonTechnicalAssetsFilename(), "technical assets JSON file")
	flags.StringVar(&what.flags.JsonStatsFilenameValue, statsJsonFileFlagName, what.config.GetJsonStatsFilename(),
		"stats JSON file")
	flags.StringVar(&what.flags.JsonOTMFilenameValue, otmJsonFileFlagName, what.config.GetJsonOTMFilename(),
		"Open Threat Model (OTM) JSON file")
	flags.StringVar(&what.flags.ReportHTMLFilenameValue, reportHTMLFileFlagName, what.config.GetReportHTMLFilename(),
		"HTML report file")
	flags.StringVar(&what.flags.ReportMarkdownFilenameValue, reportMarkdownFileFlagName,
		what.config.GetReportMarkdownFilename(), "Markdown report file")
	flags.StringVar(&what.flags.TemplateFilenameValue, templateFileNameFlagName, what.config.GetTemplateFilename(),
		"template pdf file")
	flags.StringVar(&what.flags.ReportLogoImagePathValue, reportLogoImagePathFlagName,
		what.config.GetReportLogoImagePath(), "report logo image")
	flags.StringVar(&what.flags.TechnologyFilenameValue, technologyFileFlagName, what.config.GetTechnologyFilename(),
		"file name of additional technologies")
}

// initOptionFlags adds the flags of the risk rules, the server and the diagrams.
func (what *Threagile) initOptionFlags() {
	flags := what.rootCmd.PersistentFlags()
	flags.StringVar(&what.flags.riskRulePluginsValue, customRiskRulesPluginFlagName,
		strings.Join(what.config.GetRiskRulePlugins(), ","),
		"comma-separated list of plugins file names with custom risk rules to load")
	flags.StringVar(&what.flags.skipRiskRulesValue, skipRiskRulesFlagName,
		strings.Join(what.config.GetSkipRiskRules(), ","), "comma-separated list of risk rules (by their ID) to skip")
	flags.StringVar(&what.flags.ExecuteModelMacroValue, executeModelMacroFlagName, what.config.GetExecuteModelMacro(),
		"macro to execute")
	flags.StringVar(&what.flags.FailOnValue, failOnFlagName, what.config.GetFailOn(),
		"exit with status 2 when unchecked risks of this severity or higher remain (low, medium, elevated, high, critical)")

	// RiskExcelValue not available as flags

	flags.IntVar(&what.flags.ServerPortValue, serverPortFlagName, what.config.GetServerPort(), "server port")
	flags.StringVar(&what.flags.ServerFolderValue, serverDirFlagName, what.config.GetDataFolder(),
		"base folder for server mode")
	flags.IntVar(&what.flags.DiagramDPIValue, diagramDpiFlagName, what.config.GetDiagramDPI(),
		"DPI used to render: maximum is "+strconv.Itoa(what.config.GetMaxGraphvizDPI()))
	// MaxGraphvizDPIValue not available as flags
	flags.IntVar(&what.flags.BackupHistoryFilesToKeepValue, backupHistoryFilesToKeepFlagName,
		what.config.GetBackupHistoryFilesToKeep(), "number of backup history files to keep")

	flags.BoolVar(&what.flags.AddModelTitleValue, addModelTitleFlagName, what.config.GetAddModelTitle(), "add model title")
	flags.BoolVar(&what.flags.KeepDiagramSourceFilesValue, keepDiagramSourceFilesFlagName,
		what.config.GetKeepDiagramSourceFiles(), "keep diagram source files")
	flags.BoolVar(&what.flags.IgnoreOrphanedRiskTrackingValue, ignoreOrphanedRiskTrackingFlagName,
		what.config.GetIgnoreOrphanedRiskTracking(),
		"ignore orphaned risk tracking (just log them) not matching a concrete risk")
}

// initSkipFlags adds the flags that skip outputs, and the deprecated ones that generate them.
func (what *Threagile) initSkipFlags() {
	flags := what.rootCmd.PersistentFlags()
	flags.BoolVar(&what.flags.SkipDataFlowDiagramValue, skipDataFlowDiagramFlagName, what.config.GetSkipDataFlowDiagram(),
		"skip generating data flow diagram")
	flags.BoolVar(&what.flags.SkipDataAssetDiagramValue, skipDataAssetDiagramFlagName,
		what.config.GetSkipDataAssetDiagram(), "skip generating data asset diagram")
	flags.BoolVar(&what.flags.SkipRisksJSONValue, skipRisksJSONFlagName, what.config.GetSkipRisksJSON(),
		"skip generating risks json")
	flags.BoolVar(&what.flags.SkipTechnicalAssetsJSONValue, skipTechnicalAssetsJSONFlagName,
		what.config.GetSkipTechnicalAssetsJSON(), "skip generating technical assets json")
	flags.BoolVar(&what.flags.SkipStatsJSONValue, skipStatsJSONFlagName, what.config.GetSkipStatsJSON(),
		"skip generating stats json")
	flags.BoolVar(&what.flags.SkipOTMJSONValue, skipOTMJSONFlagName, what.config.GetSkipOTMJSON(),
		"skip generating Open Threat Model (OTM) json")
	flags.BoolVar(&what.flags.SkipRisksExcelValue, skipRisksExcelFlagName, what.config.GetSkipRisksExcel(),
		"skip generating risks excel")
	flags.BoolVar(&what.flags.SkipTagsExcelValue, skipTagsExcelFlagName, what.config.GetSkipTagsExcel(),
		"skip generating tags excel")
	flags.BoolVar(&what.flags.SkipReportPDFValue, skipReportPDFFlagName, what.config.GetSkipReportPDF(),
		"skip generating report pdf, including diagrams")
	flags.BoolVar(&what.flags.SkipReportADOCValue, skipReportADOCFlagName, what.config.GetSkipReportADOC(),
		"skip generating report adoc, including diagrams")
	flags.BoolVar(&what.flags.SkipReportHTMLValue, skipReportHTMLFlagName, what.config.GetSkipReportHTML(),
		"skip generating report html")
	flags.BoolVar(&what.flags.SkipReportMarkdownValue, skipReportMarkdownFlagName, what.config.GetSkipReportMarkdown(),
		"skip generating report markdown")

	flags.BoolVar(&what.flags.generateDataFlowDiagramFlag, generateDataFlowDiagramFlagName,
		!what.config.GetSkipDataFlowDiagram(), "(deprecated, use the matching --skip flag) generate data flow diagram")
	flags.BoolVar(&what.flags.generateDataAssetDiagramFlag, generateDataAssetDiagramFlagName,
		!what.config.GetSkipDataAssetDiagram(), "(deprecated, use the matching --skip flag) generate data asset diagram")
	flags.BoolVar(&what.flags.generateRisksJSONFlag, generateRisksJSONFlagName, !what.config.GetSkipRisksJSON(),
		"(deprecated, use the matching --skip flag) generate risks json")
	flags.BoolVar(&what.flags.generateTechnicalAssetsJSONFlag, generateTechnicalAssetsJSONFlagName,
		!what.config.GetSkipTechnicalAssetsJSON(),
		"(deprecated, use the matching --skip flag) generate technical assets json")
	flags.BoolVar(&what.flags.generateStatsJSONFlag, generateStatsJSONFlagName, !what.config.GetSkipStatsJSON(),
		"(deprecated, use the matching --skip flag) generate stats json")
	flags.BoolVar(&what.flags.generateRisksExcelFlag, generateRisksExcelFlagName, !what.config.GetSkipRisksExcel(),
		"(deprecated, use the matching --skip flag) generate risks excel")
	flags.BoolVar(&what.flags.generateTagsExcelFlag, generateTagsExcelFlagName, !what.config.GetSkipTagsExcel(),
		"(deprecated, use the matching --skip flag) generate tags excel")
	flags.BoolVar(&what.flags.generateReportPDFFlag, generateReportPDFFlagName, !what.config.GetSkipReportPDF(),
		"(deprecated, use the matching --skip flag) generate report pdf, including diagrams")
	flags.BoolVar(&what.flags.generateReportADOCFlag, generateReportADOCFlagName, !what.config.GetSkipReportADOC(),
		"(deprecated, use the matching --skip flag) generate report adoc, including diagrams")
}

func (what *Threagile) run(thisCmd *cobra.Command, args []string) {
	what.processArgs(thisCmd, args)

	if !what.config.GetInteractive() {
		what.rootCmd.Println("Please add the --interactive flag to run in interactive mode.")
		return
	}

	shell, ok := what.newShell()
	if !ok {
		return
	}

	defer func() { _ = shell.Close() }()

	for {
		line, readError := shell.Readline()
		if errors.Is(readError, readline.ErrInterrupt) {
			return
		}
		if readError != nil {
			what.rootCmd.Println("Error, please report bug at https://github.com/Threagile/threagile. " +
				"Unable to read line: " + readError.Error())
			return
		}

		what.runLine(line)
	}
}

// historyLimit is how many lines the history of the interactive mode keeps.
const historyLimit = 1000

// newShell sets up the line reader of the interactive mode; it reports why it could not.
func (what *Threagile) newShell() (*readline.Instance, bool) {
	completer := readline.NewPrefixCompleter()
	for _, child := range what.rootCmd.Commands() {
		what.cobraToReadline(completer, child)
	}

	dir, homeError := os.UserHomeDir()
	if homeError != nil {
		what.rootCmd.Println("Error, please report bug at https://github.com/Threagile/threagile. " +
			"Unable to find home directory: " + homeError.Error())
		return nil, false
	}

	shell, readlineError := readline.NewEx(&readline.Config{
		Prompt:            "\033[31m>>\033[0m ",
		HistoryFile:       filepath.Join(dir, ".threagile_history"),
		HistoryLimit:      historyLimit,
		AutoComplete:      completer,
		InterruptPrompt:   "^C",
		EOFPrompt:         "quit",
		HistorySearchFold: true,
	})

	if readlineError != nil {
		what.rootCmd.Println("Error, please report bug at https://github.com/Threagile/threagile. " +
			"Unable to initialize readline: " + readlineError.Error())
		return nil, false
	}

	return shell, true
}

// runLine runs the command on a line of the interactive mode.
func (what *Threagile) runLine(line string) {
	if len(strings.TrimSpace(line)) == 0 {
		return
	}

	params, parseError := shellwords.Parse(line)
	if parseError != nil {
		what.rootCmd.Printf("failed to parse command line: %s", parseError.Error())
		return
	}

	cmd, args, findError := what.rootCmd.Find(params)
	if findError != nil {
		what.rootCmd.Printf("failed to find command: %s", findError.Error())
		return
	}

	if cmd == nil || cmd == what.rootCmd {
		what.rootCmd.Println("failed to find command")
		return
	}

	what.runCommand(cmd, args)
}

func (what *Threagile) runCommand(cmd *cobra.Command, args []string) {
	flagsError := cmd.ParseFlags(args)
	if flagsError != nil {
		what.rootCmd.Printf("invalid flags: %s", flagsError.Error())
		return
	}

	if !cmd.DisableFlagParsing {
		args = cmd.Flags().Args()
	}

	argsError := cmd.ValidateArgs(args)
	if argsError != nil {
		_ = cmd.Help()
		return
	}

	if cmd.Run != nil {
		cmd.Run(cmd, args)
		return
	}

	if cmd.RunE != nil {
		runError := cmd.RunE(cmd, args)
		if runError != nil {
			what.rootCmd.Printf("error: %v \n", runError)
		}

		return
	}

	_ = cmd.Help()
}

func (what *Threagile) cobraToReadline(node readline.PrefixCompleterInterface, cmd *cobra.Command) {
	cmd.SetUsageTemplate(UsageTemplate)
	cmd.Use = what.usage(cmd)
	pcItem := readline.PcItem(cmd.Use)
	node.SetChildren(append(node.GetChildren(), pcItem))

	for _, child := range cmd.Commands() {
		what.cobraToReadline(pcItem, child)
	}
}

func (what *Threagile) usage(cmd *cobra.Command) string {
	words := make([]string, 0, len(cmd.ArgAliases)+1)
	words = append(words, cmd.Use)

	for _, name := range cmd.ArgAliases {
		words = append(words, "["+name+"]")
	}

	return strings.Join(words, " ")
}

func (what *Threagile) readCommands() *report.GenerateCommands {
	commands := new(report.GenerateCommands).Defaults()
	commands.DataFlowDiagram = !what.flags.SkipDataFlowDiagramValue
	commands.DataAssetDiagram = !what.flags.SkipDataAssetDiagramValue
	commands.RisksJSON = !what.flags.SkipRisksJSONValue
	commands.StatsJSON = !what.flags.SkipStatsJSONValue
	commands.OTMJSON = !what.flags.SkipOTMJSONValue
	commands.TechnicalAssetsJSON = !what.flags.SkipTechnicalAssetsJSONValue
	commands.RisksExcel = !what.flags.SkipRisksExcelValue
	commands.TagsExcel = !what.flags.SkipTagsExcelValue
	commands.ReportPDF = !what.flags.SkipReportPDFValue
	commands.ReportADOC = !what.flags.SkipReportADOCValue
	commands.ReportHTML = !what.flags.SkipReportHTMLValue
	commands.ReportMarkdown = !what.flags.SkipReportMarkdownValue
	return commands
}

func (what *Threagile) processSystemArgs(cmd *cobra.Command) *Threagile {
	what.config.InteractiveValue = what.processArgs(cmd, os.Args[1:])
	return what
}

func (what *Threagile) processArgs(cmd *cobra.Command, args []string) bool {
	_ = cmd.PersistentFlags().Parse(args)

	if what.isFlagOverridden(cmd, configFlagName) {
		configError := what.config.Load(what.flags.configFlag)
		if configError != nil {
			what.rootCmd.Printf("WARNING: failed to load config file %q: %v\n", what.flags.configFlag, configError)
		}
	}

	override(what, cmd, verboseFlagName, &what.config.VerboseValue, what.flags.VerboseValue)

	interactive := what.config.GetInteractive()
	if what.isFlagOverridden(cmd, interactiveFlagName) {
		interactive = what.flags.InteractiveValue
	}

	what.overrideFolderArgs(cmd)
	what.overrideFileArgs(cmd)
	what.overrideOptionArgs(cmd)
	what.overrideSkipArgs(cmd)

	// AttractivenessValue not available as flags
	// ReportConfigurationValue not available as flags

	what.initFlags()

	return interactive
}

func (what *Threagile) overrideFolderArgs(cmd *cobra.Command) {
	what.overridePath(cmd, appDirFlagName, &what.config.AppFolderValue, what.flags.AppFolderValue)
	what.overridePath(cmd, pluginDirFlagName, &what.config.PluginFolderValue, what.flags.PluginFolderValue)
	what.overridePath(cmd, dataDirFlagName, &what.config.DataFolderValue, what.flags.DataFolderValue)
	what.overridePath(cmd, outputFlagName, &what.config.OutputFolderValue, what.flags.OutputFolderValue)
	what.overridePath(cmd, serverDirFlagName, &what.config.ServerFolderValue, what.flags.ServerFolderValue)
	what.overridePath(cmd, tempDirFlagName, &what.config.TempFolderValue, what.flags.TempFolderValue)
	what.overridePath(cmd, keyDirFlagName, &what.config.KeyFolderValue, what.flags.KeyFolderValue)
}

func (what *Threagile) overrideFileArgs(cmd *cobra.Command) {
	what.overridePath(cmd, importedFileFlagName, &what.config.ImportedInputFileValue, what.flags.ImportedInputFileValue)
	what.overridePath(cmd, inputFileFlagName, &what.config.InputFileValue, what.flags.InputFileValue)
	what.overridePath(cmd, otmFileFlagName, &what.config.OTMFileValue, what.flags.OTMFileValue)
	what.overridePath(cmd, dataFlowDiagramPNGFileFlagName, &what.config.DataFlowDiagramFilenamePNGValue,
		what.flags.DataFlowDiagramFilenamePNGValue)
	what.overridePath(cmd, dataAssetDiagramPNGFileFlagName, &what.config.DataAssetDiagramFilenamePNGValue,
		what.flags.DataAssetDiagramFilenamePNGValue)
	what.overridePath(cmd, dataFlowDiagramDOTFileFlagName, &what.config.DataFlowDiagramFilenameDOTValue,
		what.flags.DataFlowDiagramFilenameDOTValue)
	what.overridePath(cmd, dataAssetDiagramDOTFileFlagName, &what.config.DataAssetDiagramFilenameDOTValue,
		what.flags.DataAssetDiagramFilenameDOTValue)
	what.overridePath(cmd, reportFileFlagName, &what.config.ReportFilenameValue, what.flags.ReportFilenameValue)
	what.overridePath(cmd, risksExcelFileFlagName, &what.config.ExcelRisksFilenameValue,
		what.flags.ExcelRisksFilenameValue)
	what.overridePath(cmd, tagsExcelFileFlagName, &what.config.ExcelTagsFilenameValue, what.flags.ExcelTagsFilenameValue)
	what.overridePath(cmd, risksJsonFileFlagName, &what.config.JsonRisksFilenameValue, what.flags.JsonRisksFilenameValue)
	what.overridePath(cmd, technicalAssetsJsonFileFlagName, &what.config.JsonTechnicalAssetsFilenameValue,
		what.flags.JsonTechnicalAssetsFilenameValue)
	what.overridePath(cmd, statsJsonFileFlagName, &what.config.JsonStatsFilenameValue, what.flags.JsonStatsFilenameValue)
	what.overridePath(cmd, otmJsonFileFlagName, &what.config.JsonOTMFilenameValue, what.flags.JsonOTMFilenameValue)
	what.overridePath(cmd, reportHTMLFileFlagName, &what.config.ReportHTMLFilenameValue,
		what.flags.ReportHTMLFilenameValue)
	what.overridePath(cmd, reportMarkdownFileFlagName, &what.config.ReportMarkdownFilenameValue,
		what.flags.ReportMarkdownFilenameValue)
	override(what, cmd, templateFileNameFlagName, &what.config.TemplateFilenameValue, what.flags.TemplateFilenameValue)
	override(what, cmd, reportLogoImagePathFlagName, &what.config.ReportLogoImagePathValue,
		what.flags.ReportLogoImagePathValue)
	override(what, cmd, technologyFileFlagName, &what.config.TechnologyFilenameValue, what.flags.TechnologyFilenameValue)
}

func (what *Threagile) overrideOptionArgs(cmd *cobra.Command) {
	override(what, cmd, customRiskRulesPluginFlagName, &what.config.RiskRulePluginsValue,
		strings.Split(what.flags.riskRulePluginsValue, ","))
	override(what, cmd, skipRiskRulesFlagName, &what.config.SkipRiskRulesValue,
		strings.Split(what.flags.skipRiskRulesValue, ","))
	override(what, cmd, failOnFlagName, &what.config.FailOnValue, what.flags.FailOnValue)
	override(what, cmd, executeModelMacroFlagName, &what.config.ExecuteModelMacroValue, what.flags.ExecuteModelMacroValue)

	// RiskExcelValue not available as flags

	override(what, cmd, serverModeFlagName, &what.config.ServerModeValue, what.flags.ServerModeValue)
	override(what, cmd, serverPortFlagName, &what.config.ServerPortValue, what.flags.ServerPortValue)
	override(what, cmd, diagramDpiFlagName, &what.config.DiagramDPIValue, what.flags.DiagramDPIValue)
	override(what, cmd, graphvizDpiFlagName, &what.config.GraphvizDPIValue, what.flags.GraphvizDPIValue)

	// MaxGraphvizDPIValue not available as flags

	override(what, cmd, backupHistoryFilesToKeepFlagName, &what.config.BackupHistoryFilesToKeepValue,
		what.flags.BackupHistoryFilesToKeepValue)
	override(what, cmd, addModelTitleFlagName, &what.config.AddModelTitleValue, what.flags.AddModelTitleValue)
	override(what, cmd, keepDiagramSourceFilesFlagName, &what.config.KeepDiagramSourceFilesValue,
		what.flags.KeepDiagramSourceFilesValue)
	override(what, cmd, ignoreOrphanedRiskTrackingFlagName, &what.config.IgnoreOrphanedRiskTrackingValue,
		what.flags.IgnoreOrphanedRiskTrackingValue)
}

func (what *Threagile) overrideSkipArgs(cmd *cobra.Command) {
	override(what, cmd, skipDataFlowDiagramFlagName, &what.config.SkipDataFlowDiagramValue,
		what.flags.SkipDataFlowDiagramValue)
	override(what, cmd, skipDataAssetDiagramFlagName, &what.config.SkipDataAssetDiagramValue,
		what.flags.SkipDataAssetDiagramValue)
	override(what, cmd, skipRisksJSONFlagName, &what.config.SkipRisksJSONValue, what.flags.SkipRisksJSONValue)
	override(what, cmd, skipTechnicalAssetsJSONFlagName, &what.config.SkipTechnicalAssetsJSONValue,
		what.flags.SkipTechnicalAssetsJSONValue)
	override(what, cmd, skipStatsJSONFlagName, &what.config.SkipStatsJSONValue, what.flags.SkipStatsJSONValue)
	override(what, cmd, skipOTMJSONFlagName, &what.config.SkipOTMJSONValue, what.flags.SkipOTMJSONValue)
	override(what, cmd, skipRisksExcelFlagName, &what.config.SkipRisksExcelValue, what.flags.SkipRisksExcelValue)
	override(what, cmd, skipTagsExcelFlagName, &what.config.SkipTagsExcelValue, what.flags.SkipTagsExcelValue)
	override(what, cmd, skipReportPDFFlagName, &what.config.SkipReportPDFValue, what.flags.SkipReportPDFValue)
	override(what, cmd, skipReportADOCFlagName, &what.config.SkipReportADOCValue, what.flags.SkipReportADOCValue)
	override(what, cmd, skipReportHTMLFlagName, &what.config.SkipReportHTMLValue, what.flags.SkipReportHTMLValue)
	override(what, cmd, skipReportMarkdownFlagName, &what.config.SkipReportMarkdownValue,
		what.flags.SkipReportMarkdownValue)

	override(what, cmd, generateDataFlowDiagramFlagName, &what.config.SkipDataFlowDiagramValue,
		!what.flags.generateDataFlowDiagramFlag)
	override(what, cmd, generateDataAssetDiagramFlagName, &what.config.SkipDataAssetDiagramValue,
		!what.flags.generateDataAssetDiagramFlag)
	override(what, cmd, generateRisksJSONFlagName, &what.config.SkipRisksJSONValue, !what.flags.generateRisksJSONFlag)
	override(what, cmd, generateTechnicalAssetsJSONFlagName, &what.config.SkipTechnicalAssetsJSONValue,
		!what.flags.generateTechnicalAssetsJSONFlag)
	override(what, cmd, generateStatsJSONFlagName, &what.config.SkipStatsJSONValue, !what.flags.generateStatsJSONFlag)
	override(what, cmd, generateRisksExcelFlagName, &what.config.SkipRisksExcelValue, !what.flags.generateRisksExcelFlag)
	override(what, cmd, generateTagsExcelFlagName, &what.config.SkipTagsExcelValue, !what.flags.generateTagsExcelFlag)
	override(what, cmd, generateReportPDFFlagName, &what.config.SkipReportPDFValue, !what.flags.generateReportPDFFlag)
	override(what, cmd, generateReportADOCFlagName, &what.config.SkipReportADOCValue, !what.flags.generateReportADOCFlag)
}

// overridePath sets a path of the config to the cleaned value of its flag, if the flag was given.
func (what *Threagile) overridePath(cmd *cobra.Command, flagName string, configValue *string, flagValue string) {
	if what.isFlagOverridden(cmd, flagName) {
		*configValue = what.config.CleanPath(flagValue)
	}
}

// override sets a value of the config to the value of its flag, if the flag was given.
func override[T any](what *Threagile, cmd *cobra.Command, flagName string, configValue *T, flagValue T) {
	if what.isFlagOverridden(cmd, flagName) {
		*configValue = flagValue
	}
}

func (what *Threagile) isFlagOverridden(cmd *cobra.Command, flagName string) bool {
	if cmd == nil {
		return false
	}

	flag := cmd.PersistentFlags().Lookup(flagName)
	if flag == nil {
		return false
	}

	return flag.Changed
}
