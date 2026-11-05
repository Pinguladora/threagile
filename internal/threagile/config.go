package threagile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Pinguladora/threagile/pkg/report"
	"github.com/Pinguladora/threagile/pkg/types"
	"go.yaml.in/yaml/v3"
)

type Config struct {
	ConfigGetter
	ConfigSetter

	BuildTimestampValue string `json:"BuildTimestamp,omitempty" yaml:"BuildTimestamp"`
	VerboseValue        bool   `json:"Verbose,omitempty"        yaml:"Verbose"`
	InteractiveValue    bool   `json:"Interactive,omitempty"    yaml:"Interactive"`

	AppFolderValue    string `json:"AppFolder,omitempty"    yaml:"AppFolder"`
	PluginFolderValue string `json:"PluginFolder,omitempty" yaml:"PluginFolder"`
	DataFolderValue   string `json:"DataFolder,omitempty"   yaml:"DataFolder"`
	OutputFolderValue string `json:"OutputFolder,omitempty" yaml:"OutputFolder"`
	ServerFolderValue string `json:"ServerFolder,omitempty" yaml:"ServerFolder"`
	TempFolderValue   string `json:"TempFolder,omitempty"   yaml:"TempFolder"`
	KeyFolderValue    string `json:"KeyFolder,omitempty"    yaml:"KeyFolder"`

	InputFileValue                   string `json:"InputFile,omitempty"                   yaml:"InputFile"`
	ImportedInputFileValue           string `json:"ImportedInputFile,omitempty"           yaml:"ImportedInputFile"`
	OTMFileValue                     string `json:"OTMFile,omitempty"                     yaml:"OTMFile"`
	DataFlowDiagramFilenamePNGValue  string `json:"DataFlowDiagramFilenamePNG,omitempty"  yaml:"DataFlowDiagramFilenamePNG"`
	DataAssetDiagramFilenamePNGValue string `json:"DataAssetDiagramFilenamePNG,omitempty" yaml:"DataAssetDiagramFilenamePNG"`
	DataFlowDiagramFilenameDOTValue  string `json:"DataFlowDiagramFilenameDOT,omitempty"  yaml:"DataFlowDiagramFilenameDOT"`
	DataAssetDiagramFilenameDOTValue string `json:"DataAssetDiagramFilenameDOT,omitempty" yaml:"DataAssetDiagramFilenameDOT"`
	ReportFilenameValue              string `json:"ReportFilename,omitempty"              yaml:"ReportFilename"`
	ExcelRisksFilenameValue          string `json:"ExcelRisksFilename,omitempty"          yaml:"ExcelRisksFilename"`
	ExcelTagsFilenameValue           string `json:"ExcelTagsFilename,omitempty"           yaml:"ExcelTagsFilename"`
	JsonRisksFilenameValue           string `json:"JsonRisksFilename,omitempty"           yaml:"JsonRisksFilename"`
	JsonTechnicalAssetsFilenameValue string `json:"JsonTechnicalAssetsFilename,omitempty" yaml:"JsonTechnicalAssetsFilename"`
	JsonStatsFilenameValue           string `json:"JsonStatsFilename,omitempty"           yaml:"JsonStatsFilename"`
	JsonOTMFilenameValue             string `json:"JsonOTMFilename,omitempty"             yaml:"JsonOTMFilename"`
	ReportHTMLFilenameValue          string `json:"ReportHTMLFilename,omitempty"          yaml:"ReportHTMLFilename"`
	ReportMarkdownFilenameValue      string `json:"ReportMarkdownFilename,omitempty"      yaml:"ReportMarkdownFilename"`
	TemplateFilenameValue            string `json:"TemplateFilename,omitempty"            yaml:"TemplateFilename"`
	ReportLogoImagePathValue         string `json:"ReportLogoImagePath,omitempty"         yaml:"ReportLogoImagePath"`
	TechnologyFilenameValue          string `json:"TechnologyFilename,omitempty"          yaml:"TechnologyFilename"`
	HideEmptyChaptersValue           bool   `json:"HideEmptyChapters,omitempty"           yaml:"HideEmptyChapters"`

	RiskRulePluginsValue   []string        `json:"RiskRulePlugins,omitempty"   yaml:"RiskRulePlugins"`
	SkipRiskRulesValue     []string        `json:"SkipRiskRules,omitempty"     yaml:"SkipRiskRules"`
	ExecuteModelMacroValue string          `json:"ExecuteModelMacro,omitempty" yaml:"ExecuteModelMacro"`
	FailOnValue            string          `json:"FailOn,omitempty"            yaml:"FailOn"`
	BaselineValue          string          `json:"Baseline,omitempty"          yaml:"Baseline"`
	RiskExcelValue         RiskExcelConfig `json:"RiskExcel"                   yaml:"RiskExcel"`

	ServerModeValue               bool `json:"ServerMode,omitempty"               yaml:"ServerMode"`
	ServerPortValue               int  `json:"ServerPort,omitempty"               yaml:"ServerPort"`
	DiagramDPIValue               int  `json:"DiagramDPI,omitempty"               yaml:"DiagramDPI"`
	GraphvizDPIValue              int  `json:"GraphvizDPI,omitempty"              yaml:"GraphvizDPI"`
	MaxGraphvizDPIValue           int  `json:"MaxGraphvizDPI,omitempty"           yaml:"MaxGraphvizDPI"`
	BackupHistoryFilesToKeepValue int  `json:"BackupHistoryFilesToKeep,omitempty" yaml:"BackupHistoryFilesToKeep"`

	AddModelTitleValue              bool `json:"AddModelTitle,omitempty"              yaml:"AddModelTitle"`
	AddLegendValue                  bool `json:"AddLegend,omitempty"                  yaml:"AddLegend"`
	KeepDiagramSourceFilesValue     bool `json:"KeepDiagramSourceFiles,omitempty"     yaml:"KeepDiagramSourceFiles"`
	IgnoreOrphanedRiskTrackingValue bool `json:"IgnoreOrphanedRiskTracking,omitempty" yaml:"IgnoreOrphanedRiskTracking"`

	SkipDataFlowDiagramValue     bool `json:"SkipDataFlowDiagram,omitempty"     yaml:"SkipDataFlowDiagram"`
	SkipDataAssetDiagramValue    bool `json:"SkipDataAssetDiagram,omitempty"    yaml:"SkipDataAssetDiagram"`
	SkipRisksJSONValue           bool `json:"SkipRisksJSON,omitempty"           yaml:"SkipRisksJSON"`
	SkipTechnicalAssetsJSONValue bool `json:"SkipTechnicalAssetsJSON,omitempty" yaml:"SkipTechnicalAssetsJSON"`
	SkipStatsJSONValue           bool `json:"SkipStatsJSON,omitempty"           yaml:"SkipStatsJSON"`
	SkipOTMJSONValue             bool `json:"SkipOTMJSON,omitempty"             yaml:"SkipOTMJSON"`
	SkipRisksExcelValue          bool `json:"SkipRisksExcel,omitempty"          yaml:"SkipRisksExcel"`
	SkipTagsExcelValue           bool `json:"SkipTagsExcel,omitempty"           yaml:"SkipTagsExcel"`
	SkipReportPDFValue           bool `json:"SkipReportPDF,omitempty"           yaml:"SkipReportPDF"`
	SkipReportADOCValue          bool `json:"SkipReportADOC,omitempty"          yaml:"SkipReportADOC"`
	SkipReportHTMLValue          bool `json:"SkipReportHTML,omitempty"          yaml:"SkipReportHTML"`
	SkipReportMarkdownValue      bool `json:"SkipReportMarkdown,omitempty"      yaml:"SkipReportMarkdown"`

	AttractivenessValue Attractiveness `json:"Attractiveness" yaml:"Attractiveness"`

	ReportConfigurationValue report.ReportConfiguation `json:"ReportConfiguration" yaml:"ReportConfiguration"`
}

type ConfigGetter interface {
	GetBuildTimestamp() string
	GetVerbose() bool
	GetInteractive() bool
	GetAppFolder() string
	GetPluginFolder() string
	GetDataFolder() string
	GetOutputFolder() string
	GetServerFolder() string
	GetTempFolder() string
	GetKeyFolder() string
	GetTechnologyFilename() string
	GetInputFile() string
	GetOTMFile() string
	GetDataFlowDiagramFilenamePNG() string
	GetDataAssetDiagramFilenamePNG() string
	GetDataFlowDiagramFilenameDOT() string
	GetDataAssetDiagramFilenameDOT() string
	GetReportFilename() string
	GetExcelRisksFilename() string
	GetExcelTagsFilename() string
	GetJsonRisksFilename() string
	GetJsonTechnicalAssetsFilename() string
	GetJsonStatsFilename() string
	GetJsonOTMFilename() string
	GetReportHTMLFilename() string
	GetReportMarkdownFilename() string
	GetReportLogoImagePath() string
	GetTemplateFilename() string
	GetRiskRulePlugins() []string
	GetSkipRiskRules() []string
	GetExecuteModelMacro() string
	GetFailOn() string
	GetBaseline() string
	GetRiskExcelConfigHideColumns() []string
	GetRiskExcelConfigSortByColumns() []string
	GetRiskExcelConfigWidthOfColumns() map[string]float64
	GetRiskExcelWrapText() bool
	GetRiskExcelShrinkColumnsToFit() bool
	GetRiskExcelColorText() bool
	GetServerMode() bool
	GetServerPort() int
	GetDiagramDPI() int
	GetGraphvizDPI() int
	GetMinGraphvizDPI() int
	GetMaxGraphvizDPI() int
	GetBackupHistoryFilesToKeep() int
	GetAddModelTitle() bool
	GetAddLegend() bool
	GetKeepDiagramSourceFiles() bool
	GetIgnoreOrphanedRiskTracking() bool
	GetSkipDataFlowDiagram() bool
	GetSkipDataAssetDiagram() bool
	GetSkipRisksJSON() bool
	GetSkipTechnicalAssetsJSON() bool
	GetSkipStatsJSON() bool
	GetSkipOTMJSON() bool
	GetSkipRisksExcel() bool
	GetSkipTagsExcel() bool
	GetSkipReportPDF() bool
	GetSkipReportADOC() bool
	GetSkipReportHTML() bool
	GetSkipReportMarkdown() bool
	GetAttractiveness() Attractiveness
	GetReportConfiguration() report.ReportConfiguation
	GetThreagileVersion() string
	GetProgressReporter() types.ProgressReporter
	GetReportConfigurationHideChapters() map[report.ChaptersToShowHide]bool
}
type ConfigSetter interface {
	SetVerbose(verbose bool)
	SetInteractive(interactive bool)
	SetAppFolder(appFolder string)
	SetPluginFolder(pluginFolder string)
	SetOutputFolder(outputFolder string)
	SetServerFolder(serverFolder string)
	SetTempFolder(tempFolder string)
	SetInputFile(inputFile string)
	SetTemplateFilename(templateFilename string)
	SetRiskRulePlugins(riskRulePlugins []string)
	SetSkipRiskRules(skipRiskRules []string)
	SetFailOn(failOn string)
	SetBaseline(baseline string)
	SetServerMode(serverMode bool)
	SetServerPort(serverPort int)
	SetDiagramDPI(diagramDPI int)
	SetIgnoreOrphanedRiskTracking(ignoreOrphanedRiskTracking bool)
}

func (c *Config) Defaults(buildTimestamp string) *Config {
	*c = Config{
		BuildTimestampValue: buildTimestamp,
		VerboseValue:        false,
		InteractiveValue:    false,

		AppFolderValue:    AppDir,
		PluginFolderValue: PluginDir,
		DataFolderValue:   DataDir,
		OutputFolderValue: OutputDir,
		ServerFolderValue: ServerDir,
		TempFolderValue:   TempDir,
		KeyFolderValue:    KeyDir,

		InputFileValue:                   InputFile,
		DataFlowDiagramFilenamePNGValue:  DataFlowDiagramFilenamePNG,
		DataAssetDiagramFilenamePNGValue: DataAssetDiagramFilenamePNG,
		DataFlowDiagramFilenameDOTValue:  DataFlowDiagramFilenameDOT,
		DataAssetDiagramFilenameDOTValue: DataAssetDiagramFilenameDOT,
		ReportFilenameValue:              ReportFilename,
		ExcelRisksFilenameValue:          ExcelRisksFilename,
		ExcelTagsFilenameValue:           ExcelTagsFilename,
		JsonRisksFilenameValue:           JsonRisksFilename,
		JsonTechnicalAssetsFilenameValue: JsonTechnicalAssetsFilename,
		JsonStatsFilenameValue:           JsonStatsFilename,
		JsonOTMFilenameValue:             JsonOTMFilename,
		ReportHTMLFilenameValue:          ReportHTMLFilename,
		ReportMarkdownFilenameValue:      ReportMarkdownFilename,
		TemplateFilenameValue:            TemplateFilename,
		ReportLogoImagePathValue:         ReportLogoImagePath,
		TechnologyFilenameValue:          "",
		HideEmptyChaptersValue:           false,

		RiskRulePluginsValue:   make([]string, 0),
		SkipRiskRulesValue:     make([]string, 0),
		ExecuteModelMacroValue: "",
		FailOnValue:            "",
		BaselineValue:          "",
		RiskExcelValue:         defaultRiskExcelConfig(),

		ServerModeValue:               false,
		DiagramDPIValue:               DefaultDiagramDPI,
		ServerPortValue:               DefaultServerPort,
		GraphvizDPIValue:              DefaultGraphvizDPI,
		MaxGraphvizDPIValue:           MaxGraphvizDPI,
		BackupHistoryFilesToKeepValue: DefaultBackupHistoryFilesToKeep,

		AddModelTitleValue:              false,
		AddLegendValue:                  false,
		KeepDiagramSourceFilesValue:     false,
		IgnoreOrphanedRiskTrackingValue: false,

		AttractivenessValue: defaultAttractiveness(),

		ReportConfigurationValue: report.ReportConfiguation{
			HideChapter: make(map[report.ChaptersToShowHide]bool),
		},
	}

	return c
}

func (c *Config) Load(configFilename string) error {
	if len(configFilename) == 0 {
		return nil
	}

	config, values, readError := readConfigFile(configFilename)
	if readError != nil {
		return readError
	}

	c.Merge(*config, values)

	return c.prepareFolders()
}

func defaultRiskExcelConfig() RiskExcelConfig {
	return RiskExcelConfig{
		HideColumns:        make([]string, 0),
		SortByColumns:      make([]string, 0),
		WidthOfColumns:     make(map[string]float64),
		ShrinkColumnsToFit: true,
		WrapText:           false,
		ColorText:          true,
	}
}

func defaultAttractiveness() Attractiveness {
	return Attractiveness{
		Quantity: 0,
		Confidentiality: AttackerFocus{
			Asset:                 0,
			ProcessedOrStoredData: 0,
			TransferredData:       0,
		},
		Integrity: AttackerFocus{
			Asset:                 0,
			ProcessedOrStoredData: 0,
			TransferredData:       0,
		},
		Availability: AttackerFocus{
			Asset:                 0,
			ProcessedOrStoredData: 0,
			TransferredData:       0,
		},
	}
}

// readConfigFile reads a YAML or JSON config file into a config, and into the values of its keys, which tell
// the keys that the file sets.
func readConfigFile(configFilename string) (*Config, map[string]any, error) {
	data, readError := os.ReadFile(filepath.Clean(configFilename))
	if readError != nil {
		return nil, nil, fmt.Errorf("failed to read config file: %w", readError)
	}

	values := make(map[string]any)
	var config Config

	if strings.HasSuffix(configFilename, ".yaml") {
		parseError := yaml.Unmarshal(data, &values)
		if parseError != nil {
			return nil, nil, fmt.Errorf("failed to parse keys of yaml config file %q: %w", configFilename, parseError)
		}

		unmarshalError := yaml.Unmarshal(data, &config)
		if unmarshalError != nil {
			return nil, nil, fmt.Errorf("failed to parse yaml config file %q: %w", configFilename, unmarshalError)
		}
	} else {
		parseError := json.Unmarshal(data, &values)
		if parseError != nil {
			return nil, nil, fmt.Errorf("failed to parse keys of json config file %q: %w", configFilename, parseError)
		}

		unmarshalError := json.Unmarshal(data, &config)
		if unmarshalError != nil {
			return nil, nil, fmt.Errorf("failed to parse json config file %q: %w", configFilename, unmarshalError)
		}
	}

	return &config, values, nil
}

// prepareFolders cleans the paths of the folders and checks them, or creates them where threagile writes.
func (c *Config) prepareFolders() error {
	errorList := make([]error, 0)
	c.TempFolderValue = c.CleanPath(c.TempFolderValue)
	tempDirError := os.MkdirAll(c.TempFolderValue, 0o700)
	if tempDirError != nil {
		errorList = append(errorList, fmt.Errorf("failed to create temp dir %q: %w", c.TempFolderValue, tempDirError))
	}

	c.OutputFolderValue = c.CleanPath(c.OutputFolderValue)
	outDirError := os.MkdirAll(c.OutputFolderValue, 0o700)
	if outDirError != nil {
		errorList = append(errorList, fmt.Errorf("failed to create output dir %q: %w", c.OutputFolderValue, outDirError))
	}

	// The app folder is optional: the files threagile reads from it are embedded
	// in the binary, and a copy found in the folder only overrides the embedded one.
	c.AppFolderValue = c.CleanPath(c.AppFolderValue)
	appDirError := c.checkOptionalDir(c.AppFolderValue, "app")
	if appDirError != nil {
		errorList = append(errorList, appDirError)
	}

	c.PluginFolderValue = c.CleanPath(c.PluginFolderValue)
	pluginDirError := c.checkDir(c.PluginFolderValue, "plugin")
	if pluginDirError != nil {
		errorList = append(errorList, pluginDirError)
	}

	c.DataFolderValue = c.CleanPath(c.DataFolderValue)
	dataDirError := c.checkDir(c.DataFolderValue, "data")
	if dataDirError != nil {
		errorList = append(errorList, dataDirError)
	}

	if c.TechnologyFilenameValue != "" {
		c.TechnologyFilenameValue = c.CleanPath(c.TechnologyFilenameValue)
	}

	serverFolderError := c.CheckServerFolder()
	if serverFolderError != nil {
		errorList = append(errorList, serverFolderError)
	}

	if len(errorList) > 0 {
		return errors.Join(errorList...)
	}

	return nil
}

func (c *Config) CheckServerFolder() error {
	if c.ServerModeValue {
		c.ServerFolderValue = c.CleanPath(c.ServerFolderValue)
		serverDirError := c.checkDir(c.ServerFolderValue, "server")
		if serverDirError != nil {
			return serverDirError
		}

		keyDir := filepath.Join(c.ServerFolderValue, c.KeyFolderValue)
		keyDirError := os.MkdirAll(keyDir, 0o700)
		if keyDirError != nil {
			return fmt.Errorf("failed to create key dir %q: %w", keyDir, keyDirError)
		}
	}

	return nil
}

func (c *Config) Merge(config Config, values map[string]any) {
	for key := range values {
		merge, ok := configMergers[strings.ToLower(key)]
		if ok {
			merge(c, &config, values[key])
		}
	}
}

// configMergers merge a key of a config file into the config, keyed by the lower-cased key; they get the
// parsed config file and the raw value of the key.
var configMergers = lowerCaseKeys(map[string]func(c *Config, config *Config, value any){
	"BuildTimestamp": func(c *Config, config *Config, _ any) {
		c.BuildTimestampValue = config.BuildTimestampValue
	},
	"Verbose": func(c *Config, config *Config, _ any) {
		c.VerboseValue = config.VerboseValue
	},
	"Interactive": func(c *Config, config *Config, _ any) {
		c.InteractiveValue = config.InteractiveValue
	},
	"AppFolder": func(c *Config, config *Config, _ any) {
		c.AppFolderValue = config.AppFolderValue
	},
	"PluginFolder": func(c *Config, config *Config, _ any) {
		c.PluginFolderValue = config.PluginFolderValue
	},
	"DataFolder": func(c *Config, config *Config, _ any) {
		c.DataFolderValue = config.DataFolderValue
	},
	"OutputFolder": func(c *Config, config *Config, _ any) {
		c.OutputFolderValue = config.OutputFolderValue
	},
	"ServerFolder": func(c *Config, config *Config, _ any) {
		c.ServerFolderValue = config.ServerFolderValue
	},
	"TempFolder": func(c *Config, config *Config, _ any) {
		c.TempFolderValue = config.TempFolderValue
	},
	"KeyFolder": func(c *Config, config *Config, _ any) {
		c.KeyFolderValue = config.KeyFolderValue
	},
	"InputFile": func(c *Config, config *Config, _ any) {
		c.InputFileValue = config.InputFileValue
	},
	"ImportedInputFile": func(c *Config, config *Config, _ any) {
		c.ImportedInputFileValue = config.ImportedInputFileValue
	},
	"OTMFile": func(c *Config, config *Config, _ any) {
		c.OTMFileValue = config.OTMFileValue
	},
	"DataFlowDiagramFilenamePNG": func(c *Config, config *Config, _ any) {
		c.DataFlowDiagramFilenamePNGValue = config.DataFlowDiagramFilenamePNGValue
	},
	"DataAssetDiagramFilenamePNG": func(c *Config, config *Config, _ any) {
		c.DataAssetDiagramFilenamePNGValue = config.DataAssetDiagramFilenamePNGValue
	},
	"DataFlowDiagramFilenameDOT": func(c *Config, config *Config, _ any) {
		c.DataFlowDiagramFilenameDOTValue = config.DataFlowDiagramFilenameDOTValue
	},
	"DataAssetDiagramFilenameDOT": func(c *Config, config *Config, _ any) {
		c.DataAssetDiagramFilenameDOTValue = config.DataAssetDiagramFilenameDOTValue
	},
	"ReportFilename": func(c *Config, config *Config, _ any) {
		c.ReportFilenameValue = config.ReportFilenameValue
	},
	"ExcelRisksFilename": func(c *Config, config *Config, _ any) {
		c.ExcelRisksFilenameValue = config.ExcelRisksFilenameValue
	},
	"ExcelTagsFilename": func(c *Config, config *Config, _ any) {
		c.ExcelTagsFilenameValue = config.ExcelTagsFilenameValue
	},
	"JsonRisksFilename": func(c *Config, config *Config, _ any) {
		c.JsonRisksFilenameValue = config.JsonRisksFilenameValue
	},
	"JsonTechnicalAssetsFilename": func(c *Config, config *Config, _ any) {
		c.JsonTechnicalAssetsFilenameValue = config.JsonTechnicalAssetsFilenameValue
	},
	"JsonStatsFilename": func(c *Config, config *Config, _ any) {
		c.JsonStatsFilenameValue = config.JsonStatsFilenameValue
	},
	"JsonOTMFilename": func(c *Config, config *Config, _ any) {
		c.JsonOTMFilenameValue = config.JsonOTMFilenameValue
	},
	"SkipOTMJSON": func(c *Config, config *Config, _ any) {
		c.SkipOTMJSONValue = config.SkipOTMJSONValue
	},
	"SkipDataFlowDiagram": func(c *Config, config *Config, _ any) {
		c.SkipDataFlowDiagramValue = config.SkipDataFlowDiagramValue
	},
	"SkipDataAssetDiagram": func(c *Config, config *Config, _ any) {
		c.SkipDataAssetDiagramValue = config.SkipDataAssetDiagramValue
	},
	"SkipRisksJSON": func(c *Config, config *Config, _ any) {
		c.SkipRisksJSONValue = config.SkipRisksJSONValue
	},
	"SkipTechnicalAssetsJSON": func(c *Config, config *Config, _ any) {
		c.SkipTechnicalAssetsJSONValue = config.SkipTechnicalAssetsJSONValue
	},
	"SkipStatsJSON": func(c *Config, config *Config, _ any) {
		c.SkipStatsJSONValue = config.SkipStatsJSONValue
	},
	"SkipRisksExcel": func(c *Config, config *Config, _ any) {
		c.SkipRisksExcelValue = config.SkipRisksExcelValue
	},
	"SkipTagsExcel": func(c *Config, config *Config, _ any) {
		c.SkipTagsExcelValue = config.SkipTagsExcelValue
	},
	"SkipReportPDF": func(c *Config, config *Config, _ any) {
		c.SkipReportPDFValue = config.SkipReportPDFValue
	},
	"SkipReportADOC": func(c *Config, config *Config, _ any) {
		c.SkipReportADOCValue = config.SkipReportADOCValue
	},
	"ReportHTMLFilename": func(c *Config, config *Config, _ any) {
		c.ReportHTMLFilenameValue = config.ReportHTMLFilenameValue
	},
	"SkipReportHTML": func(c *Config, config *Config, _ any) {
		c.SkipReportHTMLValue = config.SkipReportHTMLValue
	},
	"ReportMarkdownFilename": func(c *Config, config *Config, _ any) {
		c.ReportMarkdownFilenameValue = config.ReportMarkdownFilenameValue
	},
	"SkipReportMarkdown": func(c *Config, config *Config, _ any) {
		c.SkipReportMarkdownValue = config.SkipReportMarkdownValue
	},
	"TemplateFilename": func(c *Config, config *Config, _ any) {
		c.TemplateFilenameValue = config.TemplateFilenameValue
	},
	"ReportLogoImagePath": func(c *Config, config *Config, _ any) {
		c.ReportLogoImagePathValue = config.ReportLogoImagePathValue
	},
	"TechnologyFilename": func(c *Config, config *Config, _ any) {
		c.TechnologyFilenameValue = config.TechnologyFilenameValue
	},
	"HideEmptyChapters": func(c *Config, config *Config, _ any) {
		c.HideEmptyChaptersValue = config.HideEmptyChaptersValue
	},
	"RiskRulePlugins": func(c *Config, config *Config, _ any) {
		c.RiskRulePluginsValue = config.RiskRulePluginsValue
	},
	"SkipRiskRules": func(c *Config, config *Config, _ any) {
		c.SkipRiskRulesValue = config.SkipRiskRulesValue
	},
	"ExecuteModelMacro": func(c *Config, config *Config, _ any) {
		c.ExecuteModelMacroValue = config.ExecuteModelMacroValue
	},
	"FailOn": func(c *Config, config *Config, _ any) {
		c.FailOnValue = config.FailOnValue
	},
	"Baseline": func(c *Config, config *Config, _ any) {
		c.BaselineValue = config.BaselineValue
	},
	"RiskExcel": func(c *Config, config *Config, value any) {
		c.mergeRiskExcel(config, value)
	},
	"ServerMode": func(c *Config, config *Config, _ any) {
		c.ServerModeValue = config.ServerModeValue
	},
	"DiagramDPI": func(c *Config, config *Config, _ any) {
		c.DiagramDPIValue = config.DiagramDPIValue
	},
	"ServerPort": func(c *Config, config *Config, _ any) {
		c.ServerPortValue = config.ServerPortValue
	},
	"GraphvizDPI": func(c *Config, config *Config, _ any) {
		c.GraphvizDPIValue = config.GraphvizDPIValue
	},
	"MaxGraphvizDPI": func(c *Config, config *Config, _ any) {
		c.MaxGraphvizDPIValue = config.MaxGraphvizDPIValue
	},
	"BackupHistoryFilesToKeep": func(c *Config, config *Config, _ any) {
		c.BackupHistoryFilesToKeepValue = config.BackupHistoryFilesToKeepValue
	},
	"AddModelTitle": func(c *Config, config *Config, _ any) {
		c.AddModelTitleValue = config.AddModelTitleValue
	},
	"AddLegend": func(c *Config, config *Config, _ any) {
		c.AddLegendValue = config.AddLegendValue
	},
	"KeepDiagramSourceFiles": func(c *Config, config *Config, _ any) {
		c.KeepDiagramSourceFilesValue = config.KeepDiagramSourceFilesValue
	},
	"IgnoreOrphanedRiskTracking": func(c *Config, config *Config, _ any) {
		c.IgnoreOrphanedRiskTrackingValue = config.IgnoreOrphanedRiskTrackingValue
	},
	"Attractiveness": func(c *Config, config *Config, _ any) {
		c.AttractivenessValue = config.AttractivenessValue
	},
	"ReportConfiguration": func(c *Config, config *Config, value any) {
		c.mergeReportConfiguration(config, value)
	},
})

func lowerCaseKeys[V any](byKey map[string]V) map[string]V {
	byLowerCaseKey := make(map[string]V, len(byKey))
	for key, value := range byKey {
		byLowerCaseKey[strings.ToLower(key)] = value
	}
	return byLowerCaseKey
}

func (c *Config) mergeRiskExcel(config *Config, value any) {
	configMap, mapOk := value.(map[string]any)
	if !mapOk {
		return
	}

	for valueName := range configMap {
		switch strings.ToLower(valueName) {
		case strings.ToLower("HideColumns"):
			c.RiskExcelValue.HideColumns = append(c.RiskExcelValue.HideColumns, config.RiskExcelValue.HideColumns...)

		case strings.ToLower("SortByColumns"):
			c.RiskExcelValue.SortByColumns = append(c.RiskExcelValue.SortByColumns, config.RiskExcelValue.SortByColumns...)

		case strings.ToLower("WidthOfColumns"):
			if c.RiskExcelValue.WidthOfColumns == nil {
				c.RiskExcelValue.WidthOfColumns = make(map[string]float64)
			}

			maps.Copy(c.RiskExcelValue.WidthOfColumns, config.RiskExcelValue.WidthOfColumns)

		case strings.ToLower("ShrinkColumnsToFit"):
			c.RiskExcelValue.ShrinkColumnsToFit = config.RiskExcelValue.ShrinkColumnsToFit

		case strings.ToLower("WrapText"):
			c.RiskExcelValue.WrapText = config.RiskExcelValue.WrapText

		case strings.ToLower("ColorText"):
			c.RiskExcelValue.ColorText = config.RiskExcelValue.ColorText
		}
	}
}

func (c *Config) mergeReportConfiguration(config *Config, value any) {
	configMap, mapOk := value.(map[string]any)
	if !mapOk {
		return
	}

	for valueName := range configMap {
		if strings.ToLower(valueName) != "hidechapter" {
			continue
		}

		if c.ReportConfigurationValue.HideChapter == nil {
			c.ReportConfigurationValue.HideChapter = make(map[report.ChaptersToShowHide]bool)
		}

		for chapter, value := range config.ReportConfigurationValue.HideChapter {
			c.ReportConfigurationValue.HideChapter[chapter] = value
			if value {
				log.Println("Hiding chapter: ", chapter)
			}
		}
	}
}

func (c *Config) CleanPath(path string) string {
	return filepath.Clean(c.ExpandPath(path))
}

func (c *Config) checkDir(dir string, name string) error {
	dirInfo, dirError := os.Stat(dir)
	if dirError != nil {
		return fmt.Errorf("%v folder %q not good: %w", name, dir, dirError)
	}

	if !dirInfo.IsDir() {
		return fmt.Errorf("%v folder %q is not a folder", name, dir)
	}

	return nil
}

// checkOptionalDir is checkDir for a folder that may be missing.
func (c *Config) checkOptionalDir(dir string, name string) error {
	_, statError := os.Stat(dir)
	if errors.Is(statError, fs.ErrNotExist) {
		return nil
	}

	return c.checkDir(dir, name)
}

func (c *Config) ExpandPath(path string) string {
	home := c.UserHomeDir()
	if strings.HasPrefix(path, "~") {
		path = strings.Replace(path, "~", home, 1)
	}

	if strings.HasPrefix(path, "$HOME") {
		path = strings.ReplaceAll(path, "$HOME", home)
	}

	return path
}

func (c *Config) UserHomeDir() string {
	switch runtime.GOOS {
	case "windows":
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home

	default:
		return os.Getenv("HOME")
	}
}

func (c *Config) GetBuildTimestamp() string {
	return c.BuildTimestampValue
}

func (c *Config) GetVerbose() bool {
	return c.VerboseValue
}

func (c *Config) SetVerbose(verbose bool) {
	c.VerboseValue = verbose
}

func (c *Config) GetInteractive() bool {
	return c.InteractiveValue
}

func (c *Config) SetInteractive(interactive bool) {
	c.InteractiveValue = interactive
}

func (c *Config) GetAppFolder() string {
	return c.AppFolderValue
}

func (c *Config) SetAppFolder(appFolder string) {
	c.AppFolderValue = appFolder
}

func (c *Config) GetPluginFolder() string {
	return c.PluginFolderValue
}

func (c *Config) SetPluginFolder(pluginFolder string) {
	c.PluginFolderValue = pluginFolder
}

func (c *Config) GetDataFolder() string {
	return c.DataFolderValue
}

func (c *Config) GetOutputFolder() string {
	return c.OutputFolderValue
}

func (c *Config) SetOutputFolder(outputFolder string) {
	c.OutputFolderValue = outputFolder
}

func (c *Config) GetServerFolder() string {
	return c.ServerFolderValue
}

func (c *Config) SetServerFolder(serverFolder string) {
	c.ServerFolderValue = serverFolder
}

func (c *Config) GetTempFolder() string {
	return c.TempFolderValue
}

func (c *Config) SetTempFolder(tempFolder string) {
	c.TempFolderValue = tempFolder
}

func (c *Config) GetKeyFolder() string {
	return c.KeyFolderValue
}

func (c *Config) GetTechnologyFilename() string {
	return c.TechnologyFilenameValue
}

func (c *Config) GetHideEmptyChapters() bool {
	return c.HideEmptyChaptersValue
}

func (c *Config) GetInputFile() string {
	return c.InputFileValue
}

func (c *Config) SetInputFile(inputFile string) {
	c.InputFileValue = inputFile
}

func (c *Config) GetImportedInputFile() string {
	return c.ImportedInputFileValue
}

func (c *Config) GetOTMFile() string {
	return c.OTMFileValue
}

func (c *Config) SetImportedInputFile(inputFile string) {
	c.ImportedInputFileValue = inputFile
}

func (c *Config) GetDataFlowDiagramFilenamePNG() string {
	return c.DataFlowDiagramFilenamePNGValue
}

func (c *Config) GetDataAssetDiagramFilenamePNG() string {
	return c.DataAssetDiagramFilenamePNGValue
}

func (c *Config) GetDataFlowDiagramFilenameDOT() string {
	return c.DataFlowDiagramFilenameDOTValue
}

func (c *Config) GetDataAssetDiagramFilenameDOT() string {
	return c.DataAssetDiagramFilenameDOTValue
}

func (c *Config) GetReportFilename() string {
	return c.ReportFilenameValue
}

func (c *Config) GetReportHTMLFilename() string {
	return c.ReportHTMLFilenameValue
}

func (c *Config) GetReportMarkdownFilename() string {
	return c.ReportMarkdownFilenameValue
}

func (c *Config) GetExcelRisksFilename() string {
	return c.ExcelRisksFilenameValue
}

func (c *Config) GetExcelTagsFilename() string {
	return c.ExcelTagsFilenameValue
}

func (c *Config) GetJsonRisksFilename() string {
	return c.JsonRisksFilenameValue
}

func (c *Config) GetJsonTechnicalAssetsFilename() string {
	return c.JsonTechnicalAssetsFilenameValue
}

func (c *Config) GetJsonStatsFilename() string {
	return c.JsonStatsFilenameValue
}

func (c *Config) GetJsonOTMFilename() string {
	return c.JsonOTMFilenameValue
}

func (c *Config) GetReportLogoImagePath() string {
	return c.ReportLogoImagePathValue
}

func (c *Config) GetTemplateFilename() string {
	return c.TemplateFilenameValue
}

func (c *Config) SetTemplateFilename(templateFilename string) {
	c.TemplateFilenameValue = templateFilename
}

func (c *Config) GetRiskRulePlugins() []string {
	return c.RiskRulePluginsValue
}

func (c *Config) SetRiskRulePlugins(riskRulePlugins []string) {
	c.RiskRulePluginsValue = riskRulePlugins
}

func (c *Config) GetSkipRiskRules() []string {
	return c.SkipRiskRulesValue
}

func (c *Config) SetSkipRiskRules(skipRiskRules []string) {
	c.SkipRiskRulesValue = skipRiskRules
}

func (c *Config) GetFailOn() string {
	return c.FailOnValue
}

func (c *Config) SetFailOn(failOn string) {
	c.FailOnValue = failOn
}

func (c *Config) GetBaseline() string {
	return c.BaselineValue
}

func (c *Config) SetBaseline(baseline string) {
	c.BaselineValue = baseline
}

func (c *Config) GetExecuteModelMacro() string {
	return c.ExecuteModelMacroValue
}

func (c *Config) GetRiskExcelConfigHideColumns() []string {
	return c.RiskExcelValue.HideColumns
}

func (c *Config) GetRiskExcelConfigSortByColumns() []string {
	return c.RiskExcelValue.SortByColumns
}

func (c *Config) GetRiskExcelConfigWidthOfColumns() map[string]float64 {
	return c.RiskExcelValue.WidthOfColumns
}

func (c *Config) GetRiskExcelWrapText() bool {
	return c.RiskExcelValue.WrapText
}

func (c *Config) GetRiskExcelShrinkColumnsToFit() bool {
	return c.RiskExcelValue.ShrinkColumnsToFit
}

func (c *Config) GetRiskExcelColorText() bool {
	return c.RiskExcelValue.ColorText
}

func (c *Config) GetServerMode() bool {
	return c.ServerModeValue
}

func (c *Config) SetServerMode(serverMode bool) {
	c.ServerModeValue = serverMode
}

func (c *Config) GetServerPort() int {
	return c.ServerPortValue
}

func (c *Config) SetServerPort(serverPort int) {
	c.ServerPortValue = serverPort
}

func (c *Config) GetDiagramDPI() int {
	return c.DiagramDPIValue
}

func (c *Config) SetDiagramDPI(diagramDPI int) {
	c.DiagramDPIValue = diagramDPI
}

func (c *Config) GetGraphvizDPI() int {
	return c.GraphvizDPIValue
}

func (c *Config) GetMinGraphvizDPI() int {
	return MinGraphvizDPI
}

func (c *Config) GetMaxGraphvizDPI() int {
	return c.MaxGraphvizDPIValue
}

func (c *Config) GetBackupHistoryFilesToKeep() int {
	return c.BackupHistoryFilesToKeepValue
}

func (c *Config) GetAddModelTitle() bool {
	return c.AddModelTitleValue
}

func (c *Config) GetAddLegend() bool {
	return c.AddLegendValue
}

func (c *Config) GetKeepDiagramSourceFiles() bool {
	return c.KeepDiagramSourceFilesValue
}

func (c *Config) GetIgnoreOrphanedRiskTracking() bool {
	return c.IgnoreOrphanedRiskTrackingValue
}

func (c *Config) SetIgnoreOrphanedRiskTracking(ignoreOrphanedRiskTracking bool) {
	c.IgnoreOrphanedRiskTrackingValue = ignoreOrphanedRiskTracking
}

func (c *Config) GetSkipDataFlowDiagram() bool {
	return c.SkipDataFlowDiagramValue
}

func (c *Config) GetSkipDataAssetDiagram() bool {
	return c.SkipDataAssetDiagramValue
}

func (c *Config) GetSkipRisksJSON() bool {
	return c.SkipRisksJSONValue
}

func (c *Config) GetSkipTechnicalAssetsJSON() bool {
	return c.SkipTechnicalAssetsJSONValue
}

func (c *Config) GetSkipStatsJSON() bool {
	return c.SkipStatsJSONValue
}

func (c *Config) GetSkipOTMJSON() bool {
	return c.SkipOTMJSONValue
}

func (c *Config) GetSkipRisksExcel() bool {
	return c.SkipRisksExcelValue
}

func (c *Config) GetSkipTagsExcel() bool {
	return c.SkipTagsExcelValue
}

func (c *Config) GetSkipReportPDF() bool {
	return c.SkipReportPDFValue
}

func (c *Config) GetSkipReportADOC() bool {
	return c.SkipReportADOCValue
}

func (c *Config) GetSkipReportHTML() bool {
	return c.SkipReportHTMLValue
}

func (c *Config) GetSkipReportMarkdown() bool {
	return c.SkipReportMarkdownValue
}

func (c *Config) GetAttractiveness() Attractiveness {
	return c.AttractivenessValue
}

func (c *Config) GetReportConfiguration() report.ReportConfiguation {
	return c.ReportConfigurationValue
}

func (c *Config) GetThreagileVersion() string {
	return ThreagileVersion
}

func (c *Config) GetProgressReporter() types.ProgressReporter {
	return DefaultProgressReporter{Verbose: c.VerboseValue}
}

func (c *Config) GetReportConfigurationHideChapters() map[report.ChaptersToShowHide]bool {
	return c.ReportConfigurationValue.HideChapter
}
