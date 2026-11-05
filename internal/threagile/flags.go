/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package threagile

const (
	configFlagName = "config"

	verboseFlagName      = "verbose"
	verboseFlagShorthand = "v"

	interactiveFlagName      = "interactive"
	interactiveFlagShorthand = "i"

	appDirFlagName    = "app-dir"
	pluginDirFlagName = "plugin-dir"
	dataDirFlagName   = "data-dir"
	outputFlagName    = "output"
	serverDirFlagName = "server-dir"
	tempDirFlagName   = "temp-dir"
	keyDirFlagName    = "key-dir"

	inputFileFlagName               = "model"
	importedFileFlagName            = "imported-model"
	otmFileFlagName                 = "otm"
	dataFlowDiagramPNGFileFlagName  = "data-flow-diagram-png"
	dataAssetDiagramPNGFileFlagName = "data-asset-diagram-png"
	dataFlowDiagramDOTFileFlagName  = "data-flow-diagram-dot"
	dataAssetDiagramDOTFileFlagName = "data-asset-diagram-dot"
	reportFileFlagName              = "report"
	risksExcelFileFlagName          = "risks-excel"
	tagsExcelFileFlagName           = "tags-excel"
	risksJsonFileFlagName           = "risks-json"
	technicalAssetsJsonFileFlagName = "technical-assets-json"
	statsJsonFileFlagName           = "stats-json"
	otmJsonFileFlagName             = "otm-json"
	reportHTMLFileFlagName          = "report-html"
	reportMarkdownFileFlagName      = "report-md"
	templateFileNameFlagName        = "background"
	reportLogoImagePathFlagName     = "reportLogoImagePath"
	technologyFileFlagName          = "technology"

	customRiskRulesPluginFlagName = "custom-risk-rules-plugin"
	skipRiskRulesFlagName         = "skip-risk-rules"
	executeModelMacroFlagName     = "execute-model-macro"
	failOnFlagName                = "fail-on"
	baselineFlagName              = "baseline"

	serverModeFlagName               = "server-mode"
	serverPortFlagName               = "server-port"
	diagramDpiFlagName               = "diagram-dpi"
	graphvizDpiFlagName              = "graphviz-dpi"
	backupHistoryFilesToKeepFlagName = "backup-history-files-to-keep"

	addModelTitleFlagName              = "add-model-title"
	keepDiagramSourceFilesFlagName     = "keep-diagram-source-files"
	ignoreOrphanedRiskTrackingFlagName = "ignore-orphaned-risk-tracking"

	skipDataFlowDiagramFlagName     = "skip-data-flow-diagram"
	skipDataAssetDiagramFlagName    = "skip-data-asset-diagram"
	skipRisksJSONFlagName           = "skip-risks-json"
	skipTechnicalAssetsJSONFlagName = "skip-technical-assets-json"
	skipStatsJSONFlagName           = "skip-stats-json"
	skipOTMJSONFlagName             = "skip-otm-json"
	skipRisksExcelFlagName          = "skip-risks-excel"
	skipTagsExcelFlagName           = "skip-tags-excel"
	skipReportPDFFlagName           = "skip-report-pdf"
	skipReportADOCFlagName          = "skip-report-adoc"
	skipReportHTMLFlagName          = "skip-report-html"
	skipReportMarkdownFlagName      = "skip-report-md"

	generateDataFlowDiagramFlagName     = "generate-data-flow-diagram"
	generateDataAssetDiagramFlagName    = "generate-data-asset-diagram"
	generateRisksJSONFlagName           = "generate-risks-json"
	generateTechnicalAssetsJSONFlagName = "generate-technical-assets-json"
	generateStatsJSONFlagName           = "generate-stats-json"
	generateRisksExcelFlagName          = "generate-risks-excel"
	generateTagsExcelFlagName           = "generate-tags-excel"
	generateReportPDFFlagName           = "generate-report-pdf"
	generateReportADOCFlagName          = "generate-report-adoc"
)

type Flags struct {
	Config

	configFlag           string
	riskRulePluginsValue string
	skipRiskRulesValue   string

	generateDataFlowDiagramFlag     bool // deprecated
	generateDataAssetDiagramFlag    bool // deprecated
	generateRisksJSONFlag           bool // deprecated
	generateTechnicalAssetsJSONFlag bool // deprecated
	generateStatsJSONFlag           bool // deprecated
	generateRisksExcelFlag          bool // deprecated
	generateTagsExcelFlag           bool // deprecated
	generateReportPDFFlag           bool // deprecated
	generateReportADOCFlag          bool // deprecated
}
