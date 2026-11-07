package report

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/Pinguladora/threagile/pkg/model"
	"github.com/Pinguladora/threagile/pkg/types"
)

type GenerateCommands struct {
	DataFlowDiagram     bool
	DataAssetDiagram    bool
	RisksJSON           bool
	TechnicalAssetsJSON bool
	StatsJSON           bool
	OTMJSON             bool
	RisksExcel          bool
	TagsExcel           bool
	ReportPDF           bool
	ReportHTML          bool
	ReportMarkdown      bool
}

func (c *GenerateCommands) Defaults() *GenerateCommands {
	*c = GenerateCommands{
		DataFlowDiagram:     true,
		DataAssetDiagram:    true,
		RisksJSON:           true,
		TechnicalAssetsJSON: true,
		StatsJSON:           true,
		OTMJSON:             true,
		RisksExcel:          true,
		TagsExcel:           true,
		ReportPDF:           true,
		ReportHTML:          true,
		ReportMarkdown:      true,
	}
	return c
}

// reportConfigReader is the part of the configuration that the report writers read.
type reportConfigReader interface {
	GetBuildTimestamp() string
	GetThreagileVersion() string

	GetAppFolder() string
	GetOutputFolder() string
	GetTempFolder() string

	GetInputFile() string
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
	GetTemplateFilename() string
	GetReportLogoImagePath() string

	GetSkipRiskRules() []string
	GetRiskExcelConfigHideColumns() []string
	GetRiskExcelConfigSortByColumns() []string
	GetRiskExcelConfigWidthOfColumns() map[string]float64
	GetRiskExcelWrapText() bool
	GetRiskExcelShrinkColumnsToFit() bool
	GetRiskExcelColorText() bool

	GetDiagramDPI() int
	GetMinGraphvizDPI() int
	GetMaxGraphvizDPI() int

	GetKeepDiagramSourceFiles() bool
	GetAddModelTitle() bool
	GetAddLegend() bool
	GetReportConfigurationHideChapters() map[ChaptersToShowHide]bool

	GetHideEmptyChapters() bool
}

func Generate(config reportConfigReader, readResult *model.ReadResult, commands *GenerateCommands,
	riskRules types.RiskRules, progressReporter progressReporter,
) error {
	_ = os.MkdirAll(filepath.Clean(config.GetOutputFolder()), 0o750)
	_ = os.MkdirAll(filepath.Clean(config.GetTempFolder()), 0o700)

	diagramDPI := config.GetDiagramDPI()
	if diagramDPI < config.GetMinGraphvizDPI() {
		diagramDPI = config.GetMinGraphvizDPI()
	} else if diagramDPI > config.GetMaxGraphvizDPI() {
		diagramDPI = config.GetMaxGraphvizDPI()
	}
	// Data-flow Diagram rendering
	if commands.DataFlowDiagram {
		writeDOT := func(filename string) (*os.File, error) {
			return WriteDataFlowDiagramGraphvizDOT(readResult.ParsedModel, filename, diagramDPI,
				config.GetAddModelTitle(), config.GetAddLegend(), progressReporter)
		}
		removeDOT, err := renderDiagram(config, "data flow", config.GetDataFlowDiagramFilenameDOT(),
			config.GetDataFlowDiagramFilenamePNG(), writeDOT, GenerateDataFlowDiagramGraphvizImage, progressReporter)
		defer removeDOT()
		if err != nil {
			return err
		}
	}
	// Data Asset Diagram rendering
	if commands.DataAssetDiagram {
		writeDOT := func(filename string) (*os.File, error) {
			return WriteDataAssetDiagramGraphvizDOT(readResult.ParsedModel, filename, diagramDPI, progressReporter)
		}
		removeDOT, err := renderDiagram(config, "data asset", config.GetDataAssetDiagramFilenameDOT(),
			config.GetDataAssetDiagramFilenamePNG(), writeDOT, GenerateDataAssetDiagramGraphvizImage, progressReporter)
		defer removeDOT()
		if err != nil {
			return err
		}
	}

	if err := writeJSONOutputs(config, readResult, commands, progressReporter); err != nil {
		return err
	}
	if err := writeExcelOutputs(config, readResult, commands, progressReporter); err != nil {
		return err
	}
	return writeReports(config, readResult, commands, riskRules, diagramDPI, progressReporter)
}

// renderDiagram writes the DOT source of a diagram and renders it to PNG, only warning when the
// rendering fails. Unless the DOT source is to be kept, it goes into a temporary file, which the
// returned function removes. The returned function is never nil.
func renderDiagram(config reportConfigReader, name string, filenameDOT string, filenamePNG string,
	writeDOT func(filename string) (*os.File, error),
	renderPNG func(dotFile *os.File, targetDir string, filenamePNG string, progressReporter progressReporter) error,
	progressReporter progressReporter,
) (func(), error) {
	removeDOT := func() {}
	gvFile := filepath.Join(config.GetOutputFolder(), filenameDOT)
	if !config.GetKeepDiagramSourceFiles() {
		tmpFile, err := os.CreateTemp(config.GetTempFolder(), filenameDOT)
		if err != nil {
			return removeDOT, fmt.Errorf("unable to create a temporary %s diagram file: %w", name, err)
		}
		gvFile = tmpFile.Name()
		removeDOT = func() { _ = os.Remove(gvFile) }
	}
	dotFile, err := writeDOT(gvFile)
	if err != nil {
		return removeDOT, fmt.Errorf("error while generating %s diagram: %w", name, err)
	}

	err = renderPNG(dotFile, config.GetOutputFolder(), filenamePNG, progressReporter)
	if err != nil {
		progressReporter.Warn(err)
	}
	return removeDOT, nil
}

// writeJSONOutputs writes the JSON outputs that are asked for.
func writeJSONOutputs(config reportConfigReader, readResult *model.ReadResult, commands *GenerateCommands,
	progressReporter progressReporter,
) error {
	outputFile := func(filename string) string { return filepath.Join(config.GetOutputFolder(), filename) }

	// risks as risks json
	if commands.RisksJSON {
		progressReporter.Info("Writing risks json")
		err := WriteRisksJSON(readResult.ParsedModel, outputFile(config.GetJsonRisksFilename()))
		if err != nil {
			return fmt.Errorf("error while writing risks json: %w", err)
		}
	}

	// technical assets json
	if commands.TechnicalAssetsJSON {
		progressReporter.Info("Writing technical assets json")
		err := WriteTechnicalAssetsJSON(readResult.ParsedModel, outputFile(config.GetJsonTechnicalAssetsFilename()))
		if err != nil {
			return fmt.Errorf("error while writing technical assets json: %w", err)
		}
	}

	// risks as risks json
	if commands.StatsJSON {
		progressReporter.Info("Writing stats json")
		err := WriteStatsJSON(readResult.ParsedModel, outputFile(config.GetJsonStatsFilename()))
		if err != nil {
			return fmt.Errorf("error while writing stats json: %w", err)
		}
	}

	// the model with its risks as an Open Threat Model
	if commands.OTMJSON {
		progressReporter.Info("Writing otm json")
		err := WriteOTMJSON(readResult.ParsedModel, outputFile(config.GetJsonOTMFilename()))
		if err != nil {
			return fmt.Errorf("error while writing otm json: %w", err)
		}
	}
	return nil
}

// writeExcelOutputs writes the Excel outputs that are asked for.
func writeExcelOutputs(config reportConfigReader, readResult *model.ReadResult, commands *GenerateCommands,
	progressReporter progressReporter,
) error {
	outputFile := func(filename string) string { return filepath.Join(config.GetOutputFolder(), filename) }

	// risks Excel
	if commands.RisksExcel {
		progressReporter.Info("Writing risks excel")
		err := WriteRisksExcelToFile(readResult.ParsedModel, outputFile(config.GetExcelRisksFilename()), config)
		if err != nil {
			return err
		}
	}

	// tags Excel
	if commands.TagsExcel {
		progressReporter.Info("Writing tags excel")
		err := WriteTagsExcelToFile(readResult.ParsedModel, outputFile(config.GetExcelTagsFilename()), config)
		if err != nil {
			return err
		}
	}
	return nil
}

// writeReports writes the PDF, HTML and Markdown reports that are asked for.
func writeReports(config reportConfigReader, readResult *model.ReadResult, commands *GenerateCommands,
	riskRules types.RiskRules, diagramDPI int, progressReporter progressReporter,
) error {
	if commands.ReportPDF {
		err := writeReportPDF(config, readResult, riskRules, progressReporter)
		if err != nil {
			return err
		}
	}

	if commands.ReportHTML {
		progressReporter.Info("Writing report html")
		err := writeReportHTML(config, readResult, riskRules, diagramDPI, progressReporter)
		if err != nil {
			return err
		}
	}

	if commands.ReportMarkdown {
		progressReporter.Info("Writing report markdown")
		err := writeReportMarkdown(config, readResult, riskRules)
		if err != nil {
			return err
		}
	}
	return nil
}

// writeReportPDF writes the PDF report, rendered by typst; without typst it only warns that it leaves the report out.
// Like the HTML report, it renders the diagrams from DOT sources of its own.
func writeReportPDF(config reportConfigReader, readResult *model.ReadResult, riskRules types.RiskRules,
	progressReporter progressReporter,
) error {
	// the diagrams are vector graphics in the PDF, drawn at 72 dpi, so that Graphviz does not scale them to a DPI
	const diagramDPI = 72
	modelHash, err := hashFile(config.GetInputFile())
	if err != nil {
		return err
	}
	progressReporter.Info("Writing report pdf")
	if config.GetTemplateFilename() != DefaultTemplateFilename {
		progressReporter.Warn("--background is ignored: the PDF report, rendered by typst, has no background template")
	}
	writeDataFlowDOT := func(filename string) (*os.File, error) {
		return WriteDataFlowDiagramGraphvizDOT(readResult.ParsedModel, filename, diagramDPI,
			config.GetAddModelTitle(), config.GetAddLegend(), progressReporter)
	}
	dataFlowDOT, err := diagramDOT(config.GetTempFolder(), config.GetDataFlowDiagramFilenameDOT(), writeDataFlowDOT)
	if err != nil {
		return fmt.Errorf("error while generating data flow diagram: %w", err)
	}
	writeDataAssetDOT := func(filename string) (*os.File, error) {
		return WriteDataAssetDiagramGraphvizDOT(readResult.ParsedModel, filename, diagramDPI, progressReporter)
	}
	dataAssetDOT, err := diagramDOT(config.GetTempFolder(), config.GetDataAssetDiagramFilenameDOT(), writeDataAssetDOT)
	if err != nil {
		return fmt.Errorf("error while generating data asset diagram: %w", err)
	}

	logo, err := reportLogo(config.GetReportLogoImagePath())
	if err != nil {
		return err
	}
	logoExtension := filepath.Ext(config.GetReportLogoImagePath())
	if logoExtension == "" {
		logoExtension = ".png"
	}

	err = WriteReportPDF(readResult.ParsedModel, filepath.Join(config.GetOutputFolder(), config.GetReportFilename()),
		PDFReportOptions{
			ReportOptions:       reportOptions(config, readResult, riskRules, modelHash),
			DataFlowDiagramDOT:  dataFlowDOT,
			DataAssetDiagramDOT: dataAssetDOT,
			Logo:                logo,
			LogoExtension:       logoExtension,
			TempFolder:          config.GetTempFolder(),
		}, progressReporter)
	if errors.Is(err, ErrTypstMissing) {
		progressReporter.Warn(err.Error() + "; the PDF report is left out")
		return nil
	}
	return err
}

// writeReportHTML writes the HTML report. It renders the diagrams from DOT sources of its own, as
// the diagram outputs may be skipped, but the same as theirs.
func writeReportHTML(config reportConfigReader, readResult *model.ReadResult, riskRules types.RiskRules, diagramDPI int,
	progressReporter progressReporter,
) error {
	modelHash, err := hashFile(config.GetInputFile())
	if err != nil {
		return err
	}
	writeDataFlowDOT := func(filename string) (*os.File, error) {
		return WriteDataFlowDiagramGraphvizDOT(readResult.ParsedModel, filename, diagramDPI,
			config.GetAddModelTitle(), config.GetAddLegend(), progressReporter)
	}
	dataFlowDOT, err := diagramDOT(config.GetTempFolder(), config.GetDataFlowDiagramFilenameDOT(), writeDataFlowDOT)
	if err != nil {
		return fmt.Errorf("error while generating data flow diagram: %w", err)
	}
	writeDataAssetDOT := func(filename string) (*os.File, error) {
		return WriteDataAssetDiagramGraphvizDOT(readResult.ParsedModel, filename, diagramDPI, progressReporter)
	}
	dataAssetDOT, err := diagramDOT(config.GetTempFolder(), config.GetDataAssetDiagramFilenameDOT(), writeDataAssetDOT)
	if err != nil {
		return fmt.Errorf("error while generating data asset diagram: %w", err)
	}

	return WriteReportHTML(readResult.ParsedModel, filepath.Join(config.GetOutputFolder(), config.GetReportHTMLFilename()),
		HTMLReportOptions{
			ReportOptions:       reportOptions(config, readResult, riskRules, modelHash),
			DataFlowDiagramDOT:  dataFlowDOT,
			DataAssetDiagramDOT: dataAssetDOT,
		}, progressReporter)
}

// reportOptions are the inputs of the HTML and Markdown reports besides the model.
func reportOptions(config reportConfigReader, readResult *model.ReadResult, riskRules types.RiskRules,
	modelHash string,
) ReportOptions {
	return ReportOptions{
		ModelFilename:     config.GetInputFile(),
		ModelHash:         modelHash,
		BuildTimestamp:    config.GetBuildTimestamp(),
		ThreagileVersion:  config.GetThreagileVersion(),
		IntroTextRAA:      readResult.IntroTextRAA,
		SkipRiskRules:     config.GetSkipRiskRules(),
		RiskRules:         riskRules,
		CustomRiskRules:   readResult.CustomRiskRules,
		HideChapters:      config.GetReportConfigurationHideChapters(),
		HideEmptyChapters: config.GetHideEmptyChapters(),
		Baseline:          readResult.Baseline,
	}
}

// writeReportMarkdown writes the Markdown report, whose diagrams are Mermaid code drawn from the model.
func writeReportMarkdown(config reportConfigReader, readResult *model.ReadResult, riskRules types.RiskRules) error {
	modelHash, err := hashFile(config.GetInputFile())
	if err != nil {
		return err
	}
	return WriteReportMarkdown(readResult.ParsedModel,
		filepath.Join(config.GetOutputFolder(), config.GetReportMarkdownFilename()),
		reportOptions(config, readResult, riskRules, modelHash))
}

// diagramDOT writes the DOT source of a diagram into a temporary file and returns it.
func diagramDOT(tempFolder, name string, write func(filename string) (*os.File, error)) ([]byte, error) {
	file, err := os.CreateTemp(tempFolder, name)
	if err != nil {
		return nil, fmt.Errorf("error creating a temporary file: %w", err)
	}
	_ = file.Close()
	defer func() { _ = os.Remove(file.Name()) }()

	if _, err := write(file.Name()); err != nil {
		return nil, err
	}
	dot, err := os.ReadFile(file.Name())
	if err != nil {
		return nil, fmt.Errorf("error reading %s: %w", file.Name(), err)
	}
	return dot, nil
}

// hashFile is the SHA-256 hash of a file in hex, as the reports show it for the model.
func hashFile(filename string) (string, error) {
	file, err := os.Open(filepath.Clean(filename))
	if err != nil {
		return "", fmt.Errorf("error opening %s: %w", filename, err)
	}
	defer func() { _ = file.Close() }()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("error reading %s: %w", filename, err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

type progressReporter interface {
	Info(a ...any)
	Warn(a ...any)
	Error(a ...any)
}

func contains(a []string, x string) bool {
	return slices.Contains(a, x)
}
