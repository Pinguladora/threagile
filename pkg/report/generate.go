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
	ReportADOC          bool
	ReportHTML          bool
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
		ReportADOC:          true,
		ReportHTML:          true,
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

	generateDataFlowDiagram, generateDataAssetsDiagram := diagramsToGenerate(config, commands, progressReporter)

	diagramDPI := config.GetDiagramDPI()
	if diagramDPI < config.GetMinGraphvizDPI() {
		diagramDPI = config.GetMinGraphvizDPI()
	} else if diagramDPI > config.GetMaxGraphvizDPI() {
		diagramDPI = config.GetMaxGraphvizDPI()
	}
	// Data-flow Diagram rendering
	if generateDataFlowDiagram {
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
	if generateDataAssetsDiagram {
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

// diagramsToGenerate returns whether to generate the data-flow and the data asset diagram: when
// asked to, or when a PDF or AsciiDoc report needs a diagram that does not exist yet.
func diagramsToGenerate(config reportConfigReader, commands *GenerateCommands,
	progressReporter progressReporter,
) (generateDataFlowDiagram bool, generateDataAssetsDiagram bool) {
	generateDataFlowDiagram = commands.DataFlowDiagram
	generateDataAssetsDiagram = commands.DataAssetDiagram

	if commands.ReportPDF || commands.ReportADOC { // as the PDF report includes both diagrams
		if !generateDataFlowDiagram {
			dataFlowFile := filepath.Join(config.GetOutputFolder(), config.GetDataFlowDiagramFilenamePNG())
			if _, err := os.Stat(dataFlowFile); errors.Is(err, os.ErrNotExist) {
				progressReporter.Warn("Forcibly create the needed Data-Flow Diagram file to enable report generation.")
				generateDataFlowDiagram = true
			}
		}
		if !generateDataAssetsDiagram {
			dataAssetFile := filepath.Join(config.GetOutputFolder(), config.GetDataAssetDiagramFilenamePNG())
			if _, err := os.Stat(dataAssetFile); errors.Is(err, os.ErrNotExist) {
				progressReporter.Warn("Forcibly create the needed Data-Asset Diagram file to enable report generation.")
				generateDataAssetsDiagram = true
			}
		}
	}
	return generateDataFlowDiagram, generateDataAssetsDiagram
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

// writeReports writes the PDF, AsciiDoc and HTML reports that are asked for.
func writeReports(config reportConfigReader, readResult *model.ReadResult, commands *GenerateCommands,
	riskRules types.RiskRules, diagramDPI int, progressReporter progressReporter,
) error {
	if commands.ReportPDF {
		err := writeReportPDF(config, readResult, riskRules, progressReporter)
		if err != nil {
			return err
		}
	}

	if commands.ReportADOC {
		err := writeReportADOC(config, readResult, riskRules, progressReporter)
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
	return nil
}

// writeReportPDF writes the PDF report.
func writeReportPDF(config reportConfigReader, readResult *model.ReadResult, riskRules types.RiskRules,
	progressReporter progressReporter,
) error {
	modelHash, err := hashFile(config.GetInputFile())
	if err != nil {
		return err
	}
	// report PDF
	progressReporter.Info("Writing report pdf")

	templateFilename, err := backgroundTemplateFile(config.GetAppFolder(), config.GetTemplateFilename())
	if err != nil {
		return err
	}

	pdfReporter := newPdfReporter(riskRules)
	return pdfReporter.WriteReportPDF(filepath.Join(config.GetOutputFolder(), config.GetReportFilename()),
		templateFilename,
		filepath.Join(config.GetOutputFolder(), config.GetDataFlowDiagramFilenamePNG()),
		filepath.Join(config.GetOutputFolder(), config.GetDataAssetDiagramFilenamePNG()),
		config.GetInputFile(),
		config.GetSkipRiskRules(),
		config.GetBuildTimestamp(),
		config.GetThreagileVersion(),
		modelHash,
		readResult.IntroTextRAA,
		readResult.CustomRiskRules,
		config.GetTempFolder(),
		readResult.ParsedModel,
		config.GetReportConfigurationHideChapters())
}

// writeReportADOC writes the AsciiDoc report.
func writeReportADOC(config reportConfigReader, readResult *model.ReadResult, riskRules types.RiskRules,
	progressReporter progressReporter,
) error {
	modelHash, err := hashFile(config.GetInputFile())
	if err != nil {
		return err
	}

	// report ADOC
	progressReporter.Info("Writing report adoc")
	adocReporter := NewAdocReport(config.GetOutputFolder(), riskRules, config.GetHideEmptyChapters())
	return adocReporter.WriteReport(readResult.ParsedModel,
		filepath.Join(config.GetOutputFolder(), config.GetDataFlowDiagramFilenamePNG()),
		filepath.Join(config.GetOutputFolder(), config.GetDataAssetDiagramFilenamePNG()),
		config.GetInputFile(),
		config.GetSkipRiskRules(),
		config.GetBuildTimestamp(),
		config.GetThreagileVersion(),
		modelHash,
		readResult.IntroTextRAA,
		readResult.CustomRiskRules,
		config.GetReportLogoImagePath(),
		config.GetReportConfigurationHideChapters())
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
			ModelFilename:       config.GetInputFile(),
			ModelHash:           modelHash,
			BuildTimestamp:      config.GetBuildTimestamp(),
			ThreagileVersion:    config.GetThreagileVersion(),
			IntroTextRAA:        readResult.IntroTextRAA,
			SkipRiskRules:       config.GetSkipRiskRules(),
			RiskRules:           riskRules,
			CustomRiskRules:     readResult.CustomRiskRules,
			HideChapters:        config.GetReportConfigurationHideChapters(),
			HideEmptyChapters:   config.GetHideEmptyChapters(),
			DataFlowDiagramDOT:  dataFlowDOT,
			DataAssetDiagramDOT: dataAssetDOT,
		}, progressReporter)
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
