package report_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"image"
	"image/png"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"github.com/Pinguladora/threagile/internal/threagile"
	"github.com/Pinguladora/threagile/pkg/model"
	"github.com/Pinguladora/threagile/pkg/report"
	"github.com/Pinguladora/threagile/pkg/risks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// update rewrites the golden files from the current output: go test ./pkg/report -run TestGoldenOutputs -update.
var update = flag.Bool("update", false, "rewrite the golden files under testdata")

const (
	exampleModelFile = "../../demo/example/threagile.yaml"
	goldenDir        = "testdata/example"
	// determinismRuns is how many times the determinism test generates the outputs; Go picks a
	// new map iteration order every time, so more runs catch an unsorted map more reliably.
	determinismRuns = 4
)

// goldenFiles are the outputs compared against testdata; the JSON ones are stored indented.
var goldenFiles = []string{
	"data-flow-diagram.gv",
	"data-asset-diagram.gv",
	"risks.json",
	"technical-assets.json",
	"stats.json",
	"otm.json",
	"report.html",
	"THREAT_MODEL.md",
}

// executionTimestamp matches the wall-clock time the AsciiDoc report records for the run.
var executionTimestamp = regexp.MustCompile(`(Threagile Execution Timestamp: *\| )\d{14}`)

func TestGoldenOutputs(t *testing.T) {
	outputs := generateOutputs(t)

	for _, name := range goldenFiles {
		t.Run(name, func(t *testing.T) {
			got, ok := outputs[name]
			require.True(t, ok, "output %s was not written", name)
			if filepath.Ext(name) == ".json" {
				got = indentJSON(t, got)
			}

			goldenFile := filepath.Join(goldenDir, name)
			if *update {
				require.NoError(t, os.MkdirAll(goldenDir, 0o750))
				require.NoError(t, os.WriteFile(goldenFile, got, 0o600))
				return
			}

			want, err := os.ReadFile(filepath.Clean(goldenFile))
			require.NoError(t, err, "missing golden file, run the test with -update to create it")
			assert.Equal(t, string(want), string(got), "output differs from %s, run the test with -update if the change is intended", goldenFile)
		})
	}
}

// TestOutputsAreDeterministic catches nondeterminism even when the golden files get regenerated.
func TestOutputsAreDeterministic(t *testing.T) {
	first := generateOutputs(t)
	require.NotEmpty(t, first)

	for run := 2; run <= determinismRuns; run++ {
		next := generateOutputs(t)
		require.Equal(t, slices.Sorted(maps.Keys(first)), slices.Sorted(maps.Keys(next)), "run %d wrote other files than run 1", run)
		for _, name := range slices.Sorted(maps.Keys(first)) {
			if !bytes.Equal(first[name], next[name]) {
				t.Errorf("run %d: %s differs from run 1", run, name)
			}
		}
	}
}

// generateOutputs analyzes the example model and writes every output but the PDF report and the
// PNG diagrams, the same way report.Generate does. It returns the written files by path relative
// to the output folder, with the execution timestamp of the AsciiDoc report normalised.
func generateOutputs(t *testing.T) map[string][]byte {
	t.Helper()
	// the HTML and Markdown reports record when they were generated
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	reporter := testReporter{t}
	outputDir := t.TempDir()

	config := new(threagile.Config).Defaults("")
	config.SetAppFolder(t.TempDir())
	config.SetPluginFolder(t.TempDir())
	config.SetInputFile(exampleModelFile)
	config.SetOutputFolder(outputDir)
	config.SetTempFolder(t.TempDir())
	config.SetIgnoreOrphanedRiskTracking(true)

	result, err := model.ReadAndAnalyzeModel(config, risks.GetBuiltInRiskRules(), reporter)
	require.NoError(t, err)
	parsedModel := result.ParsedModel

	_, err = report.WriteDataFlowDiagramGraphvizDOT(parsedModel, filepath.Join(outputDir, config.GetDataFlowDiagramFilenameDOT()),
		config.GetDiagramDPI(), config.GetAddModelTitle(), config.GetAddLegend(), reporter)
	require.NoError(t, err)
	_, err = report.WriteDataAssetDiagramGraphvizDOT(parsedModel, filepath.Join(outputDir, config.GetDataAssetDiagramFilenameDOT()),
		config.GetDiagramDPI(), reporter)
	require.NoError(t, err)

	require.NoError(t, report.WriteRisksJSON(parsedModel, filepath.Join(outputDir, config.GetJsonRisksFilename())))
	require.NoError(t, report.WriteTechnicalAssetsJSON(parsedModel, filepath.Join(outputDir, config.GetJsonTechnicalAssetsFilename())))
	require.NoError(t, report.WriteStatsJSON(parsedModel, filepath.Join(outputDir, config.GetJsonStatsFilename())))
	require.NoError(t, report.WriteOTMJSON(parsedModel, filepath.Join(outputDir, config.GetJsonOTMFilename())))
	options := report.ReportOptions{
		ModelFilename:     config.GetInputFile(),
		ModelHash:         "test-model-hash",
		BuildTimestamp:    "test-build-timestamp",
		ThreagileVersion:  "test-version",
		IntroTextRAA:      result.IntroTextRAA,
		SkipRiskRules:     config.GetSkipRiskRules(),
		RiskRules:         risks.GetBuiltInRiskRules(),
		CustomRiskRules:   result.CustomRiskRules,
		HideChapters:      config.GetReportConfigurationHideChapters(),
		HideEmptyChapters: config.GetHideEmptyChapters(),
	}
	require.NoError(t, report.WriteReportHTML(parsedModel, filepath.Join(outputDir, config.GetReportHTMLFilename()),
		report.HTMLReportOptions{
			ReportOptions:       options,
			DataFlowDiagramDOT:  readFile(t, filepath.Join(outputDir, config.GetDataFlowDiagramFilenameDOT())),
			DataAssetDiagramDOT: readFile(t, filepath.Join(outputDir, config.GetDataAssetDiagramFilenameDOT())),
		}, reporter))
	require.NoError(t, report.WriteReportMarkdown(parsedModel, filepath.Join(outputDir, config.GetReportMarkdownFilename()), options))
	require.NoError(t, report.WriteRisksExcelToFile(parsedModel, filepath.Join(outputDir, config.GetExcelRisksFilename()), config))
	require.NoError(t, report.WriteTagsExcelToFile(parsedModel, filepath.Join(outputDir, config.GetExcelTagsFilename()), config))

	// the AsciiDoc report copies the rendered diagrams; stand-in images keep Graphviz out of the test
	imageDir := t.TempDir()
	adoc := report.NewAdocReport(outputDir, risks.GetBuiltInRiskRules(), config.GetHideEmptyChapters())
	err = adoc.WriteReport(parsedModel,
		writePlaceholderPNG(t, filepath.Join(imageDir, config.GetDataFlowDiagramFilenamePNG())),
		writePlaceholderPNG(t, filepath.Join(imageDir, config.GetDataAssetDiagramFilenamePNG())),
		config.GetInputFile(),
		config.GetSkipRiskRules(),
		"test-build-timestamp",
		"test-version",
		"test-model-hash",
		result.IntroTextRAA,
		result.CustomRiskRules,
		"",
		config.GetReportConfigurationHideChapters())
	require.NoError(t, err)

	return readOutputs(t, outputDir)
}

func readOutputs(t *testing.T, outputDir string) map[string][]byte {
	t.Helper()
	root, err := os.OpenRoot(outputDir)
	require.NoError(t, err)
	defer func() { _ = root.Close() }()

	outputs := make(map[string][]byte)
	outputFS := root.FS()
	err = fs.WalkDir(outputFS, ".", func(name string, entry fs.DirEntry, walkError error) error {
		if walkError != nil || entry.IsDir() {
			return walkError
		}

		content, readError := fs.ReadFile(outputFS, name)
		if readError != nil {
			return readError
		}

		if path.Ext(name) == ".adoc" {
			content = executionTimestamp.ReplaceAll(content, []byte("${1}YYYYMMDDhhmmss"))
		}
		outputs[name] = content
		return nil
	})
	require.NoError(t, err)
	return outputs
}

func readFile(t *testing.T, filename string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Clean(filename))
	require.NoError(t, err)
	return content
}

func writePlaceholderPNG(t *testing.T, filename string) string {
	t.Helper()
	file, err := os.Create(filepath.Clean(filename))
	require.NoError(t, err)
	defer func() { _ = file.Close() }()
	require.NoError(t, png.Encode(file, image.NewGray(image.Rect(0, 0, 4, 3))))
	return filename
}

func indentJSON(t *testing.T, content []byte) []byte {
	t.Helper()
	var indented bytes.Buffer
	require.NoError(t, json.Indent(&indented, content, "", "  "))
	indented.WriteString("\n")
	return indented.Bytes()
}

// testReporter sends warnings to the test log and fails the test on errors.
type testReporter struct {
	t *testing.T
}

func (r testReporter) Info(...any) {}

func (r testReporter) Infof(string, ...any) {}

func (r testReporter) Warn(a ...any) {
	r.t.Log(a...)
}

func (r testReporter) Warnf(format string, a ...any) {
	r.t.Logf(format, a...)
}

func (r testReporter) Error(a ...any) {
	r.t.Error(a...)
}

func (r testReporter) Errorf(format string, a ...any) {
	r.t.Errorf(format, a...)
}
