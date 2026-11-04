package report_test

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Pinguladora/threagile/internal/threagile"
	"github.com/Pinguladora/threagile/pkg/model"
	"github.com/Pinguladora/threagile/pkg/report"
	"github.com/Pinguladora/threagile/pkg/risks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReportsOfMinimalModels generates every output, the PDF report included, for minimal models:
// one split with includes into files that hold the assets (threagile#164), and one without any
// asset, which is what releases that ignored `includes:` made of such a model and where the
// report divided by zero.
func TestReportsOfMinimalModels(t *testing.T) {
	emptyModel := filepath.Join(t.TempDir(), "threagile.yaml")
	require.NoError(t, os.WriteFile(emptyModel, []byte("title: Empty Model\nbusiness_criticality: important\n"), 0o600))

	for name, test := range map[string]struct {
		modelFile       string
		technicalAssets []string
		dataAssets      []string
	}{
		"split with includes": {"testdata/includes/threagile.yaml", []string{"customer-service"}, []string{"customer-data"}},
		"without assets":      {emptyModel, nil, nil},
	} {
		t.Run(name, func(t *testing.T) {
			reporter := testReporter{t}
			outputDir := t.TempDir()

			config := new(threagile.Config).Defaults("")
			config.SetAppFolder(t.TempDir())
			config.SetPluginFolder(t.TempDir())
			config.SetInputFile(test.modelFile)
			config.SetOutputFolder(outputDir)
			config.SetTempFolder(t.TempDir())

			result, err := model.ReadAndAnalyzeModel(config, risks.GetBuiltInRiskRules(), reporter)
			require.NoError(t, err)
			assert.ElementsMatch(t, test.technicalAssets, result.ParsedModel.SortedTechnicalAssetIDs())
			assert.ElementsMatch(t, test.dataAssets, slices.Collect(maps.Keys(result.ParsedModel.DataAssets)))

			require.NoError(t, report.Generate(config, result, new(report.GenerateCommands).Defaults(), risks.GetBuiltInRiskRules(), reporter))

			for _, output := range []string{config.GetReportFilename(), config.GetDataFlowDiagramFilenamePNG(), config.GetDataAssetDiagramFilenamePNG()} {
				info, statError := os.Stat(filepath.Join(outputDir, output))
				require.NoError(t, statError, output)
				assert.Positive(t, info.Size(), output)
			}
		})
	}
}
