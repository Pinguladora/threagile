package report_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Pinguladora/threagile/internal/threagile"
	"github.com/Pinguladora/threagile/pkg/model"
	"github.com/Pinguladora/threagile/pkg/report"
	"github.com/Pinguladora/threagile/pkg/risks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHideDevOps generates the reports of the example model, whose build pipeline and repository are devops assets,
// with and without them: the setting of the model counts unless the config overrides it, and the JSON outputs keep
// everything either way.
func TestHideDevOps(t *testing.T) {
	modelText, err := os.ReadFile("../../demo/example/threagile.yaml")
	require.NoError(t, err)
	modelDir := t.TempDir()
	modelRoot, err := os.OpenRoot(modelDir)
	require.NoError(t, err)
	defer func() { _ = modelRoot.Close() }()
	require.NoError(t, modelRoot.WriteFile("threagile.yaml",
		append(modelText, []byte("\nhide_devops_in_reports: true\n")...), 0o600))
	hiding := filepath.Join(modelDir, "threagile.yaml")

	yes, no := true, false
	for name, test := range map[string]struct {
		modelFile string
		override  *bool
		hidden    bool
	}{
		"model shows them":              {"../../demo/example/threagile.yaml", nil, false},
		"model hides them":              {hiding, nil, true},
		"config hides them":             {"../../demo/example/threagile.yaml", &yes, true},
		"config shows what model hides": {hiding, &no, false},
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
			config.HideDevOpsValue = test.override

			result, err := model.ReadAndAnalyzeModel(config, risks.GetBuiltInRiskRules(), reporter)
			require.NoError(t, err)
			commands := new(report.GenerateCommands).Defaults()
			commands.ReportPDF = false
			require.NoError(t, report.Generate(config, result, commands, risks.GetBuiltInRiskRules(), reporter))

			outputRoot, err := os.OpenRoot(outputDir)
			require.NoError(t, err)
			defer func() { _ = outputRoot.Close() }()
			read := func(name string) string {
				content, readError := outputRoot.ReadFile(name)
				require.NoError(t, readError, name)
				return string(content)
			}
			for _, name := range []string{config.GetReportMarkdownFilename(), config.GetReportHTMLFilename()} {
				content := read(name)
				if test.hidden {
					assert.Contains(t, content, "Left out", name)
					assert.NotContains(t, content, "Jenkins Build Server", name)
				} else {
					assert.NotContains(t, content, "Left out", name)
					assert.Contains(t, content, "Jenkins Build Server", name)
				}
			}
			assert.Contains(t, read(config.GetJsonRisksFilename()), "@jenkins-build-server", "the risks JSON keeps all")
			assert.Contains(t, read(config.GetJsonTechnicalAssetsFilename()), "Jenkins Build Server")
		})
	}
}
