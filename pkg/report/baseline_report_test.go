package report_test

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Pinguladora/threagile/internal/threagile"
	"github.com/Pinguladora/threagile/pkg/baseline"
	"github.com/Pinguladora/threagile/pkg/model"
	"github.com/Pinguladora/threagile/pkg/report"
	"github.com/Pinguladora/threagile/pkg/risks"
	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMarkdownReportComparesWithTheBaseline checks the chapter of the changes since a baseline: it follows the risks
// by severity, links the risks the model has and lists those it no longer has.
func TestMarkdownReportComparesWithTheBaseline(t *testing.T) {
	config := new(threagile.Config).Defaults("")
	config.SetAppFolder(t.TempDir())
	config.SetPluginFolder(t.TempDir())
	config.SetInputFile(exampleModel.file)
	config.SetOutputFolder(t.TempDir())
	config.SetTempFolder(t.TempDir())
	result, err := model.ReadAndAnalyzeModel(config, risks.GetBuiltInRiskRules(), testReporter{t})
	require.NoError(t, err)

	current := result.ParsedModel.AllRisks()
	baselineRisks := make([]baseline.Risk, 0, len(current))
	for _, risk := range current[1:] { // the first risk is new
		baselineRisks = append(baselineRisks, baseline.Risk{SyntheticId: risk.SyntheticId, Severity: risk.Severity})
	}
	baselineRisks[0].Severity = types.CriticalSeverity // de-escalated, unless it is critical already
	baselineRisks = append(baselineRisks, baseline.Risk{
		SyntheticId: "gone-rule@old-asset", Title: "Gone Rule at Old Asset", Severity: types.HighSeverity,
	})
	comparison := baseline.Compare(filepath.Join("previous", "risks.json"), baselineRisks, current)
	require.Len(t, comparison.New, 1)
	require.Len(t, comparison.Deescalated, 1)

	source := string(writeMarkdownReport(t, result.ParsedModel, report.ReportOptions{
		RiskRules: risks.GetBuiltInRiskRules(), Baseline: comparison,
	}))

	start := strings.Index(source, "\n## Changes Since the Baseline\n")
	require.Positive(t, start)
	chapter := source[start+1:]
	chapter = chapter[:strings.Index(chapter, "\n## ")+1]
	assert.Less(t, strings.Index(source, "\n## Risks by Severity\n"), strings.Index(source, chapter))
	assert.Contains(t, chapter, "baseline `risks.json`: **1 new**, 1 resolved, 0 escalated, 1 de-escalated and ")
	assert.Contains(t, chapter, "### New Risks\n")
	assert.Contains(t, chapter, "`"+current[0].SyntheticId+"`")
	assert.NotContains(t, chapter, "### Escalated Risks")
	assert.Contains(t, chapter, "### De-escalated Risks\n")
	assert.Contains(t, chapter, "| Gone Rule at Old Asset | `gone-rule@old-asset` | High |")
	assert.Len(t, regexp.MustCompile(`\]\(#[^)]+\)`).FindAllString(chapter, -1), 2,
		"the new and the de-escalated risk link to their details")

	withoutBaseline := string(writeMarkdownReport(t, result.ParsedModel, report.ReportOptions{
		RiskRules: risks.GetBuiltInRiskRules(),
	}))
	assert.NotContains(t, withoutBaseline, "Changes Since the Baseline")
}
