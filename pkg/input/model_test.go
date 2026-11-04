package input

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadMergesIncludesIntoEmptySections covers a root model that lists its sections without
// values and leaves their content to included files (threagile#164).
func TestLoadMergesIncludesIntoEmptySections(t *testing.T) {
	dir := t.TempDir()
	shared := t.TempDir()

	writeModelFile(t, filepath.Join(shared, "contributors.yaml"), `
contributors:
  - name: Second Contributor
`)
	writeModelFile(t, filepath.Join(dir, "threagile.yaml"), `
title: Split Model
contributors:
  - name: First Contributor
data_assets:
technical_assets:
risk_tracking:
abuse_cases:
includes:
  - parts/assets.yaml
  - `+filepath.Join(shared, "contributors.yaml")+`
`)
	writeModelFile(t, filepath.Join(dir, "parts", "assets.yaml"), `
includes:
  - links.yaml
data_assets:
  Customer Data:
    id: customer-data
technical_assets:
  Web Server:
    id: web-server
abuse_cases:
  Some Abuse Case: Some description
risk_tracking:
  some-risk@web-server:
    status: accepted
`)
	// resolved relative to parts/, the folder of the file that includes it
	writeModelFile(t, filepath.Join(dir, "parts", "links.yaml"), `
technical_assets:
  Web Server:
    communication_links:
      Database Traffic:
        target: database
`)

	model := new(Model).Defaults()
	require.NoError(t, model.Load(filepath.Join(dir, "threagile.yaml")))

	assert.Contains(t, model.DataAssets, "Customer Data")
	assert.Contains(t, model.AbuseCases, "Some Abuse Case")
	assert.Contains(t, model.RiskTracking, "some-risk@web-server")
	require.Contains(t, model.TechnicalAssets, "Web Server")
	assert.Equal(t, "web-server", model.TechnicalAssets["Web Server"].ID)
	assert.Equal(t, "database", model.TechnicalAssets["Web Server"].CommunicationLinks["Database Traffic"].Target)

	contributors := make([]string, 0, len(model.Contributors))
	for _, contributor := range model.Contributors {
		contributors = append(contributors, contributor.Name)
	}
	assert.ElementsMatch(t, []string{"First Contributor", "Second Contributor"}, contributors)
}

func TestLoadMergesDeprecatedRiskCategoriesOfIncludes(t *testing.T) {
	dir := t.TempDir()
	writeModelFile(t, filepath.Join(dir, "threagile.yaml"), `
individual_risk_categories:
  First Category:
    id: first
includes:
  - categories.yaml
`)
	writeModelFile(t, filepath.Join(dir, "categories.yaml"), `
individual_risk_categories:
  Second Category:
    id: second
`)

	model := new(Model).Defaults()
	require.NoError(t, model.Load(filepath.Join(dir, "threagile.yaml")))
	assert.Len(t, model.IndividualRiskCategories, 2)

	converted, err := model.ConvertIndividualRiskCategories()
	require.NoError(t, err)
	assert.Equal(t, 2, converted)
	require.Len(t, model.CustomRiskCategories, 2)
	assert.Equal(t, "First Category", model.CustomRiskCategories[0].Title)
	assert.Equal(t, "second", model.CustomRiskCategories[1].ID)
}

func TestLoadReportsMissingIncludeAsError(t *testing.T) {
	dir := t.TempDir()
	writeModelFile(t, filepath.Join(dir, "threagile.yaml"), `
includes:
  - missing.yaml
`)

	err := new(Model).Defaults().Load(filepath.Join(dir, "threagile.yaml"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing.yaml")
}

func writeModelFile(t *testing.T, filename string, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(filename), 0o750))
	require.NoError(t, os.WriteFile(filename, []byte(content), 0o600))
}

func TestLoadMergesTheTechnologiesOfIncludes(t *testing.T) {
	dir := t.TempDir()
	writeModelFile(t, filepath.Join(dir, "threagile.yaml"), `
technical_assets:
  Web Server:
    id: web-server
    technologies: [web-server]
includes:
  - more.yaml
`)
	writeModelFile(t, filepath.Join(dir, "more.yaml"), `
technical_assets:
  Web Server:
    technologies: [waf, web-server]
`)

	model := new(Model).Defaults()
	require.NoError(t, model.Load(filepath.Join(dir, "threagile.yaml")))

	assert.ElementsMatch(t, []string{"web-server", "waf"}, model.TechnicalAssets["Web Server"].Technologies)
}

// TestLoadMergesAFileBeforeItsIncludes checks that the text a file adds comes before the text of the files it
// includes, whatever the order of its sections.
func TestLoadMergesAFileBeforeItsIncludes(t *testing.T) {
	dir := t.TempDir()
	writeModelFile(t, filepath.Join(dir, "threagile.yaml"), `
includes:
  - part.yaml
`)
	writeModelFile(t, filepath.Join(dir, "part.yaml"), `
includes:
  - nested.yaml
management_summary_comment: part
`)
	writeModelFile(t, filepath.Join(dir, "nested.yaml"), `
management_summary_comment: nested
`)

	for range 20 {
		model := new(Model).Defaults()
		require.NoError(t, model.Load(filepath.Join(dir, "threagile.yaml")))
		require.Equal(t, "part\n<br><br>\nnested", model.ManagementSummaryComment)
	}
}
