package model

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Pinguladora/threagile/pkg/input"
	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const customRiskCategoryAssets = `
business_criticality: important
technical_assets:
  Database:
    id: database
    type: datastore
    usage: business
    size: component
    technology: database
    machine: virtual
    encryption: none
    confidentiality: confidential
    integrity: critical
    availability: critical
`

const customRiskCategoryFields = `
    description: Some text describing the risk category...
    function: business-side
    stride: repudiation
    cwe: 693
    risks_identified:
      Something Strange at Database:
        severity: critical
        exploitation_likelihood: likely
        exploitation_impact: medium
        data_breach_probability: probable
        data_breach_technical_assets:
          - database
        most_relevant_technical_asset: database
`

// TestCustomRiskCategoryForms parses custom risk categories in the current list form and in the
// map keyed by title that it replaced (threagile#130); both must name the category in the reports.
func TestCustomRiskCategoryForms(t *testing.T) {
	for name, test := range map[string]struct {
		categories string
		title      string
	}{
		"list":               {"custom_risk_categories:\n  - id: something-strange\n    title: Something Strange" + customRiskCategoryFields, "Something Strange"},
		"list without title": {"custom_risk_categories:\n  - id: something-strange" + customRiskCategoryFields, "something-strange"},
		"deprecated map":     {"individual_risk_categories:\n  Something Strange:\n    id: something-strange" + customRiskCategoryFields, "Something Strange"},
		"map with title":     {"individual_risk_categories:\n  Some Key:\n    id: something-strange\n    title: Something Strange" + customRiskCategoryFields, "Something Strange"},
	} {
		t.Run(name, func(t *testing.T) {
			modelInput := loadModel(t, customRiskCategoryAssets+test.categories)
			_, err := modelInput.ConvertIndividualRiskCategories()
			require.NoError(t, err)
			assert.Nil(t, modelInput.IndividualRiskCategories, "the deprecated map is converted, not written back")

			parsedModel, err := ParseModel(&mockConfig{}, modelInput, make(types.RiskRules), make(types.RiskRules))
			require.NoError(t, err)

			category := parsedModel.GetRiskCategory("something-strange")
			require.NotNil(t, category)
			assert.Equal(t, test.title, category.Title)
			assert.NotEmpty(t, category.Description)
			assert.Equal(t, types.Repudiation, category.STRIDE)
			require.Len(t, parsedModel.GeneratedRisksByCategory["something-strange"], 1)
			assert.Equal(t, "something-strange@database", parsedModel.GeneratedRisksByCategory["something-strange"][0].SyntheticId)
		})
	}
}

func TestConvertIndividualRiskCategories(t *testing.T) {
	modelInput := loadModel(t, customRiskCategoryAssets+`
custom_risk_categories:
  - id: current
    title: Current
individual_risk_categories:
  Second Legacy:
    id: second-legacy
  First Legacy:
    id: first-legacy
`)

	converted, err := modelInput.ConvertIndividualRiskCategories()
	require.NoError(t, err)
	assert.Equal(t, 2, converted)

	titles := make([]string, 0, len(modelInput.CustomRiskCategories))
	for _, category := range modelInput.CustomRiskCategories {
		titles = append(titles, category.Title)
	}
	assert.Equal(t, []string{"Current", "First Legacy", "Second Legacy"}, titles, "the deprecated ones follow, in title order")

	converted, err = modelInput.ConvertIndividualRiskCategories()
	require.NoError(t, err)
	assert.Zero(t, converted)
}

func TestConvertIndividualRiskCategoriesRejectsDuplicateId(t *testing.T) {
	modelInput := loadModel(t, customRiskCategoryAssets+`
custom_risk_categories:
  - id: something-strange
individual_risk_categories:
  Something Strange:
    id: something-strange
`)

	_, err := modelInput.ConvertIndividualRiskCategories()
	assert.ErrorContains(t, err, "something-strange")
}

func loadModel(t *testing.T, content string) *input.Model {
	t.Helper()
	modelFile := filepath.Join(t.TempDir(), "threagile.yaml")
	require.NoError(t, os.WriteFile(modelFile, []byte(content), 0o600))

	modelInput := new(input.Model).Defaults()
	require.NoError(t, modelInput.Load(modelFile))
	return modelInput
}
