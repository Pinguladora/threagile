package report

import (
	"bytes"
	"testing"

	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/jung-kurt/gofpdf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHeadlinesAreBookmarked checks that the chapters of the PDF report show in the outline of PDF readers
// (threagile#84), a small headline below the chapter before it.
func TestHeadlinesAreBookmarked(t *testing.T) {
	r := newTestPdfReporter()
	r.addHeadline("Technical Assets", false)
	r.addHeadline("Web Server", true)

	var pdf bytes.Buffer
	require.NoError(t, r.pdf.Output(&pdf))

	assert.Contains(t, pdf.String(), "/Type /Outlines")
	assert.Contains(t, pdf.String(), "/Title (Technical Assets)")
	assert.Regexp(t, `/Title \(Web Server\)\s*/Parent \d+ 0 R`, pdf.String())
}

// TestRiskRulesCheckedListsTheBuiltInRules checks that the PDF report lists the built-in risk rules it was given,
// which it dropped before.
func TestRiskRulesCheckedListsTheBuiltInRules(t *testing.T) {
	rules := types.RiskRules{"some-rule": &testRiskRule{category: &types.RiskCategory{
		ID: "some-rule", Title: "Some Rule", STRIDE: types.Spoofing, Function: types.Development,
	}}}
	r := newPdfReporter(rules)
	r.initReport()
	r.pdf = gofpdf.New("P", "mm", "A4", "")
	r.parseBackgroundTemplate("")
	r.pdf.AddPage()
	r.pdf.SetCompression(false)

	r.checkedBuiltInRiskRules(nil)

	var pdf bytes.Buffer
	require.NoError(t, r.pdf.Output(&pdf))
	assert.Contains(t, pdf.String(), "(Some Rule)")
	assert.Contains(t, pdf.String(), "(some-rule)")
}

// testRiskRule is a risk rule of a category that finds nothing.
type testRiskRule struct {
	category *types.RiskCategory
}

func (what *testRiskRule) Category() *types.RiskCategory { return what.category }

func (what *testRiskRule) SupportedTags() []string { return nil }

func (what *testRiskRule) GenerateRisks(*types.Model) ([]*types.Risk, error) { return nil, nil }
