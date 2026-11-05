package report_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Pinguladora/threagile/pkg/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReportPDFNeedsTypst(t *testing.T) {
	parsedModel, options := analyzeHostileModel(t)
	t.Setenv("PATH", t.TempDir())
	filename := filepath.Join(t.TempDir(), "report.pdf")

	err := report.WriteReportPDF(parsedModel, filename, report.PDFReportOptions{
		ReportOptions: options, TempFolder: t.TempDir(),
	}, testReporter{t})

	require.ErrorIs(t, err, report.ErrTypstMissing)
	assert.NoFileExists(t, filename)
}

// TestReportPDFOfAHostileModel renders the PDF report of a model whose texts are full of markup: typst only ever gets
// them as strings, so they render as text, and the same input gives the same bytes.
func TestReportPDFOfAHostileModel(t *testing.T) {
	if _, err := exec.LookPath("typst"); err != nil {
		t.Skip("typst is not installed")
	}
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	parsedModel, options := analyzeHostileModel(t)
	reporter := testReporter{t}
	pdfOptions := report.PDFReportOptions{ReportOptions: options, TempFolder: t.TempDir()}
	pdfOptions.DataFlowDiagramDOT = writeDOT(t, func(filename string) (*os.File, error) {
		return report.WriteDataFlowDiagramGraphvizDOT(parsedModel, filename, 72, true, true, reporter)
	})

	render := func() []byte {
		filename := filepath.Join(t.TempDir(), "report.pdf")
		require.NoError(t, report.WriteReportPDF(parsedModel, filename, pdfOptions, reporter))
		return readFile(t, filename)
	}
	first := render()

	require.True(t, bytes.HasPrefix(first, []byte("%PDF-")), "a PDF")
	assert.True(t, bytes.Equal(first, render()), "the same model gives the same bytes")
}
