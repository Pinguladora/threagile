package report

import (
	"image"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/jung-kurt/gofpdf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEmbedDiagramsOfAnySize embeds diagrams lower than the space reserved for them, as an
// (almost) empty model renders them; the data-flow diagram divided by zero there (threagile#164).
func TestEmbedDiagramsOfAnySize(t *testing.T) {
	for _, size := range []image.Point{{X: 11, Y: 11}, {X: 1, Y: 1}, {X: 400, Y: 199}, {X: 199, Y: 400}, {X: 2000, Y: 300}} {
		diagram := writeDiagramPNG(t, size)

		r := newTestPdfReporter()
		require.NoError(t, r.embedDataFlowDiagram(diagram, t.TempDir()), "data-flow diagram of %v pixels", size)
		require.NoError(t, r.embedDataRiskMapping(diagram, t.TempDir()), "data asset diagram of %v pixels", size)
		require.NoError(t, r.pdf.Error())
	}
}

func TestEmbedDiagramReportsUnreadableImage(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.png")
	notAnImage := filepath.Join(t.TempDir(), "diagram.png")
	require.NoError(t, os.WriteFile(notAnImage, []byte("not a PNG"), 0o600))

	for _, diagram := range []string{missing, notAnImage} {
		r := newTestPdfReporter()
		assert.Error(t, r.embedDataFlowDiagram(diagram, t.TempDir()), diagram)
		assert.Error(t, r.embedDataRiskMapping(diagram, t.TempDir()), diagram)
	}
}

func newTestPdfReporter() *pdfReporter {
	r := newPdfReporter(nil)
	r.initReport()
	r.pdf = gofpdf.New("P", "mm", "A4", "")
	r.parseBackgroundTemplate("")
	r.pdf.AddPage()
	return r
}

func writeDiagramPNG(t *testing.T, size image.Point) string {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "diagram.png")
	file, err := os.Create(filepath.Clean(filename))
	require.NoError(t, err)
	defer func() { _ = file.Close() }()
	require.NoError(t, png.Encode(file, image.NewGray(image.Rectangle{Max: size})))
	return filename
}
