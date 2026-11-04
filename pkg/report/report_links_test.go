package report

import (
	"testing"

	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/jung-kurt/gofpdf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestChapterLinksOfEmptyModel defines the link targets of chapters that the table of contents of
// an empty model does not list; counting the links ran past the last one there (threagile#164).
func TestChapterLinksOfEmptyModel(t *testing.T) {
	r := newPdfReporter(nil)
	r.initReport()
	r.pdf = gofpdf.New("P", "mm", "A4", "")
	r.parseBackgroundTemplate("")
	r.createTableOfContents(&types.Model{})
	require.NoError(t, r.pdf.Error())

	assert.NotContains(t, r.tocLinkIdByAlias, "{intro-risks-by-technical-asset}")
	for _, alias := range []string{"{management-summary}", "{intro-risks-by-technical-asset}", "{intro-risks-by-data-asset}", "{disclaimer}"} {
		r.pdf.AddPage()
		assert.NotPanics(t, func() { r.defineLinkTarget(alias) }, alias)
	}

	// every entry links to its own chapter, the last one included
	assert.Equal(t, r.homeLink, r.tocLinkIdByAlias["{home}"])
	assert.Len(t, uniqueValues(r.tocLinkIdByAlias), len(r.tocLinkIdByAlias))
	assert.Contains(t, r.tocLinkIdByAlias, "{disclaimer}")
}

func uniqueValues(links map[string]int) map[int]bool {
	unique := make(map[int]bool, len(links))
	for _, link := range links {
		unique[link] = true
	}
	return unique
}
