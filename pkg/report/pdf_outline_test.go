package report

import (
	"bytes"
	"testing"

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
