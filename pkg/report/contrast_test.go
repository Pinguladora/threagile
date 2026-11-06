package report

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContrastRatio(t *testing.T) {
	assert.InDelta(t, 21, contrastRatio("#000000", "#FFFFFF"), 0.01)
	assert.InDelta(t, 1, contrastRatio("#3A52C8", "#3A52C8"), 0.01)
	assert.InDelta(t, 4.0, contrastRatio("#FF0000", "#FFFFFF"), 0.01)

	darkened := darkenedForContrast("#FF8E00", "#FFFFFF", contrastAAA)
	assert.GreaterOrEqual(t, contrastRatio(darkened, "#FFFFFF"), contrastAAA)
	assert.Less(t, contrastRatio(darkened, "#FFFFFF"), contrastAAA+0.2, "darkened only as far as needed")
	assert.Equal(t, "#23465F", darkenedForContrast("#23465F", "#FFFFFF", contrastAAA), "already dark enough")
}

// TestPDFColorsReachAAA checks the coloured text of the PDF report against its white page.
func TestPDFColorsReachAAA(t *testing.T) {
	for name, color := range typstColors() {
		assert.GreaterOrEqual(t, contrastRatio(color, "#FFFFFF"), contrastAAA, "%s %s", name, color)
	}
}

// TestHTMLColorsReachAAA checks the badges of the HTML report, their text on their background, and the text colours
// of each theme on its backgrounds.
func TestHTMLColorsReachAAA(t *testing.T) {
	css, err := os.ReadFile("templates/report.css")
	require.NoError(t, err)

	badges := regexp.MustCompile(`\.((?:sev|status)-[a-z-]+|out-of-scope) \{\n  background: (#[0-9a-f]{6});\n  color: (#[0-9a-f]{6});`).
		FindAllStringSubmatch(string(css), -1)
	require.Len(t, badges, 12, "the five severities, the six statuses and out of scope")
	for _, badge := range badges {
		assert.GreaterOrEqual(t, contrastRatio(badge[3], badge[2]), contrastAAA, badge[1])
	}

	themes := regexp.MustCompile(`(?s)\{[^{}]*?(--bg: #[0-9a-f]{6};[^{}]*?--accent: #[0-9a-f]{6};)`).FindAllStringSubmatch(string(css), -1)
	require.Len(t, themes, 3, "the light, dark and print themes")
	variable := regexp.MustCompile(`--([a-z]+): (#[0-9a-f]{6});`)
	for _, theme := range themes {
		colors := make(map[string]string)
		for _, match := range variable.FindAllStringSubmatch(theme[1], -1) {
			colors[match[1]] = match[2]
		}
		for _, text := range []string{"fg", "muted", "link", "accent"} {
			for _, background := range []string{"bg", "surface"} {
				assert.GreaterOrEqual(t, contrastRatio(colors[text], colors[background]), contrastAAA,
					"--%s %s on --%s %s", text, colors[text], background, colors[background])
			}
		}
	}
}
