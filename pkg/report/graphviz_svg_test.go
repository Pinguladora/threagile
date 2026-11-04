package report

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderDiagramSVG(t *testing.T) {
	svg, err := renderDiagramSVG([]byte(testDiagramDOT))
	require.NoError(t, err)
	require.Contains(t, string(svg), "<svg")

	inlined, err := inlineSVG(svg, "Test diagram")
	require.NoError(t, err)

	assert.Regexp(t, `^<svg width="[\d.]+pt" viewBox="0 0 [\d.]+ [\d.]+" role`, inlined)
	assert.Contains(t, inlined, ` role="img" aria-label="Test diagram"><title>Test diagram</title>`)
	assert.True(t, strings.HasSuffix(inlined, "</svg>"), inlined)
	for _, leftOut := range []string{"<?xml", "<!DOCTYPE", "<!--", " id=", " class=", "xmlns", "<title>test</title>"} {
		assert.NotContains(t, inlined, leftOut)
	}
	// the three nodes, the edge with its arrowhead and the background are all still drawn
	assert.Equal(t, strings.Count(string(svg), "<polygon"), strings.Count(inlined, "<polygon"))
	assert.Equal(t, strings.Count(string(svg), "<path"), strings.Count(inlined, "<path"))
	assert.Equal(t, 3, strings.Count(inlined, "<text"))
}

// TestInlineSVGScalesWithTheDPI: Graphviz writes the viewBox of a diagram in points before
// scaling it to the DPI, so the viewBox of the inlined diagram is its size in points instead.
func TestInlineSVGScalesWithTheDPI(t *testing.T) {
	svg, err := renderDiagramSVG([]byte(strings.Replace(testDiagramDOT, "dpi=72", "dpi=144", 1)))
	require.NoError(t, err)
	width := regexp.MustCompile(`<svg width="([\d.]+)pt" height="([\d.]+)pt"`).FindStringSubmatch(string(svg))
	require.Len(t, width, 3, "Graphviz wrote no size in points")
	require.Contains(t, string(svg), "scale(2 2)")

	inlined := mustInlineSVG(t, svg, "Diagram")
	assert.True(t, strings.HasPrefix(inlined, `<svg width="`+width[1]+`pt" viewBox="0 0 `+width[1]+" "+width[2]+`"`), inlined)
}

func TestRenderDiagramSVGInvalidSource(t *testing.T) {
	_, err := renderDiagramSVG([]byte("digraph {"))
	assert.Error(t, err)
}

// TestDiagramSVGEscapesModelText renders labels the way the diagrams carry model text: escaped
// into HTML-like labels and quoted into plain ones. Graphviz writes them as escaped text.
func TestDiagramSVGEscapesModelText(t *testing.T) {
	const dot = `digraph g {
		graph [ label="</svg><script>alert(1)</script> \"x\" onload=alert(2)" ];
		a [ label=<<b>&lt;/text&gt;&lt;script&gt;alert(3)&lt;/script&gt; "q" onmouseover='x' javascript:alert(4)</b>> ];
		b [ label=<<b><img src=x onerror=alert(5)></b>> ];
		a -> b [ xlabel="</text><style>*{}</style><a href=javascript:alert(6)>" ];
	}`
	svg, err := renderDiagramSVG([]byte(dot))
	require.NoError(t, err)

	for _, document := range []string{string(svg), mustInlineSVG(t, svg, "Diagram")} {
		for _, element := range []string{"<script", "<style", "<img", "<a "} {
			assert.NotContains(t, document, element)
		}
		assert.NotRegexp(t, `<[^>]*\son\w+=`, document, "an event handler attribute")
		assert.Equal(t, 1, strings.Count(document, "<svg"))
		assert.Equal(t, 1, strings.Count(document, "</svg>"))
		assert.Equal(t, 3, strings.Count(document, "</text>"))
		assert.Contains(t, document, "&lt;/svg&gt;&lt;script&gt;alert(1)&lt;/script&gt;")
		assert.Contains(t, document, "&lt;/text&gt;&lt;script&gt;alert(3)&lt;/script&gt;")
	}
}

func TestInlineSVGLeavesOutActiveContent(t *testing.T) {
	const svg = `<?xml version="1.0"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="10pt" height="10pt" viewBox="0 0 10 10" onload="alert(1)" xmlns="http://www.w3.org/2000/svg"
	xmlns:xlink="http://www.w3.org/1999/xlink">
<script>alert(2)</script>
<style>text { fill: red }</style>
<g id="graph0" class="graph" transform="scale(1 1) rotate(0) translate(4 4)" style="fill:red">
<title>&lt;script&gt;</title>
<a xlink:href="javascript:alert(3)" href="javascript:alert(4)"><text x="1" y="2" fill="url(javascript:alert(5))"
	onclick="alert(6)">a &lt;b&gt; &amp; "c"<title>left out</title></text></a>
<image xlink:href="https://example.com/x.png" width="1" height="1"/>
<foreignObject><div xmlns="http://www.w3.org/1999/xhtml"><text>html</text></div></foreignObject>
<polygon fill="#ff0000" points="0,0 1,1" transform="scale(1) url(x)"/>
</g>
</svg>`
	inlined, err := inlineSVG([]byte(svg), `"><script>alert(7)</script>`)
	require.NoError(t, err)

	assert.Equal(t, `<svg width="10pt" viewBox="0 0 10 10" role="img" `+
		`aria-label="&#34;&gt;&lt;script&gt;alert(7)&lt;/script&gt;"><title>&#34;&gt;&lt;script&gt;alert(7)&lt;/script&gt;</title>`+
		`<g transform="scale(1 1) rotate(0) translate(4 4)">`+
		`<text x="1" y="2">a &lt;b&gt; &amp; &#34;c&#34;</text>`+
		`<polygon fill="#ff0000" points="0,0 1,1"></polygon>`+
		`</g></svg>`, strings.Join(strings.Fields(inlined), " "))
}

func TestInlineSVGRejectsOtherDocuments(t *testing.T) {
	for _, document := range []string{"", "<html><svg></svg></html>", "<svg>", "not xml"} {
		_, err := inlineSVG([]byte(document), "Diagram")
		assert.Error(t, err, document)
	}
}

func mustInlineSVG(t *testing.T, svg []byte, label string) string {
	t.Helper()
	inlined, err := inlineSVG(svg, label)
	require.NoError(t, err)
	return inlined
}
