package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTypstDocument(t *testing.T) {
	markdown := "# Threat Model Report: Shop\n\n" +
		"- **Author:** Jane\n\n" +
		"## Contents\n\n1. [Summary](#summary)\n\n" +
		"## Summary\n\n" +
		"Text with **bold**, _italics_, `an-id`, \\*no emphasis\\*, &lt;b&gt; and a [link](https://example.com/a).\n" +
		"A [heading link](#details) and a [scripted link](javascript:alert(1)).\n\n" +
		"### Details\n\n" +
		"| Risk | Count |\n| --- | ---: |\n| [Summary](#summary) | 3 |\n\n" +
		"```mermaid\nflowchart LR\n```\n\n" +
		"```mermaid\nflowchart LR\n```\n\n" +
		"- item\n\n    more of the item\n"

	blocks := newTypstDocument([]byte(markdown), []typstDiagram{{File: "diagram.svg", Alt: "Data-flow diagram"}})

	require.Len(t, blocks, 6, "the title, the details below it and the contents are left out")
	assert.Equal(t, &typstBlock{Kind: "heading", Level: 1, Label: "summary", Spans: []typstSpan{{Text: "Summary"}}},
		blocks[0], "a chapter is a heading of the top level, labelled with its slug")

	assert.Equal(t, []typstSpan{
		{Text: "Text with "},
		{Text: "bold", Bold: true},
		{Text: ", "},
		{Text: "italics", Italic: true},
		{Text: ", "},
		{Text: "an-id", Code: true},
		{Text: ", *no emphasis*, <b> and a "},
		{Text: "link", Link: "https://example.com/a"},
		{Text: ". A "},
		{Text: "heading link", Ref: "details"},
		{Text: " and a scripted link."},
	}, blocks[1].Spans, "escapes are resolved, and only http(s) links stay links")

	assert.Equal(t, "details", blocks[2].Label)
	assert.Equal(t, 2, blocks[2].Level)

	assert.Equal(t, []typstColumn{{Title: "Risk"}, {Title: "Count", Number: true}}, blocks[3].Columns)
	assert.Equal(t, [][][]typstSpan{{{{Text: "Summary", Ref: "summary"}}, {{Text: "3"}}}}, blocks[3].Rows)

	assert.Equal(t, &typstBlock{Kind: "image", Image: "diagram.svg", Alt: "Data-flow diagram"}, blocks[4],
		"a Mermaid diagram is replaced by the diagram given, and left out when there is none left")

	assert.Equal(t, "list", blocks[5].Kind)
	require.Len(t, blocks[5].Items, 1)
	assert.Len(t, blocks[5].Items[0], 2, "an item keeps its paragraphs")
}
