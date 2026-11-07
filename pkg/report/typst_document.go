package report

import (
	"net/url"
	"strings"

	"github.com/yuin/goldmark/v2"
	"github.com/yuin/goldmark/v2/ast"
	"github.com/yuin/goldmark/v2/extension"
	extensionast "github.com/yuin/goldmark/v2/extension/ast"
	"github.com/yuin/goldmark/v2/text"
	"github.com/yuin/goldmark/v2/util"
)

// typstDocument is the report as data for the Typst template: the chapters of the Markdown report, read back as
// blocks of plain text with its formatting, so that no text of the model is ever read as Typst markup.
type typstDocument struct {
	Title    string `json:"title"`
	Subtitle string `json:"subtitle"`
	Author   string `json:"author"`
	// Contributors are the names of the people besides the author who worked on the model.
	Contributors []string `json:"contributors,omitempty"`
	Date         string   `json:"date"`
	Version      string   `json:"version"`
	Logo         string   `json:"logo,omitempty"` // a file name next to the document
	// Colors are the colours of the severities and statuses by their titles, and of the links.
	Colors map[string]string `json:"colors"`
	Blocks []*typstBlock     `json:"blocks"`
}

// typstBlock is a heading, a paragraph, a list, a table or an image.
type typstBlock struct {
	Kind    string          `json:"kind"`
	Level   int             `json:"level,omitempty"`
	Label   string          `json:"label,omitempty"`
	Spans   []typstSpan     `json:"spans,omitempty"`
	Ordered bool            `json:"ordered,omitempty"`
	Items   [][]*typstBlock `json:"items,omitempty"`
	Columns []typstColumn   `json:"columns,omitempty"`
	Rows    [][][]typstSpan `json:"rows,omitempty"`
	Image   string          `json:"image,omitempty"`
	Alt     string          `json:"alt,omitempty"`
}

// typstColumn is a column of a table: its title and whether its numbers align to the right.
type typstColumn struct {
	Title  string `json:"title"`
	Number bool   `json:"number,omitempty"`
}

// typstSpan is a piece of text with its formatting, a link to a heading (by its label) or to a URL, or a line break.
type typstSpan struct {
	Text   string `json:"text,omitempty"`
	Bold   bool   `json:"bold,omitempty"`
	Italic bool   `json:"italic,omitempty"`
	Code   bool   `json:"code,omitempty"`
	Ref    string `json:"ref,omitempty"`
	Link   string `json:"link,omitempty"`
	Break  bool   `json:"break,omitempty"`
}

// typstDiagram is a diagram that replaces a Mermaid block of the Markdown report, in the order they come.
type typstDiagram struct {
	File string
	Alt  string
}

// newTypstDocument reads the Markdown report back into blocks. The title, the details of the model and the contents
// of the Markdown report are left out, as the template sets the title page and the outline; the chapters become the
// top level, and the Mermaid diagrams are replaced by the diagrams given, in their order, or left out when there are
// fewer.
func newTypstDocument(markdown []byte, diagrams []typstDiagram) []*typstBlock {
	parser := goldmark.New(goldmark.WithExtensions(extension.Table)).Parser()
	root := parser.Parse(text.NewReader(markdown))
	converter := &typstConverter{source: markdown, slugs: make(headingSlugs), diagrams: diagrams}
	blocks := make([]*typstBlock, 0)
	skipping := false // the title, the details of the model below it and the contents, which the template replaces
	for node := root.FirstChild(); node != nil; node = node.NextSibling() {
		if heading, ok := node.(*ast.Heading); ok {
			title := converter.plainText(heading)
			slug := converter.slugs.next(title) // as the Markdown writer counts them, the left out headings too
			skipping = heading.Level == 1 || heading.Level == 2 && title == "Contents"
			if skipping {
				continue
			}
			blocks = append(blocks, &typstBlock{
				Kind: "heading", Level: heading.Level - 1, Label: slug, Spans: converter.inlines(heading),
			})
			continue
		}
		if skipping {
			continue
		}
		blocks = append(blocks, converter.blocks(node)...)
	}
	return blocks
}

type typstConverter struct {
	source   []byte
	slugs    headingSlugs
	diagrams []typstDiagram
}

// blocks converts a block node of the Markdown report.
func (what *typstConverter) blocks(node ast.Node) []*typstBlock {
	switch node := node.(type) {
	case *ast.Paragraph, *ast.TextBlock:
		return []*typstBlock{{Kind: "paragraph", Spans: what.inlines(node)}}
	case *ast.List:
		list := &typstBlock{Kind: "list", Ordered: node.IsOrdered()}
		for item := node.FirstChild(); item != nil; item = item.NextSibling() {
			content := make([]*typstBlock, 0)
			for child := item.FirstChild(); child != nil; child = child.NextSibling() {
				content = append(content, what.blocks(child)...)
			}
			list.Items = append(list.Items, content)
		}
		return []*typstBlock{list}
	case *extensionast.Table:
		return []*typstBlock{what.table(node)}
	case *ast.FencedCodeBlock:
		if string(node.Language(what.source)) != "mermaid" || len(what.diagrams) == 0 {
			return nil
		}
		diagram := what.diagrams[0]
		what.diagrams = what.diagrams[1:]
		return []*typstBlock{{Kind: "image", Image: diagram.File, Alt: diagram.Alt}}
	default:
		return nil
	}
}

func (what *typstConverter) table(node *extensionast.Table) *typstBlock {
	table := &typstBlock{Kind: "table"}
	for row := node.FirstChild(); row != nil; row = row.NextSibling() {
		cells := make([][]typstSpan, 0)
		for cell := row.FirstChild(); cell != nil; cell = cell.NextSibling() {
			cells = append(cells, what.inlines(cell))
		}
		if _, isHeader := row.(*extensionast.TableHeader); isHeader {
			for index, cell := range cells {
				column := typstColumn{Title: plainSpans(cell)}
				if index < len(node.Alignments) {
					column.Number = node.Alignments[index] == extensionast.AlignRight
				}
				table.Columns = append(table.Columns, column)
			}
			continue
		}
		table.Rows = append(table.Rows, cells)
	}
	return table
}

// inlines converts the inline content of a node into spans.
func (what *typstConverter) inlines(node ast.Node) []typstSpan {
	spans := make([]typstSpan, 0)
	what.walkInlines(node, typstSpan{}, &spans)
	return mergedSpans(spans)
}

// walkInlines adds the spans of the children of the node, in the style of the node.
func (what *typstConverter) walkInlines(node ast.Node, style typstSpan, spans *[]typstSpan) {
	for child := node.FirstChild(); child != nil; child = child.NextSibling() {
		switch child := child.(type) {
		case *ast.Text:
			*spans = append(*spans, what.textSpans(child, style)...)
		case *ast.String:
			*spans = append(*spans, styled(style, string(child.Value)))
		case *ast.CodeSpan:
			span := styled(style, what.plainText(child))
			span.Code = true
			*spans = append(*spans, span)
		case *ast.Emphasis:
			what.walkInlines(child, emphasisStyle(style, child.Level), spans)
		case *ast.Link:
			what.walkInlines(child, linkStyle(style, string(child.Destination)), spans)
		case *ast.AutoLink:
			url := string(child.URL(what.source))
			*spans = append(*spans, linkStyle(styled(style, url), url))
		default:
			what.walkInlines(child, style, spans)
		}
	}
}

// textSpans is the text with its escapes resolved, followed by the line break that ends it, if any: a hard one as a
// break, a soft one as a space.
func (what *typstConverter) textSpans(text *ast.Text, style typstSpan) []typstSpan {
	spans := []typstSpan{styled(style, unescapedMarkdown(text.Segment.Value(what.source)))}
	switch {
	case text.HardLineBreak():
		spans = append(spans, typstSpan{Break: true})
	case text.SoftLineBreak():
		spans = append(spans, styled(style, " "))
	}
	return spans
}

// emphasisStyle is the style with the emphasis of the level: bold for two delimiters, italics for one.
func emphasisStyle(style typstSpan, level int) typstSpan {
	style.Bold = style.Bold || level >= 2
	style.Italic = style.Italic || level < 2
	return style
}

// styled is a span of the text in the style.
func styled(style typstSpan, text string) typstSpan {
	style.Text = text
	return style
}

// linkStyle is the style with the link to the destination: a reference to a heading for "#slug", the URL for an
// http(s) URL, and no link for any other destination.
func linkStyle(style typstSpan, destination string) typstSpan {
	if fragment, isFragment := strings.CutPrefix(destination, "#"); isFragment {
		style.Ref = fragment
		if unescaped, err := url.PathUnescape(fragment); err == nil {
			style.Ref = unescaped
		}
	} else if link, ok := httpLink(destination); ok {
		style.Link = link
	}
	return style
}

// mergedSpans joins the neighbouring spans of text that have the same formatting.
func mergedSpans(spans []typstSpan) []typstSpan {
	merged := make([]typstSpan, 0, len(spans))
	for _, span := range spans {
		if last := len(merged) - 1; last >= 0 && !span.Break && !merged[last].Break {
			previous := merged[last]
			previous.Text = span.Text
			if previous == span {
				merged[last].Text += span.Text
				continue
			}
		}
		merged = append(merged, span)
	}
	return merged
}

// plainText is the text of a node without its formatting.
func (what *typstConverter) plainText(node ast.Node) string {
	return plainSpans(what.inlines(node))
}

func plainSpans(spans []typstSpan) string {
	var result strings.Builder
	for _, span := range spans {
		result.WriteString(span.Text)
	}
	return result.String()
}

// unescapedMarkdown is the text of a Markdown text segment, with its backslash escapes and character references
// resolved, as a Markdown renderer shows it.
func unescapedMarkdown(segment []byte) string {
	return string(util.ResolveEntityNames(util.ResolveNumericReferences(util.UnescapePunctuations(segment))))
}
