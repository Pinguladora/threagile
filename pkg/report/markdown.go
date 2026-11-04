package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Pinguladora/threagile/pkg/types"
)

// WriteReportMarkdown writes the report as a single Markdown file in the dialect that GitHub,
// GitLab, MkDocs and Docusaurus have in common, with the diagrams as Mermaid code blocks, for
// keeping it in a repository or publishing it on a documentation site. It shows the chapters of
// the HTML report, in the same order.
func WriteReportMarkdown(parsedModel *types.Model, filename string, options ReportOptions) error {
	if err := os.WriteFile(filepath.Clean(filename), renderReportMarkdown(parsedModel, options), 0o600); err != nil {
		return fmt.Errorf("failed to write the Markdown report: %w", err)
	}
	return nil
}

// renderReportMarkdown renders the report twice: the first time to learn the anchors that the
// headings get, which depend on all headings before them, and the second time with links to them.
func renderReportMarkdown(parsedModel *types.Model, options ReportOptions) []byte {
	view := newReportView(parsedModel, options)
	first := newMarkdownWriter(nil)
	first.report(view)
	second := newMarkdownWriter(first.headings)
	second.report(view)
	return []byte(second.out.String())
}

// markdownWriter writes the report as Markdown. Everything it writes from the model goes through
// markdownText, markdownInline or markdownCode, which escape it.
type markdownWriter struct {
	out   strings.Builder
	slugs headingSlugs
	// anchors are the slugs of the headings by the anchors of the view, as the first pass found
	// them; headings collects them in this pass.
	anchors  map[string]string
	headings map[string]string
}

func newMarkdownWriter(anchors map[string]string) *markdownWriter {
	return &markdownWriter{slugs: make(headingSlugs), anchors: anchors, headings: make(map[string]string)}
}

// block writes the lines of a block, separated from the block before by an empty line.
func (what *markdownWriter) block(lines ...string) {
	if what.out.Len() > 0 {
		what.out.WriteString("\n")
	}
	for _, line := range lines {
		what.out.WriteString(line + "\n")
	}
}

// heading writes a heading of the plain text, which the anchor then links to, and returns its
// slug; an empty anchor is not linked to.
func (what *markdownWriter) heading(level int, anchor string, title string) string {
	what.block(strings.Repeat("#", level) + " " + markdownText(title))
	slug := what.slugs.next(title)
	what.alias(anchor, slug)
	return slug
}

// alias makes the anchor link to the heading of the slug.
func (what *markdownWriter) alias(anchor string, slug string) {
	if anchor != "" && slug != "" {
		what.headings[anchor] = slug
	}
}

// paragraph writes a paragraph of inline Markdown.
func (what *markdownWriter) paragraph(text string) {
	if text != "" {
		what.block(markdownBlockStart(text))
	}
}

// markup writes markup text as paragraphs, one for each of its lines.
func (what *markdownWriter) markup(text markupText) {
	for _, line := range markdownLines(text, true) {
		what.paragraph(line)
	}
}

// list writes a list of items of inline Markdown.
func (what *markdownWriter) list(items ...string) {
	if len(items) == 0 {
		return
	}
	lines := make([]string, 0, len(items))
	for _, item := range items {
		lines = append(lines, "- "+markdownBlockStart(item))
	}
	what.block(lines...)
}

// markdownEntry is an item of a list with paragraphs of markup text below its term, as the HTML
// report shows a definition list.
type markdownEntry struct {
	term string // inline Markdown
	text markupText
}

// entries writes a list of entries. The paragraphs of an item are indented by four spaces, which
// Python-Markdown requires and CommonMark accepts.
func (what *markdownWriter) entries(entries ...markdownEntry) {
	if len(entries) == 0 {
		return
	}
	lines := make([]string, 0, 3*len(entries))
	for index, entry := range entries {
		if index > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, "- "+markdownBlockStart(entry.term))
		for _, line := range markdownLines(entry.text, true) {
			lines = append(lines, "", "    "+markdownBlockStart(line))
		}
	}
	what.block(lines...)
}

// The titles of the columns and properties that the tables of the report share.
const (
	columnSeverity = "Severity"
	columnStatus   = "Status"
	columnSTRIDE   = "STRIDE"
	columnTags     = "Tags"
	columnUsage    = "Usage"
)

// markdownColumn is a column of a table: its title and whether its numbers align to the right.
type markdownColumn struct {
	title  string
	number bool
}

// table writes a table of cells of inline Markdown, which hold no line breaks and, escaped, no pipes.
func (what *markdownWriter) table(columns []markdownColumn, rows ...[]string) {
	header, delimiter := make([]string, 0, len(columns)), make([]string, 0, len(columns))
	for _, column := range columns {
		header = append(header, markdownText(column.title))
		if column.number {
			delimiter = append(delimiter, "---:")
		} else {
			delimiter = append(delimiter, "---")
		}
	}
	lines := make([]string, 0, 2+len(rows))
	lines = append(lines, markdownRow(header), markdownRow(delimiter))
	for _, row := range rows {
		lines = append(lines, markdownRow(row))
	}
	what.block(lines...)
}

func markdownRow(cells []string) string {
	return "| " + strings.Join(cells, " | ") + " |"
}

// properties writes a table of the properties of an object, by their names.
func (what *markdownWriter) properties(rows ...[]string) {
	what.table([]markdownColumn{{title: "Property"}, {title: "Value"}}, rows...)
}

// ref is a reference to an object of the model, linked to its heading if it has one.
func (what *markdownWriter) ref(ref viewRef) string {
	return what.linked(markdownText(ref.Title), ref.Anchor)
}

// linked links inline Markdown to the heading of the anchor, if there is one.
func (what *markdownWriter) linked(text string, anchor string) string {
	if slug := what.anchors[anchor]; anchor != "" && slug != "" && text != "" {
		return markdownLink(text, "#"+slug)
	}
	return text
}

// refs are references, separated by commas, or none.
func (what *markdownWriter) refs(refs []viewRef) string {
	if len(refs) == 0 {
		return viewNone
	}
	result := make([]string, 0, len(refs))
	for _, ref := range refs {
		result = append(result, what.ref(ref))
	}
	return strings.Join(result, ", ")
}

// riskLink is the title of a risk, linked to its details.
func (what *markdownWriter) riskLink(risk *viewRisk) string {
	return what.linked(strings.Join(markdownLines(risk.Title, false), " "), risk.Anchor)
}

// quoted is the title of the model in quotes, as the texts of the report name it.
func quoted(title string) string {
	return `"` + markdownText(title) + `"`
}

// strong is bold inline Markdown.
func strong(text string) string {
	return "**" + text + "**"
}

// plural is the count with the noun, in the plural unless the count is one.
func plural(count int, singular string, pluralForm string) string {
	if count == 1 {
		return strconv.Itoa(count) + " " + singular
	}
	return strconv.Itoa(count) + " " + pluralForm
}
