package report_test

import (
	"bytes"
	"encoding/json"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Pinguladora/threagile/pkg/report"
	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"golang.org/x/net/html"
)

// TestMarkdownReportOfAHostileModelIsInert renders the report of a model with hostile text in
// every field, ids included, as GitHub-flavoured Markdown, which goldmark parses as CommonMark
// does: no raw HTML may get through, no link may go anywhere but to a heading or to http(s), no
// text may break out of a table cell or a code block, and no Mermaid label out of its diagram.
func TestMarkdownReportOfAHostileModelIsInert(t *testing.T) {
	parsedModel, options := analyzeHostileModel(t)
	source := writeMarkdownReport(t, parsedModel, options)
	page := renderGFM(t, source)

	// goldmark leaves raw HTML out unless told otherwise, and says so
	assert.NotContains(t, string(page), "raw HTML omitted")
	document, err := html.Parse(bytes.NewReader(page))
	require.NoError(t, err)
	headings, links, texts, mermaid := make([]string, 0), make([]string, 0), new(strings.Builder), make([]string, 0)
	blocks := 0
	for node := range document.Descendants() {
		switch node.Type {
		case html.TextNode:
			texts.WriteString(node.Data)
		case html.ElementNode:
			assertInertElement(t, node)
			switch node.Data {
			case "h1", "h2", "h3", "h4", "h5", "h6":
				headings = append(headings, textOf(node))
			case "a":
				links = append(links, attributeOf(node, "href"))
			case "pre":
				blocks++
			case "code":
				if attributeOf(node, "class") == "language-mermaid" {
					mermaid = append(mermaid, textOf(node))
				}
			}
		default:
		}
	}

	assertLinksResolve(t, links, githubAnchors(headings))
	// both diagrams, which are the only code blocks: an item's indented paragraphs are no code
	require.Len(t, mermaid, 2)
	assert.Equal(t, 2, blocks)
	for _, diagram := range mermaid {
		assertMermaidFlowchart(t, diagram)
	}
	assert.Equal(t, mermaidBlocks(source), mermaid, "the diagrams as written, so no text ended a code block")
	assertTablesKeepTheirCells(t, source)
	assertNoMDXSyntax(t, source)

	// the hostile text is shown, as text
	assert.Contains(t, texts.String(), `<script>alert("x")</script>"><img src=x onerror=alert(1)></style>`)
	assert.Contains(t, texts.String(), `<B>upper</B></title><svg onload=alert(5)>'`)
	assert.Contains(t, texts.String(), `x"><script>alert(8)</script>`, "the hostile id")
	assert.Contains(t, texts.String(), `<a href="javascript:alert(3)">link</a>`, "a title is no markup")
}

// TestMarkdownReportOfTheExample checks the Markdown report of the example model beyond its
// golden file: every risk is in it, every link goes to a heading as GitHub names its anchor, and
// the diagrams are well-formed.
func TestMarkdownReportOfTheExample(t *testing.T) {
	outputs := generateOutputs(t, exampleModel)
	source := outputs["THREAT_MODEL.md"]
	require.NotEmpty(t, source)

	var risks []struct {
		SyntheticID string `json:"synthetic_id"`
	}
	require.NoError(t, json.Unmarshal(outputs["risks.json"], &risks))
	require.NotEmpty(t, risks)
	for _, risk := range risks {
		assert.Contains(t, string(source), "`"+risk.SyntheticID+"`")
	}

	lines := strings.Split(string(source), "\n")
	require.True(t, strings.HasPrefix(lines[0], "# "), "the title comes first")
	headings, level := make([]string, 0), 0
	inCode := false
	for _, line := range lines {
		if strings.HasPrefix(line, "```") {
			inCode = !inCode
		}
		if heading := regexp.MustCompile(`^(#+) (.*)$`).FindStringSubmatch(line); heading != nil && !inCode {
			assert.LessOrEqual(t, len(heading[1]), level+1, "heading %q skips a level", line)
			assert.False(t, len(heading[1]) == 1 && level > 0, "a second title %q", line)
			level = len(heading[1])
			headings = append(headings, unescapeMarkdown(heading[2]))
		}
	}
	anchors := githubAnchors(headings)
	links := regexp.MustCompile(`\]\((#[^)]*)\)`).FindAllStringSubmatch(string(source), -1)
	require.NotEmpty(t, links)
	for _, link := range links {
		assert.True(t, anchors[strings.TrimPrefix(link[1], "#")], "link to the missing anchor %s", link[1])
	}

	diagrams := mermaidBlocks(source)
	require.Len(t, diagrams, 2)
	for _, diagram := range diagrams {
		assertMermaidFlowchart(t, diagram)
	}
	assert.Contains(t, diagrams[0], "subgraph ", "the trust boundaries")
	assert.Contains(t, diagrams[0], " ==>", "a link that also receives data back")
	assert.Contains(t, diagrams[0], "class ", "the assets out of scope")
	assertTablesKeepTheirCells(t, source)
	assertNoMDXSyntax(t, source)
}

func writeMarkdownReport(t *testing.T, parsedModel *types.Model, options report.ReportOptions) []byte {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "THREAT_MODEL.md")
	require.NoError(t, report.WriteReportMarkdown(parsedModel, filename, options))
	return readFile(t, filename)
}

func renderGFM(t *testing.T, source []byte) []byte {
	t.Helper()
	var page bytes.Buffer
	// GitHub-flavoured Markdown, with the alignment of table cells as attributes rather than styles
	gfm := goldmark.New(goldmark.WithExtensions(extension.Linkify, extension.Strikethrough, extension.TaskList,
		extension.NewTable(extension.WithTableCellAlignMethod(extension.TableCellAlignAttribute))))
	require.NoError(t, gfm.Convert(source, &page))
	return page.Bytes()
}

func textOf(node *html.Node) string {
	var text strings.Builder
	for descendant := range node.Descendants() {
		if descendant.Type == html.TextNode {
			text.WriteString(descendant.Data)
		}
	}
	return text.String()
}

func assertLinksResolve(t *testing.T, links []string, anchors map[string]bool) {
	t.Helper()
	require.NotEmpty(t, links)
	for _, link := range links {
		if anchor, isAnchor := strings.CutPrefix(link, "#"); isAnchor {
			unescaped, err := url.PathUnescape(anchor)
			require.NoError(t, err)
			assert.True(t, anchors[unescaped], "link to the missing anchor %q", link)
			continue
		}
		parsed, err := url.Parse(link)
		if assert.NoError(t, err, link) {
			assert.Contains(t, []string{"http", "https"}, parsed.Scheme, "link %q", link)
		}
	}
}

// githubWordless matches what GitHub drops from the text of a heading for its anchor.
var githubWordless = regexp.MustCompile(`[^\p{L}\p{M}\p{Nd}\p{Pc}\- ]`)

// githubAnchors are the anchors that GitHub gives the headings, the way it documents them: the
// text in lower case, without punctuation, spaces as hyphens, and a number appended to repeats.
func githubAnchors(headings []string) map[string]bool {
	anchors, counts := make(map[string]bool), make(map[string]int)
	for _, heading := range headings {
		anchor := strings.ReplaceAll(githubWordless.ReplaceAllString(strings.ToLower(heading), ""), " ", "-")
		if counts[anchor] > 0 {
			anchors[anchor+"-"+strconv.Itoa(counts[anchor])] = true
		} else {
			anchors[anchor] = true
		}
		counts[anchor]++
	}
	return anchors
}

// unescapeMarkdown is the text that inline Markdown without markup shows.
func unescapeMarkdown(text string) string {
	return html.UnescapeString(regexp.MustCompile(`\\(.)`).ReplaceAllString(text, "$1"))
}

// mermaidBlocks are the contents of the Mermaid code blocks of a Markdown file.
func mermaidBlocks(source []byte) []string {
	matches := regexp.MustCompile("(?ms)^```mermaid\n(.*?)^```$").FindAllSubmatch(source, -1)
	blocks := make([]string, 0, len(matches))
	for _, block := range matches {
		blocks = append(blocks, string(block[1]))
	}
	return blocks
}

var (
	mermaidLabelText = `"[^"]*"`
	mermaidStatement = regexp.MustCompile(`^(?:` +
		`(?P<flowchart>flowchart (?:TB|LR))|` +
		`subgraph (?P<subgraph>\w+) \[` + mermaidLabelText + `\]|` +
		`(?P<end>end)|` +
		`(?P<node>\w+)(?:\[` + mermaidLabelText + `\]|\(\[` + mermaidLabelText + `\]\)|\[\(` + mermaidLabelText +
		`\)\]|\{\{` + mermaidLabelText + `\}\})|` +
		`(?P<source>\w+) (?:-->|==>|-\.->)(?:\|` + mermaidLabelText + `\|)? (?P<target>\w+)|` +
		`classDef \w+ [-\w: ]+|` +
		`class (?P<classed>\w+(?:,\w+)*) \w+` +
		`)$`)
	mermaidLabels = regexp.MustCompile(mermaidLabelText)
	// mermaidEntity is an entity code, which the labels write their special characters as.
	mermaidEntity = regexp.MustCompile(`#\w+;`)
)

// assertMermaidFlowchart checks a flowchart against the part of Mermaid's grammar that the
// report writes: every line is a statement, subgraphs end, node ids are unique and not reserved
// words, edges and classes refer to nodes, and labels hold nothing raw that Mermaid or HTML reads.
func assertMermaidFlowchart(t *testing.T, diagram string) {
	t.Helper()
	nodes, subgraphs, depth := make(map[string]bool), make(map[string]bool), 0
	references := make([]string, 0)
	for index, line := range strings.Split(strings.TrimSuffix(diagram, "\n"), "\n") {
		statement := strings.TrimLeft(line, " ")
		match := mermaidStatement.FindStringSubmatch(statement)
		if !assert.NotNil(t, match, "line %d is no statement: %q", index+1, line) {
			continue
		}
		group := func(name string) string { return match[mermaidStatement.SubexpIndex(name)] }
		assert.Equal(t, index == 0, group("flowchart") != "", "the flowchart header on line %d", index+1)
		switch {
		case group("subgraph") != "":
			assert.False(t, subgraphs[group("subgraph")] || nodes[group("subgraph")], "repeated id %q", line)
			subgraphs[group("subgraph")] = true
			depth++
		case group("end") != "":
			depth--
			assert.GreaterOrEqual(t, depth, 0, "end without subgraph on line %d", index+1)
		case group("node") != "":
			assert.False(t, subgraphs[group("node")] || nodes[group("node")], "repeated id %q", line)
			assert.NotEqual(t, "end", group("node"))
			nodes[group("node")] = true
		case group("source") != "":
			references = append(references, group("source"), group("target"))
		case group("classed") != "":
			references = append(references, strings.Split(group("classed"), ",")...)
		}
		for _, label := range mermaidLabels.FindAllString(statement, -1) {
			raw := mermaidEntity.ReplaceAllString(strings.Trim(label, `"`), "")
			assert.NotContains(t, raw, "#", label)
			assert.False(t, strings.ContainsAny(raw, ";`<>&|"), "label %s", label)
		}
	}
	assert.Zero(t, depth, "every subgraph ends")
	for _, reference := range references {
		assert.True(t, nodes[reference], "%s is no node", reference)
	}
}

// assertTablesKeepTheirCells checks that every row of a table has as many cells as its header,
// so that no text broke out of a cell.
func assertTablesKeepTheirCells(t *testing.T, source []byte) {
	t.Helper()
	columns := 0
	for line := range strings.SplitSeq(string(source), "\n") {
		if !strings.HasPrefix(line, "| ") {
			columns = 0
			continue
		}
		cells := strings.Count(line, "|") - strings.Count(line, `\|`)
		if columns == 0 {
			columns = cells
		}
		assert.Equal(t, columns, cells, "row %q", line)
	}
}

// assertNoMDXSyntax checks that outside code nothing starts JSX, an expression or an ES module,
// which Docusaurus would compile and run, as it reads Markdown as MDX: no <, and { and } escaped.
func assertNoMDXSyntax(t *testing.T, source []byte) {
	t.Helper()
	inCode := false
	for line := range strings.SplitSeq(string(source), "\n") {
		if strings.HasPrefix(line, "```") {
			inCode = !inCode
			continue
		}
		if inCode {
			continue
		}
		text := regexp.MustCompile("`[^`]*`").ReplaceAllString(line, "")
		assert.NotContains(t, text, "<", line)
		assert.NotRegexp(t, `(^|[^\\])[{}]`, text, line)
		assert.NotRegexp(t, `^\s*(import|export)\s`, text, line)
	}
}
