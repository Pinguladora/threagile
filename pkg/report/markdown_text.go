package report

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// markdownEscaper escapes model text, which is untrusted, for inline Markdown. It keeps to what
// GitHub, GitLab, MkDocs (Python-Markdown) and Docusaurus (MDX) all read the same way: a
// backslash where Python-Markdown accepts it as an escape, and a character reference elsewhere.
// No HTML gets through, nor emphasis, code, links, JSX expressions or MkDocs attribute lists ({}),
// GitHub's strikethrough and math ($), or a pipe that would end a table cell. The underscore is
// left to markdownEscape.
var markdownEscaper = strings.NewReplacer(
	`\`, `\\`, "`", "\\`", "*", `\*`, "[", `\[`, "]", `\]`, "{", `\{`, "}", `\}`, "#", `\#`,
	"<", "&lt;", ">", "&gt;", "&", "&amp;", "|", "&#124;", "~", "&#126;", "$", "&#36;",
)

// markdownEscape escapes model text for inline Markdown. An underscore between two letters or
// digits stays as it is, as it cannot start or end emphasis there, which keeps ids such as
// customer_data readable in the file.
func markdownEscape(text string) string {
	escaped := []rune(markdownEscaper.Replace(text))
	var result strings.Builder
	for index, r := range escaped {
		if r == '_' && (index == 0 || index == len(escaped)-1 ||
			!isLetterOrDigit(escaped[index-1]) || !isLetterOrDigit(escaped[index+1])) {
			result.WriteByte('\\')
		}
		result.WriteRune(r)
	}
	return result.String()
}

func isLetterOrDigit(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// markdownText is plain model text as inline Markdown, on one line.
func markdownText(text string) string {
	return strings.TrimSpace(markdownEscape(collapseSpace(text)))
}

// collapseSpace turns every run of white space and control characters into a single space, as
// HTML shows text, so that model text stays on its line: in a table cell, a list item or a heading.
func collapseSpace(text string) string {
	var result strings.Builder
	space := false
	for _, r := range text {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			space = true
			continue
		}
		if space {
			result.WriteByte(' ')
			space = false
		}
		result.WriteRune(r)
	}
	if space {
		result.WriteByte(' ')
	}
	return result.String()
}

// markdownOrderedListStart matches what would start an ordered list at the start of a line.
var markdownOrderedListStart = regexp.MustCompile(`^\d{1,9}[.)]`)

// markdownBlockStart escapes what would make a line of escaped text something else than a
// paragraph or the text of a list item: a list, a thematic break or a setext underline (+, -,
// =, a number with . or )), an MkDocs admonition or definition (!, ?, :), a Docusaurus
// admonition (:::), or the import and export statements that MDX would run as JavaScript.
func markdownBlockStart(line string) string {
	if line == "" {
		return line
	}
	switch line[0] {
	case '+', '-', '!':
		return `\` + line
	case '=', '?', ':':
		return markdownCharacterReference(line[0]) + line[1:]
	}
	if match := markdownOrderedListStart.FindStringIndex(line); match != nil {
		return line[:match[1]-1] + `\` + line[match[1]-1:]
	}
	if strings.HasPrefix(line, "import ") || strings.HasPrefix(line, "export ") {
		return markdownCharacterReference(line[0]) + line[1:]
	}
	return line
}

func markdownCharacterReference(character byte) string {
	return "&#" + strconv.Itoa(int(character)) + ";"
}

// markdownCode is an id as code, or as text when it holds what a code span cannot: a backtick,
// a pipe, which ends a table cell even in a code span, or a line break.
func markdownCode(id string) string {
	if id == "" || strings.ContainsAny(id, "`|") || collapseSpace(id) != id || strings.TrimSpace(id) != id {
		return markdownText(id)
	}
	return "`" + id + "`"
}

// markdownURL writes an http(s) URL for a link destination, percent-encoding everything that
// Markdown, a table or MDX might read otherwise: space, quotes, brackets, braces, the pipe and
// the backslash, and all that is not ASCII.
func markdownURL(link string) string {
	var result strings.Builder
	for _, b := range []byte(link) {
		if b > ' ' && b < 0x7f && !strings.ContainsRune("\"'()<>[]{}|\\`^", rune(b)) {
			result.WriteByte(b)
		} else {
			_, _ = fmt.Fprintf(&result, "%%%02X", b)
		}
	}
	return result.String()
}

// markdownLink links the Markdown text to the destination.
func markdownLink(text, destination string) string {
	return "[" + text + "](" + destination + ")"
}

// markdownSpan is text of basic markup with the style it has.
type markdownSpan struct {
	text   string
	bold   bool
	italic bool   // also for underlined text, as Markdown has no underline
	link   string // the http(s) URL of the link that the text is in
}

// markdownMarkup collects the spans of basic markup, line by line, for markdownLines. It shows
// the elements as flat runs of emphasis, which survive mis-nested markup, rather than nested
// delimiters, which Markdown parsers read differently.
type markdownMarkup struct {
	lines [][]markdownSpan
}

func (what *markdownMarkup) text(text string, open []basicMarkupElement) {
	if text == "" {
		return
	}
	span := markdownSpan{text: text}
	for _, element := range open {
		switch element.name {
		case "b":
			span.bold = true
		case "a":
			span.link = element.link
		default:
			span.italic = true
		}
	}
	if len(what.lines) == 0 {
		what.lines = append(what.lines, nil)
	}
	what.lines[len(what.lines)-1] = append(what.lines[len(what.lines)-1], span)
}

func (what *markdownMarkup) lineBreak() {
	if len(what.lines) == 0 {
		what.lines = append(what.lines, nil)
	}
	what.lines = append(what.lines, nil)
}

func (what *markdownMarkup) start(basicMarkupElement) {}

func (what *markdownMarkup) end([]basicMarkupElement, int) {}

// markdownLines is markup text as inline Markdown, a line for each line of the text, empty lines
// left out. With links false, links show as their text only, as in the text of another link.
func markdownLines(text markupText, links bool) []string {
	var markup markdownMarkup
	scanBasicMarkup(string(text), &markup)
	lines := make([]string, 0, len(markup.lines))
	for _, spans := range markup.lines {
		if line := markdownLine(spans, links); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// markdownInline is markup text as inline Markdown on one line, its line breaks as spaces.
func markdownInline(text markupText) string {
	return strings.Join(markdownLines(text, true), " ")
}

// markdownLine renders the spans of a line: the runs of the same link as a link, and within
// them the runs of the same style as emphasis.
func markdownLine(spans []markdownSpan, links bool) string {
	if !links {
		spans = slices.Clone(spans)
		for index := range spans {
			spans[index].link = ""
		}
	}
	var line strings.Builder
	for index := 0; index < len(spans); {
		end := index + 1
		for end < len(spans) && spans[end].link == spans[index].link {
			end++
		}
		text := markdownEmphasis(spans[index:end])
		if trimmed := strings.TrimSpace(text); spans[index].link != "" && trimmed != "" {
			text = leadingSpace(text) + markdownLink(trimmed, markdownURL(spans[index].link)) + trailingSpace(text)
		}
		line.WriteString(text)
		index = end
	}
	return strings.Join(strings.Fields(line.String()), " ")
}

// markdownEmphasis renders spans as text, each run of bold text in strong emphasis and within
// it each run of italic text in emphasis. The delimiters go right around the text, with the
// spaces outside, as Markdown requires; _ rather than * for emphasis keeps them apart from **.
func markdownEmphasis(spans []markdownSpan) string {
	var result strings.Builder
	for index := 0; index < len(spans); {
		end := index + 1
		for end < len(spans) && spans[end].bold == spans[index].bold {
			end++
		}
		text := markdownItalics(spans[index:end])
		if spans[index].bold {
			text = delimited(text, "**")
		}
		result.WriteString(text)
		index = end
	}
	return result.String()
}

func markdownItalics(spans []markdownSpan) string {
	var result strings.Builder
	for index := 0; index < len(spans); {
		var text strings.Builder
		end := index
		for ; end < len(spans) && spans[end].italic == spans[index].italic; end++ {
			text.WriteString(spans[end].text)
		}
		escaped := markdownEscape(collapseSpace(text.String()))
		if spans[index].italic {
			escaped = delimited(escaped, "_")
		}
		result.WriteString(escaped)
		index = end
	}
	return result.String()
}

// delimited puts the delimiter around the text, inside its spaces; text of spaces only stays as it is.
func delimited(text string, delimiter string) string {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return text
	}
	return leadingSpace(text) + delimiter + trimmed + delimiter + trailingSpace(text)
}

func leadingSpace(text string) string {
	if strings.HasPrefix(text, " ") {
		return " "
	}
	return ""
}

func trailingSpace(text string) string {
	if strings.HasSuffix(text, " ") {
		return " "
	}
	return ""
}

// headingSlugs makes the anchors of the headings of a document as GitHub does, which Docusaurus
// does too: the text in lower case without punctuation, spaces as hyphens, and -1, -2 and so on
// appended to repeated ones.
type headingSlugs map[string]int

func (what headingSlugs) next(heading string) string {
	base := githubSlug(heading)
	slug := base
	for _, taken := what[slug]; taken; _, taken = what[slug] {
		what[base]++
		slug = base + "-" + strconv.Itoa(what[base])
	}
	what[slug] = 0
	return slug
}

// githubSlug keeps the letters, marks, digits, connector punctuation (_) and hyphens of a
// heading's text in lower case, and turns its spaces into hyphens.
func githubSlug(heading string) string {
	var slug strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(collapseSpace(heading))) {
		switch {
		case r == ' ':
			slug.WriteByte('-')
		case r == '-' || unicode.IsLetter(r) || unicode.IsMark(r) || unicode.Is(unicode.Nd, r) || unicode.Is(unicode.Pc, r):
			slug.WriteRune(r)
		}
	}
	return slug.String()
}
