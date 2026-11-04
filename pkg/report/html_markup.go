package report

import (
	"html"
	"html/template"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// basicMarkupTag matches the markup that threagile's own texts (the risk rules, the RAA intro)
// and many models use, the subset the PDF report renders: <b>, <i>, <u> and <br> exactly, and
// links in the form <a href="...">.
var basicMarkupTag = regexp.MustCompile(`<(/?)([biu])>|<br>|<a href="([^"<>]*)">|</a>`)

// basicMarkupElement is an element that basicMarkup opened and has to close again.
type basicMarkupElement struct {
	name string
	open string // the start tag, "" for a link that is left out as its URL is not http(s)
}

// basicMarkup turns text from the model, which is untrusted, into HTML: <b>, <i>, <u> and <br>
// become those elements, and <a href="..."> a link when the URL is http or https. Everything
// else is escaped, and elements are closed (and nested) properly, even where the text does not.
func basicMarkup(text string) template.HTML {
	var result strings.Builder
	open := make([]basicMarkupElement, 0)
	position := 0
	for _, match := range basicMarkupTag.FindAllStringSubmatchIndex(text, -1) {
		result.WriteString(html.EscapeString(text[position:match[0]]))
		position = match[1]

		tag := text[match[0]:match[1]]
		switch {
		case tag == "<br>":
			result.WriteString("<br>")
		case tag == "</a>":
			open = closeBasicMarkup(&result, open, "a", tag)
		case strings.HasPrefix(tag, "<a "):
			open = openBasicLink(&result, open, html.UnescapeString(text[match[6]:match[7]]), tag)
		case text[match[2]:match[3]] == "/":
			open = closeBasicMarkup(&result, open, text[match[4]:match[5]], tag)
		default:
			result.WriteString(tag)
			open = append(open, basicMarkupElement{name: text[match[4]:match[5]], open: tag})
		}
	}
	result.WriteString(html.EscapeString(text[position:]))
	for _, element := range slices.Backward(open) {
		writeEndTag(&result, element)
	}
	return template.HTML(result.String()) // #nosec G203 -- built from escaped text and fixed tags only
}

// openBasicLink opens a link, leaving out the tag (but not the text) of a link that is nested
// into another or whose URL is not http(s).
func openBasicLink(result *strings.Builder, open []basicMarkupElement, link, tag string) []basicMarkupElement {
	if slices.ContainsFunc(open, func(element basicMarkupElement) bool { return element.name == "a" }) {
		result.WriteString(html.EscapeString(tag))
		return open
	}
	element := basicMarkupElement{name: "a"}
	if safeLink, ok := httpLink(link); ok {
		element.open = `<a href="` + html.EscapeString(safeLink) + `" rel="noopener noreferrer">`
		result.WriteString(element.open)
	}
	return append(open, element)
}

// closeBasicMarkup closes the innermost open element of the name; the elements opened inside it
// are closed before and opened again after it. An end tag without an open element is text.
func closeBasicMarkup(result *strings.Builder, open []basicMarkupElement, name, tag string) []basicMarkupElement {
	index := len(open) - 1
	for index >= 0 && open[index].name != name {
		index--
	}
	if index < 0 {
		result.WriteString(html.EscapeString(tag))
		return open
	}

	for i := len(open) - 1; i >= index; i-- {
		writeEndTag(result, open[i])
	}
	for _, element := range open[index+1:] {
		result.WriteString(element.open)
	}
	return slices.Delete(open, index, index+1)
}

func writeEndTag(result *strings.Builder, element basicMarkupElement) {
	if element.open != "" {
		result.WriteString("</" + element.name + ">")
	}
}

// linkHost matches the host names and IP addresses that httpLink accepts.
var linkHost = regexp.MustCompile(`^([-.\w]+|\[[:.\da-fA-F]+\])(:\d+)?$`)

// httpLink returns the link in its normalized form if it is an absolute http or https URL.
func httpLink(link string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(link))
	if err != nil || !linkHost.MatchString(parsed.Host) || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", false
	}
	return parsed.String(), true
}
