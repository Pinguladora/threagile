package report

import (
	"html"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// basicMarkupTag matches the markup that threagile's own texts (the risk rules, the RAA intro)
// and many models use, the subset the PDF report renders: <b>, <i>, <u> and <br> exactly, and
// links in the form <a href="...">.
var basicMarkupTag = regexp.MustCompile(`<(/?)([biu])>|<br>|<a href="([^"<>]*)">|</a>`)

// basicMarkupElement is an element of the basic markup that is open.
type basicMarkupElement struct {
	name string // b, i, u or a
	link string // the http(s) URL of a link, "" for one that is left out as its URL is not http(s)
}

// basicMarkupVisitor receives what scanBasicMarkup finds in a text, in order. The text is
// untrusted: the visitor escapes it for its format.
type basicMarkupVisitor interface {
	// text is text between the markup, with the elements open around it, the innermost last.
	text(text string, open []basicMarkupElement)
	lineBreak()
	// start opens the element, which is the innermost one then.
	start(element basicMarkupElement)
	// end closes open[index]; the elements after it, which it was closed across, stay open.
	end(open []basicMarkupElement, index int)
}

// scanBasicMarkup reads text from the model, which is untrusted, as basic markup: <b>, <i>, <u>
// and <br>, and <a href="..."> with a link only when the URL is http or https. Everything else is
// text, a nested link and an end tag without an open element included. The elements still open
// at the end are closed, the innermost first.
func scanBasicMarkup(text string, visitor basicMarkupVisitor) {
	open := make([]basicMarkupElement, 0)
	position := 0
	for _, match := range basicMarkupTag.FindAllStringSubmatchIndex(text, -1) {
		visitor.text(text[position:match[0]], open)
		position = match[1]

		tag := text[match[0]:match[1]]
		switch {
		case tag == "<br>":
			visitor.lineBreak()
		case tag == "</a>":
			open = endBasicMarkup(visitor, open, "a", tag)
		case strings.HasPrefix(tag, "<a "):
			open = startBasicLink(visitor, open, html.UnescapeString(text[match[6]:match[7]]), tag)
		case text[match[2]:match[3]] == "/":
			open = endBasicMarkup(visitor, open, text[match[4]:match[5]], tag)
		default:
			element := basicMarkupElement{name: text[match[4]:match[5]]}
			visitor.start(element)
			open = append(open, element)
		}
	}
	visitor.text(text[position:], open)
	for index := range slices.Backward(open) {
		visitor.end(open[:index+1], index)
	}
}

// startBasicLink opens a link, leaving its tag as text when it is nested into another link.
func startBasicLink(visitor basicMarkupVisitor, open []basicMarkupElement, link, tag string) []basicMarkupElement {
	if slices.ContainsFunc(open, func(element basicMarkupElement) bool { return element.name == "a" }) {
		visitor.text(tag, open)
		return open
	}
	element := basicMarkupElement{name: "a"}
	if safeLink, ok := httpLink(link); ok {
		element.link = safeLink
	}
	visitor.start(element)
	return append(open, element)
}

// endBasicMarkup closes the innermost open element of the name. An end tag without an open
// element is text.
func endBasicMarkup(visitor basicMarkupVisitor, open []basicMarkupElement, name, tag string) []basicMarkupElement {
	index := len(open) - 1
	for index >= 0 && open[index].name != name {
		index--
	}
	if index < 0 {
		visitor.text(tag, open)
		return open
	}
	visitor.end(open, index)
	return slices.Delete(open, index, index+1)
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
