package report

import (
	"html"
	"html/template"
	"strings"
)

// htmlMarkup is markup text of the report view in HTML.
func htmlMarkup(text markupText) template.HTML {
	return basicMarkup(string(text))
}

// basicMarkup turns text from the model, which is untrusted, into HTML: <b>, <i>, <u> and <br>
// become those elements, and <a href="..."> a link when the URL is http or https. Everything
// else is escaped, and elements are closed (and nested) properly, even where the text does not.
func basicMarkup(text string) template.HTML {
	var result htmlMarkupWriter
	scanBasicMarkup(text, &result)
	return template.HTML(result.out.String()) // #nosec G203 -- built from escaped text and fixed tags only
}

// htmlMarkupWriter writes basic markup as HTML. An element that is closed across others closes
// them before and opens them again after it; a link that is left out writes no tags.
type htmlMarkupWriter struct {
	out strings.Builder
}

func (what *htmlMarkupWriter) text(text string, _ []basicMarkupElement) {
	what.out.WriteString(html.EscapeString(text))
}

func (what *htmlMarkupWriter) lineBreak() {
	what.out.WriteString("<br>")
}

func (what *htmlMarkupWriter) start(element basicMarkupElement) {
	switch {
	case element.name != "a":
		what.out.WriteString("<" + element.name + ">")
	case element.link != "":
		what.out.WriteString(`<a href="` + html.EscapeString(element.link) + `" rel="noopener noreferrer">`)
	}
}

func (what *htmlMarkupWriter) end(open []basicMarkupElement, index int) {
	for i := len(open) - 1; i >= index; i-- {
		if open[i].name != "a" || open[i].link != "" {
			what.out.WriteString("</" + open[i].name + ">")
		}
	}
	for _, element := range open[index+1:] {
		what.start(element)
	}
}
