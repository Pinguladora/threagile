package report

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/goccy/go-graphviz"
)

// renderDiagramSVG lays out the DOT source and renders it with the SVG renderer of Graphviz
// itself, in-process. Unlike its PNG renderer (see graphviz_png.go) that one draws faithfully.
func renderDiagramSVG(dot []byte) ([]byte, error) {
	diagramRenderMutex.Lock()
	defer diagramRenderMutex.Unlock()

	ctx := context.Background()
	gv, err := graphviz.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("error creating graphviz: %w", err)
	}
	defer func() { _ = gv.Close() }()

	graph, err := graphviz.ParseBytes(dot)
	if err != nil {
		return nil, fmt.Errorf("error parsing the diagram source: %w", err)
	}
	defer func() { _ = graph.Close() }()

	var svg bytes.Buffer
	if err := gv.Render(ctx, graph, graphviz.SVG, &svg); err != nil {
		return nil, fmt.Errorf("error rendering the diagram: %w", err)
	}
	return svg.Bytes(), nil
}

const svgNamespace = "http://www.w3.org/2000/svg"

// inlineSVGElements are the SVG elements that inlineSVG keeps: the ones Graphviz draws with.
// Other elements are left out, but what is inside them is kept, so the shapes of a node that
// Graphviz wraps into a link still show; text is only kept directly inside <text> and <tspan>.
var inlineSVGElements = wordSet("svg g path polygon polyline ellipse circle rect line text tspan")

// inlineSVGAttributes are the attributes that inlineSVG keeps, the presentation attributes
// Graphviz writes. Ids (Graphviz numbers them from graph0 in every diagram), classes, event
// handlers, links and styles are left out.
var inlineSVGAttributes = wordSet("width height viewBox transform points d x y x1 y1 x2 y2 cx cy r rx ry " +
	"fill fill-opacity stroke stroke-width stroke-dasharray stroke-opacity text-anchor " +
	"font-family font-size font-weight font-style text-decoration baseline-shift")

var (
	// inlineSVGAttributeValue matches the values of colours, lengths, coordinates and font names,
	// so neither a url() (as in fill="url(...)") nor any markup gets through.
	inlineSVGAttributeValue = regexp.MustCompile(`^[-#%.,\w ]*$`)
	inlineSVGTransform      = regexp.MustCompile(`^( *(scale|rotate|translate)\([-.,\d ]*\))* *$`)
)

func wordSet(words string) map[string]bool {
	set := make(map[string]bool)
	for word := range strings.FieldsSeq(words) {
		set[word] = true
	}
	return set
}

// inlineSVG turns an SVG document of Graphviz into markup to inline into an HTML page. It
// writes the elements and attributes it knows anew, all values escaped, and leaves out the rest:
// the XML declaration, the doctype, comments (Graphviz puts the node names in them), the
// Graphviz titles, ids and anything active. The root element gets label as its accessible name.
func inlineSVG(svg []byte, label string) (string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(svg))
	decoder.Entity = xml.HTMLEntity

	inliner := svgInliner{label: label}
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("error reading the diagram: %w", err)
		}
		if err := inliner.write(token); err != nil {
			return "", err
		}
	}
	if inliner.result.Len() == 0 {
		return "", errors.New("error reading the diagram: no svg element")
	}
	return inliner.result.String(), nil
}

type svgInliner struct {
	label  string
	result strings.Builder
	open   []string // the open elements, "" for the ones left out
}

func (what *svgInliner) write(token xml.Token) error {
	switch token := token.(type) {
	case xml.StartElement:
		name, err := what.start(token)
		if err != nil {
			return err
		}
		what.open = append(what.open, name)
	case xml.EndElement:
		if name := what.open[len(what.open)-1]; name != "" {
			what.result.WriteString("</" + name + ">")
		}
		what.open = what.open[:len(what.open)-1]
	case xml.CharData:
		if n := len(what.open); n > 0 && (what.open[n-1] == "text" || what.open[n-1] == "tspan") {
			what.result.WriteString(html.EscapeString(string(token)))
		}
	}
	return nil
}

// start writes the start tag of an element if inlineSVG keeps it and returns its name, or
// returns "" for an element it leaves out.
func (what *svgInliner) start(element xml.StartElement) (string, error) {
	name := element.Name.Local
	root := len(what.open) == 0
	if root && (name != "svg" || element.Name.Space != svgNamespace) {
		return "", fmt.Errorf("error reading the diagram: the root element is %q, not svg", name)
	}
	if element.Name.Space != svgNamespace || !inlineSVGElements[name] {
		return "", nil
	}

	what.result.WriteString("<" + name)
	attributes := element.Attr
	if root {
		attributes = scalableSVGRoot(attributes)
	}
	for _, attribute := range attributes {
		if keepSVGAttribute(attribute) {
			what.result.WriteString(" " + attribute.Name.Local + `="` + html.EscapeString(attribute.Value) + `"`)
		}
	}
	if root {
		label := html.EscapeString(what.label)
		what.result.WriteString(` role="img" aria-label="` + label + `"><title>` + label + "</title>")
		return name, nil
	}
	what.result.WriteString(">")
	return name, nil
}

func keepSVGAttribute(attribute xml.Attr) bool {
	if attribute.Name.Space != "" || !inlineSVGAttributes[attribute.Name.Local] {
		return false
	}
	if attribute.Name.Local == "transform" {
		return inlineSVGTransform.MatchString(attribute.Value)
	}
	return inlineSVGAttributeValue.MatchString(attribute.Value)
}

// scalableSVGRoot makes the root element of a diagram scale to the width of the page: with the
// height left out, the browser derives it from the viewBox. Graphviz writes the viewBox before
// scaling to the DPI of the diagram, though, so the drawing would be cut off; the viewBox becomes
// the width and height in points instead, which the drawing scaled to the DPI fills exactly.
func scalableSVGRoot(attributes []xml.Attr) []xml.Attr {
	var width, height string
	for _, attribute := range attributes {
		switch attribute.Name.Local {
		case "width":
			width = attribute.Value
		case "height":
			height = attribute.Value
		}
	}
	widthPoints, widthErr := strconv.ParseFloat(strings.TrimSuffix(width, "pt"), 64)
	heightPoints, heightErr := strconv.ParseFloat(strings.TrimSuffix(height, "pt"), 64)
	if widthErr != nil || heightErr != nil || widthPoints <= 0 || heightPoints <= 0 {
		return attributes
	}
	viewBox := "0 0 " + strconv.FormatFloat(widthPoints, 'f', -1, 64) + " " +
		strconv.FormatFloat(heightPoints, 'f', -1, 64)
	return []xml.Attr{
		{Name: xml.Name{Local: "width"}, Value: width},
		{Name: xml.Name{Local: "viewBox"}, Value: viewBox},
	}
}
