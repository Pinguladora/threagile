// Copyright (c) 2020 Masaaki Goshima. MIT License:
// https://github.com/goccy/go-graphviz/blob/v0.2.10/LICENSE
//
// The PNG renderer below is derived from gvc/image_renderer.go of go-graphviz v0.2.10.
// Changes from the original:
//   - edges are always stroked: the WASM bridge reports every edge spline as filled,
//     which turned edges into filled wedges, and the same flag is unreliable for
//     arrowheads and unfilled nodes, so filling is decided from the object instead
//     (for an arrow, from the arrowhead or arrowtail attribute of the end it is at);
//   - shapes are filled and then outlined, clusters included;
//   - pen widths, dash patterns (those of the Graphviz cairo renderer, with butt
//     caps) and font sizes scale with the output DPI;
//   - colours keep their alpha, so transparent pens draw nothing;
//   - text uses the embedded DejaVu Sans font (regular weight only) and is centred
//     in the box Graphviz reserved for it, shrunk where it would not fit;
//   - images, bold, italic and output to a file name are not supported.

package report

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"math"
	"strings"
	"sync"

	"github.com/fogleman/gg"
	"github.com/goccy/go-graphviz"
	"github.com/goccy/go-graphviz/gvc"
	"github.com/golang/freetype/truetype"
	"golang.org/x/image/font"
)

// DejaVu Sans 2.37, see fonts/DejaVuSans-LICENSE. Its widths are close to the
// Verdana metrics that Graphviz uses to size the labels.
//
//go:embed fonts/DejaVuSans.ttf
var diagramFontTTF []byte

// The library runs one global WASM instance, which must not be entered concurrently.
var diagramRenderMutex sync.Mutex

// renderDiagramPNG lays out the DOT source and renders it to PNG in-process.
func renderDiagramPNG(dot []byte) ([]byte, error) {
	diagramRenderMutex.Lock()
	defer diagramRenderMutex.Unlock()

	ctx := context.Background()
	diagramFont, err := truetype.Parse(diagramFontTTF)
	if err != nil {
		return nil, fmt.Errorf("error parsing the diagram font: %w", err)
	}
	renderPlugin, err := gvc.NewRenderPlugin(ctx, string(graphviz.PNG), &pngRenderer{
		DefaultRenderEngine: &gvc.DefaultRenderEngine{},
		font:                diagramFont,
		faces:               make(map[float64]font.Face),
	})
	if err != nil {
		return nil, fmt.Errorf("error creating the graphviz render plugin: %w", err)
	}
	devicePlugin, err := gvc.PNGDevicePlugin(ctx)
	if err != nil {
		return nil, fmt.Errorf("error creating the graphviz device plugin: %w", err)
	}
	gv, err := graphviz.NewWithPlugins(ctx, renderPlugin, devicePlugin)
	if err != nil {
		return nil, fmt.Errorf("error creating graphviz: %w", err)
	}
	defer func() { _ = gv.Close() }()

	graph, err := graphviz.ParseBytes(dot)
	if err != nil {
		return nil, fmt.Errorf("error parsing the diagram source: %w", err)
	}
	defer func() { _ = graph.Close() }()

	var png bytes.Buffer
	if err := gv.Render(ctx, graph, graphviz.PNG, &png); err != nil {
		return nil, fmt.Errorf("error rendering the diagram: %w", err)
	}
	return png.Bytes(), nil
}

type pngRenderer struct {
	*gvc.DefaultRenderEngine
	dc    *gg.Context
	font  *truetype.Font
	faces map[float64]font.Face
	// nodeFilled is set once the current node's shape has been filled.
	nodeFilled bool
	// edgeStart and edgeEnd are the ends of the current edge's spline, in Graphviz
	// coordinates: the tail arrow is drawn at the start, the head arrow at the end.
	edgeStart, edgeEnd [2]float64
}

func (r *pngRenderer) BeginPage(_ context.Context, job *gvc.Job) error {
	r.dc = gg.NewContext(int(job.Width()), int(job.Height())) // #nosec G115 -- page size in pixels
	x, y := r.point(job, job.Translation().X(), job.Translation().Y())
	r.dc.Translate(x, y)
	return nil
}

func (r *pngRenderer) BeginNode(_ context.Context, _ *gvc.Job) error {
	r.nodeFilled = false
	return nil
}

func (r *pngRenderer) BeginEdge(_ context.Context, _ *gvc.Job) error {
	r.edgeStart, r.edgeEnd = [2]float64{}, [2]float64{}
	return nil
}

func (r *pngRenderer) EndPage(_ context.Context, job *gvc.Job) error {
	var png bytes.Buffer
	if err := r.dc.EncodePNG(&png); err != nil {
		return fmt.Errorf("error encoding the diagram: %w", err)
	}
	job.SetOutputData(png.Bytes())
	job.SetOutputDataPosition(uint(png.Len())) // #nosec G115 -- a buffer length is never negative
	return nil
}

func (r *pngRenderer) TextSpan(_ context.Context, job *gvc.Job, p *gvc.PointFloat, span *gvc.TextSpan) error {
	if !r.setColor(job.Object().PenColor()) {
		return nil
	}
	scale := job.Scale().X()
	size := span.Font().Size() * scale
	r.dc.SetFontFace(r.face(size))
	width, _ := r.dc.MeasureString(span.Text())
	reserved := span.Size().X() * scale
	if width > reserved && width > 0 {
		// Text sized for a narrower font (the default Times of the legend) shrinks to fit.
		r.dc.SetFontFace(r.face(size * reserved / width))
		width, _ = r.dc.MeasureString(span.Text())
	}
	x, y := r.point(job, p.X(), p.Y()+span.YOffsetCenterLine())
	switch span.Just() {
	case 'l':
	case 'r':
		x -= reserved
	default:
		x -= reserved / 2
	}
	r.dc.DrawString(span.Text(), x+(reserved-width)/2, y)
	return nil
}

func (r *pngRenderer) Ellipse(_ context.Context, job *gvc.Job, a []*gvc.PointFloat, filled bool) error {
	cx, cy := r.point(job, a[0].X(), a[0].Y())
	rx, ry := r.point(job, a[1].X()-a[0].X(), a[1].Y()-a[0].Y())
	r.dc.DrawEllipse(cx, cy, rx, -ry)
	r.draw(job, r.fills(job, filled, [2]float64{a[0].X(), a[0].Y()}))
	return nil
}

func (r *pngRenderer) Polygon(_ context.Context, job *gvc.Job, a []*gvc.PointFloat, filled bool) error {
	r.lines(job, a)
	r.dc.ClosePath()
	r.draw(job, r.fills(job, filled, centroid(a)))
	return nil
}

func (r *pngRenderer) BezierCurve(_ context.Context, job *gvc.Job, a []*gvc.PointFloat, filled bool) error {
	if job.Object().Type() == gvc.EdgeObjectType {
		// Graphviz draws the spline before the arrows, which sit beyond its two ends.
		r.edgeStart = [2]float64{a[0].X(), a[0].Y()}
		r.edgeEnd = [2]float64{a[len(a)-1].X(), a[len(a)-1].Y()}
	}
	r.dc.MoveTo(r.point(job, a[0].X(), a[0].Y()))
	for i := 1; i+2 < len(a); i += 3 {
		x1, y1 := r.point(job, a[i].X(), a[i].Y())
		x2, y2 := r.point(job, a[i+1].X(), a[i+1].Y())
		x3, y3 := r.point(job, a[i+2].X(), a[i+2].Y())
		r.dc.CubicTo(x1, y1, x2, y2, x3, y3)
	}
	r.draw(job, filled && job.Object().Type() != gvc.EdgeObjectType && r.fills(job, filled, [2]float64{}))
	return nil
}

func (r *pngRenderer) Polyline(_ context.Context, job *gvc.Job, a []*gvc.PointFloat) error {
	r.lines(job, a)
	r.draw(job, false)
	return nil
}

// fills reports whether a closed shape centred at the given point is filled; see the note on
// the WASM bridge at the top.
func (r *pngRenderer) fills(job *gvc.Job, filled bool, centre [2]float64) bool {
	obj := job.Object()
	switch obj.Type() {
	case gvc.NodeObjectType:
		// Graphviz draws the filled shape first; extra peripheries and the cells
		// of an HTML label come after it and stay unfilled.
		fill := !r.nodeFilled && obj.Fill() != gvc.FillNone
		r.nodeFilled = true
		return fill
	case gvc.EdgeObjectType:
		// An arrow: the one at the tail end of the edge (dir=both or back) is the arrowtail.
		attribute := "arrowhead"
		if math.Hypot(centre[0]-r.edgeStart[0], centre[1]-r.edgeStart[1]) <
			math.Hypot(centre[0]-r.edgeEnd[0], centre[1]-r.edgeEnd[1]) {
			attribute = "arrowtail"
		}
		arrow := strings.TrimLeft(obj.Edge().GetStr(attribute), "lr")
		open := strings.HasPrefix(arrow, "o") && !strings.HasPrefix(arrow, "open")
		return !open && arrow != "empty" && arrow != "invempty" && arrow != "ediamond"
	default:
		return filled
	}
}

// draw fills the current path if asked to, then strokes it with the object's pen.
func (r *pngRenderer) draw(job *gvc.Job, fill bool) {
	obj := job.Object()
	if fill && r.setColor(obj.FillColor()) {
		r.dc.FillPreserve()
	}
	if obj.Pen() == gvc.PenNone || !r.setColor(obj.PenColor()) {
		r.dc.ClearPath()
		return
	}
	scale := job.Scale().X()
	r.dc.SetLineWidth(obj.PenWidth() * scale)
	r.dc.SetLineCapButt()
	switch obj.Pen() { // the dash patterns of the Graphviz cairo renderer
	case gvc.PenDashed:
		r.dc.SetDash(6*scale, 6*scale)
	case gvc.PenDotted:
		r.dc.SetDash(2*scale, 6*scale)
	default:
		r.dc.SetDash()
	}
	r.dc.Stroke()
}

// centroid is the mean of the points, in Graphviz coordinates.
func centroid(a []*gvc.PointFloat) [2]float64 {
	var x, y float64
	for _, p := range a {
		x += p.X()
		y += p.Y()
	}
	n := float64(len(a))
	return [2]float64{x / n, y / n}
}

func (r *pngRenderer) lines(job *gvc.Job, a []*gvc.PointFloat) {
	r.dc.MoveTo(r.point(job, a[0].X(), a[0].Y()))
	for _, p := range a[1:] {
		r.dc.LineTo(r.point(job, p.X(), p.Y()))
	}
}

// point converts Graphviz coordinates (y up, in points) to image pixels (y down).
func (r *pngRenderer) point(job *gvc.Job, x, y float64) (float64, float64) {
	return job.Scale().X() * x, -job.Scale().Y() * y
}

// setColor selects the colour and reports whether it is visible at all.
func (r *pngRenderer) setColor(c *gvc.Color) bool {
	rgba := c.RGBAUint()
	if rgba[3] == 0 {
		return false
	}
	r.dc.SetRGBA255(int(rgba[0]), int(rgba[1]), int(rgba[2]), int(rgba[3])) // #nosec G115 -- 0..255
	return true
}

func (r *pngRenderer) face(size float64) font.Face {
	if face, ok := r.faces[size]; ok {
		return face
	}
	face := truetype.NewFace(r.font, &truetype.Options{Size: size})
	r.faces[size] = face
	return face
}
