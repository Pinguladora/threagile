package report

import (
	"bytes"
	"image"
	"image/png"
	"testing"
)

// At 72 dpi one point is one pixel. The blue edge bends at a right angle (ortho
// splines), so a filled spline would cover a large wedge instead of a thin line.
const testDiagramDOT = `digraph test {
	graph [dpi=72 splines=ortho nodesep=1.5];
	node [shape=box style=filled fillcolor="#FF0000" fontcolor="#FF0000"];
	a -> c [color="#0000FF" arrowhead=none];
	b -> c [style=invis];
	c [width=0.3];
}`

func TestRenderDiagramPNG(t *testing.T) {
	data, err := renderDiagramPNG([]byte(testDiagramDOT))
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	if !bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatalf("output is not a PNG")
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decoding the PNG failed: %v", err)
	}
	bounds := img.Bounds()
	if bounds.Dx() < 150 || bounds.Dx() > 300 || bounds.Dy() < 100 || bounds.Dy() > 140 {
		t.Fatalf("unexpected size %v", bounds.Size())
	}

	if r, g, b := rgb(img, 0, 0); r != 255 || g != 255 || b != 255 {
		t.Errorf("background is (%d,%d,%d), want white", r, g, b)
	}
	if r, g, b := rgb(img, 10, 20); r < 200 || g > 50 || b > 50 {
		t.Errorf("node fill is (%d,%d,%d), want red", r, g, b)
	}

	// The edge must be drawn, as a thin line: a wedge would cover hundreds of pixels.
	blue := 0
	for y := range bounds.Dy() {
		for x := range bounds.Dx() {
			if r, _, b := rgb(img, x, y); b > 128 && r < 128 {
				blue++
			}
		}
	}
	if blue < 20 || blue > 150 {
		t.Errorf("the edge covers %d pixels, want a thin line of 20 to 150", blue)
	}
}

func TestRenderDiagramPNGInvalidSource(t *testing.T) {
	if _, err := renderDiagramPNG([]byte("digraph {")); err == nil {
		t.Fatal("expected an error for an invalid diagram source")
	}
}

func rgb(img image.Image, x, y int) (r, g, b uint32) {
	r, g, b, _ = img.At(x, y).RGBA()
	return r >> 8, g >> 8, b >> 8
}
