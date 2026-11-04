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

// The edge has a filled arrowhead at b and a hollow arrowtail at a; Graphviz places the tail
// arrow between y=-142.25 and -122.25 and the head arrow between y=-57.6 and -37.6, which are
// pixel rows 41.75 to 61.75 and 126.4 to 146.4 after the translation by (4, 184).
const testBidirectionalDiagramDOT = `digraph test {
	graph [dpi=72 splines=ortho ranksep=1.5];
	node [shape=box];
	a -> b [color="#0000FF" dir=both arrowhead=normal arrowtail=empty arrowsize=2.0];
}`

func TestRenderDiagramPNGArrowTail(t *testing.T) {
	data, err := renderDiagramPNG([]byte(testBidirectionalDiagramDOT))
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decoding the PNG failed: %v", err)
	}
	if size := img.Bounds().Size(); size.X != 62 || size.Y != 188 {
		t.Fatalf("unexpected size %v, the arrow positions below assume 62x188", size)
	}

	// Inside each arrow, near its base and off the spline, which ends at the base.
	for _, x := range []int{29, 31, 33} {
		if r, g, b := rgb(img, x, 57); r < 200 || g < 200 || b < 200 {
			t.Errorf("hollow arrowtail at (%d,57) is (%d,%d,%d), want white", x, r, g, b)
		}
		if r, g, b := rgb(img, x, 131); r > 50 || g > 50 || b < 200 {
			t.Errorf("filled arrowhead at (%d,131) is (%d,%d,%d), want blue", x, r, g, b)
		}
	}
	// The outline of the hollow arrowtail is still drawn: its base is at row 61.75.
	if r, _, b := rgb(img, 31, 62); b < 128 || r > 128 {
		t.Errorf("the base of the hollow arrowtail is (%d,_,%d), want blue", r, b)
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
