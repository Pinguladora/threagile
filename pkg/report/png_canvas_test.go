package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPNGCanvasDashes(t *testing.T) {
	canvas := newPNGCanvas(1, 1)
	canvas.SetDash(6, 6)

	dashes := canvas.dashed([][2]float64{{0, 0}, {10, 0}, {20, 0}})

	assert.Equal(t, [][][2]float64{{{0, 0}, {6, 0}}, {{12, 0}, {18, 0}}}, dashes,
		"the pattern runs on across the points of the line")

	canvas.SetDash()
	assert.Len(t, canvas.dashed([][2]float64{{0, 0}, {20, 0}}), 1, "a solid line is one piece")
}

func TestPNGCanvasStrokeJoins(t *testing.T) {
	corner := strokePolygons([][2]float64{{0, 0}, {10, 0}, {10, 10}}, 2)
	assert.Len(t, corner, 3, "two segments and the round join of the corner")

	straight := strokePolygons([][2]float64{{0, 0}, {10, 0}, {20, 0.1}}, 2)
	assert.Len(t, straight, 2, "no join where the line hardly turns")

	segment := strokePolygons([][2]float64{{0, 0}, {10, 0}}, 1)
	assert.Equal(t, [][2]float64{{0, 1}, {10, 1}, {10, -1}, {0, -1}}, segment[0], "butt caps end at the points")
}

func TestPNGCanvasFillsOverlapsOnce(t *testing.T) {
	canvas := newPNGCanvas(10, 10)
	canvas.SetRGBA255(0, 0, 255, 128)
	canvas.fill([][][2]float64{
		{{0, 0}, {10, 0}, {10, 10}, {0, 10}},
		{{0, 0}, {0, 10}, {10, 10}, {10, 0}}, // the same square, turned the other way round
	})

	_, _, b, a := canvas.img.At(5, 5).RGBA()
	assert.InDelta(t, 128, a>>8, 1, "the overlap is blended once, not cancelled or doubled")
	assert.InDelta(t, 128, b>>8, 1)
}
