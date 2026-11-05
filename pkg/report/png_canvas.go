package report

import (
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"io"
	"math"
	"slices"

	"golang.org/x/image/font"
	"golang.org/x/image/math/fixed"
	"golang.org/x/image/vector"
)

// pngCanvas draws the paths and the text of a diagram onto an image with golang.org/x/image: vector fills the
// paths, and strokes are filled as the polygons that cover them, with butt caps, round joins and dashes, as the
// Graphviz cairo renderer draws them.
type pngCanvas struct {
	img                    *image.RGBA
	translateX, translateY float64
	subpaths               []pngSubpath
	color                  color.NRGBA
	lineWidth              float64
	dash                   []float64 // alternating lengths of dashes and gaps; empty for solid lines
	face                   font.Face
	currentX, currentY     float64
	hasCurrent             bool
}

// pngSubpath is a flattened subpath of the current path, in pixels.
type pngSubpath struct {
	points [][2]float64
	closed bool
}

func newPNGCanvas(width int, height int) *pngCanvas {
	return &pngCanvas{img: image.NewRGBA(image.Rect(0, 0, width, height)), lineWidth: 1}
}

// Translate moves the origin of the coordinates of the following drawing.
func (c *pngCanvas) Translate(x float64, y float64) {
	c.translateX, c.translateY = c.translateX+x, c.translateY+y
}

func (c *pngCanvas) SetRGBA255(r int, g int, b int, a int) {
	c.color = color.NRGBA{R: uint8(r), G: uint8(g), B: uint8(b), A: uint8(a)} // #nosec G115 -- 0..255
}

func (c *pngCanvas) SetLineWidth(width float64) { c.lineWidth = width }

func (c *pngCanvas) SetDash(dashes ...float64) { c.dash = dashes }

func (c *pngCanvas) SetFontFace(face font.Face) { c.face = face }

func (c *pngCanvas) MoveTo(x float64, y float64) {
	x, y = x+c.translateX, y+c.translateY
	c.subpaths = append(c.subpaths, pngSubpath{points: [][2]float64{{x, y}}})
	c.currentX, c.currentY, c.hasCurrent = x, y, true
}

func (c *pngCanvas) LineTo(x float64, y float64) {
	if !c.hasCurrent {
		c.MoveTo(x, y)
		return
	}
	x, y = x+c.translateX, y+c.translateY
	c.lineTo(x, y)
}

func (c *pngCanvas) lineTo(x float64, y float64) {
	last := &c.subpaths[len(c.subpaths)-1]
	last.points = append(last.points, [2]float64{x, y})
	c.currentX, c.currentY = x, y
}

// CubicTo adds a cubic Bézier curve, flattened into lines short enough to look smooth.
func (c *pngCanvas) CubicTo(x1 float64, y1 float64, x2 float64, y2 float64, x3 float64, y3 float64) {
	if !c.hasCurrent {
		c.MoveTo(x1, y1)
	}
	x1, y1 = x1+c.translateX, y1+c.translateY
	x2, y2 = x2+c.translateX, y2+c.translateY
	x3, y3 = x3+c.translateX, y3+c.translateY
	x0, y0 := c.currentX, c.currentY
	length := math.Hypot(x1-x0, y1-y0) + math.Hypot(x2-x1, y2-y1) + math.Hypot(x3-x2, y3-y2)
	steps := max(4, int(math.Ceil(length/2)))
	for i := 1; i <= steps; i++ {
		t := float64(i) / float64(steps)
		u := 1 - t
		c.lineTo(
			u*u*u*x0+3*u*u*t*x1+3*u*t*t*x2+t*t*t*x3,
			u*u*u*y0+3*u*u*t*y1+3*u*t*t*y2+t*t*t*y3,
		)
	}
}

func (c *pngCanvas) ClosePath() {
	if len(c.subpaths) > 0 {
		c.subpaths[len(c.subpaths)-1].closed = true
	}
}

// DrawEllipse adds an ellipse as a closed subpath.
func (c *pngCanvas) DrawEllipse(x float64, y float64, rx float64, ry float64) {
	steps := max(16, int(math.Ceil(math.Pi*(math.Abs(rx)+math.Abs(ry))/2)))
	c.MoveTo(x+rx, y)
	for i := 1; i < steps; i++ {
		angle := 2 * math.Pi * float64(i) / float64(steps)
		c.LineTo(x+rx*math.Cos(angle), y+ry*math.Sin(angle))
	}
	c.ClosePath()
}

// ClearPath forgets the current path.
func (c *pngCanvas) ClearPath() {
	c.subpaths, c.hasCurrent = nil, false
}

// FillPreserve fills the current path and keeps it, to stroke it next.
func (c *pngCanvas) FillPreserve() {
	polygons := make([][][2]float64, 0, len(c.subpaths))
	for _, subpath := range c.subpaths {
		polygons = append(polygons, subpath.points)
	}
	c.fill(polygons)
}

// Stroke strokes the current path with the line width and dashes, then forgets it.
func (c *pngCanvas) Stroke() {
	polygons := make([][][2]float64, 0)
	for _, subpath := range c.subpaths {
		points := subpath.points
		if subpath.closed && len(points) > 1 {
			points = append(slices.Clip(points), points[0])
		}
		for _, line := range c.dashed(points) {
			polygons = append(polygons, strokePolygons(line, c.lineWidth/2)...)
		}
	}
	c.fill(polygons)
	c.ClearPath()
}

// fill draws the polygons in one pass in the current colour, so that where they overlap, the colour is not
// blended twice. Each polygon is turned the same way round, so that overlaps add up instead of cancelling out.
func (c *pngCanvas) fill(polygons [][][2]float64) {
	bounds := c.img.Bounds()
	rasterizer := vector.NewRasterizer(bounds.Dx(), bounds.Dy())
	drawn := false
	for _, polygon := range polygons {
		if len(polygon) < 3 {
			continue
		}
		if signedArea(polygon) < 0 {
			polygon = reversed(polygon)
		}
		rasterizer.MoveTo(float32(polygon[0][0]), float32(polygon[0][1]))
		for _, point := range polygon[1:] {
			rasterizer.LineTo(float32(point[0]), float32(point[1]))
		}
		rasterizer.ClosePath()
		drawn = true
	}
	if drawn {
		rasterizer.DrawOp = draw.Over
		rasterizer.Draw(c.img, bounds, image.NewUniform(c.color), image.Point{})
	}
}

// dashed splits a polyline into its dashes, or returns it whole for a solid line.
func (c *pngCanvas) dashed(points [][2]float64) [][][2]float64 {
	if len(c.dash) == 0 || len(points) < 2 {
		return [][][2]float64{points}
	}
	dashes := make([][][2]float64, 0)
	index, left, on := 0, c.dash[0], true
	current := [][2]float64{points[0]}
	for i := 1; i < len(points); i++ {
		from, to := points[i-1], points[i]
		segment := math.Hypot(to[0]-from[0], to[1]-from[1])
		for segment > left {
			t := left / segment
			split := [2]float64{from[0] + (to[0]-from[0])*t, from[1] + (to[1]-from[1])*t}
			if on {
				dashes = append(dashes, append(current, split))
			}
			current, on = [][2]float64{split}, !on
			from, segment = split, segment-left
			index = (index + 1) % len(c.dash)
			left = c.dash[index]
		}
		left -= segment
		current = append(current, to)
	}
	if on && len(current) > 1 {
		dashes = append(dashes, current)
	}
	return dashes
}

// strokePolygons are the polygons covering a polyline drawn with the half width: a rectangle along each segment
// (which ends it with a butt cap) and a disc at each joint where it turns (a round join).
func strokePolygons(points [][2]float64, halfWidth float64) [][][2]float64 {
	polygons := make([][][2]float64, 0, 2*len(points))
	for i := 1; i < len(points); i++ {
		from, to := points[i-1], points[i]
		length := math.Hypot(to[0]-from[0], to[1]-from[1])
		if length == 0 {
			continue
		}
		nx, ny := -(to[1]-from[1])/length*halfWidth, (to[0]-from[0])/length*halfWidth
		polygons = append(polygons, [][2]float64{
			{from[0] + nx, from[1] + ny}, {to[0] + nx, to[1] + ny}, {to[0] - nx, to[1] - ny}, {from[0] - nx, from[1] - ny},
		})
		if i+1 < len(points) && halfWidth > 0.5 && turns(from, to, points[i+1]) {
			polygons = append(polygons, disc(to, halfWidth))
		}
	}
	return polygons
}

// turns tells whether the polyline turns at the middle point by more than a few degrees, enough for the gap between
// the rectangles of its two segments to show; a flattened curve turns by less at each of its points.
func turns(from [2]float64, middle [2]float64, to [2]float64) bool {
	ax, ay := middle[0]-from[0], middle[1]-from[1]
	bx, by := to[0]-middle[0], to[1]-middle[1]
	return math.Abs(math.Atan2(ax*by-ay*bx, ax*bx+ay*by)) > 5*math.Pi/180
}

func disc(centre [2]float64, radius float64) [][2]float64 {
	steps := max(8, int(math.Ceil(2*math.Pi*radius/2)))
	points := make([][2]float64, steps)
	for i := range steps {
		angle := 2 * math.Pi * float64(i) / float64(steps)
		points[i] = [2]float64{centre[0] + radius*math.Cos(angle), centre[1] + radius*math.Sin(angle)}
	}
	return points
}

func signedArea(polygon [][2]float64) float64 {
	area := 0.0
	for i, point := range polygon {
		next := polygon[(i+1)%len(polygon)]
		area += point[0]*next[1] - next[0]*point[1]
	}
	return area / 2
}

func reversed(polygon [][2]float64) [][2]float64 {
	result := make([][2]float64, len(polygon))
	for i, point := range polygon {
		result[len(polygon)-1-i] = point
	}
	return result
}

// MeasureString is the width of the text in the current font, in pixels.
func (c *pngCanvas) MeasureString(text string) float64 {
	return float64(font.MeasureString(c.face, text)) / 64
}

// DrawString draws the text in the current font and colour, with its baseline starting at the point.
func (c *pngCanvas) DrawString(text string, x float64, y float64) {
	drawer := font.Drawer{
		Dst:  c.img,
		Src:  image.NewUniform(c.color),
		Face: c.face,
		Dot: fixed.Point26_6{
			X: fixed.Int26_6(math.Round((x + c.translateX) * 64)),
			Y: fixed.Int26_6(math.Round((y + c.translateY) * 64)),
		},
	}
	drawer.DrawString(text)
}

func (c *pngCanvas) EncodePNG(w io.Writer) error {
	if err := png.Encode(w, c.img); err != nil {
		return fmt.Errorf("error encoding the image: %w", err)
	}
	return nil
}
