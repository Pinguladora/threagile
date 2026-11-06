package report

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// contrastAAA is the contrast ratio that WCAG 2.2 asks of text at level AAA (1.4.6 Contrast (Enhanced)), which the
// reports meet for all their text, as the coloured text of the tables is small.
const contrastAAA = 7.0

// relativeLuminance is the relative luminance of an sRGB colour written as #rrggbb, as WCAG defines it.
func relativeLuminance(hexColor string) float64 {
	r, g, b := hexChannels(hexColor)
	linear := func(channel float64) float64 {
		if channel <= 0.04045 {
			return channel / 12.92
		}
		return math.Pow((channel+0.055)/1.055, 2.4)
	}
	return 0.2126*linear(r) + 0.7152*linear(g) + 0.0722*linear(b)
}

// contrastRatio is the WCAG contrast ratio of two colours, from 1 to 21.
func contrastRatio(first string, second string) float64 {
	lighter, darker := relativeLuminance(first), relativeLuminance(second)
	if lighter < darker {
		lighter, darker = darker, lighter
	}
	return (lighter + 0.05) / (darker + 0.05)
}

// darkenedForContrast is the colour, darkened towards black as little as needed for its contrast with the
// background to reach the ratio; a colour that reaches it already is returned as it is.
func darkenedForContrast(hexColor string, background string, ratio float64) string {
	r, g, b := hexChannels(hexColor)
	for factor := 1.0; factor > 0; factor -= 0.005 {
		candidate := hexColorOf(r*factor, g*factor, b*factor)
		if contrastRatio(candidate, background) >= ratio {
			return candidate
		}
	}
	return "#000000"
}

func hexChannels(hexColor string) (r, g, b float64) {
	value, err := strconv.ParseUint(strings.TrimPrefix(hexColor, "#"), 16, 32)
	if err != nil {
		return 0, 0, 0
	}
	return float64(value>>16&0xff) / 255, float64(value>>8&0xff) / 255, float64(value&0xff) / 255
}

func hexColorOf(r, g, b float64) string {
	channel := func(value float64) int { return int(math.Round(math.Max(0, math.Min(1, value)) * 255)) }
	return fmt.Sprintf("#%02X%02X%02X", channel(r), channel(g), channel(b))
}
