package report

import (
	"encoding/hex"

	"github.com/Pinguladora/threagile/pkg/types"
)

const (
	Amber                = "#AF780E"
	Green                = "#008000"
	Blue                 = "#000080"
	DarkBlue             = "#000060"
	Black                = "#000000"
	Gray                 = "#444444"
	LightGray            = "#666666"
	MiddleLightGray      = "#999999"
	MoreLightGray        = "#D2D2D2"
	VeryLightGray        = "#E5E5E5"
	ExtremeLightGray     = "#F6F6F6"
	Pink                 = "#F987C5"
	LightPink            = "#FFE7EF"
	Red                  = "#CC0000"
	OutOfScopeFancy      = "#D5D7FF"
	CustomDevelopedParts = "#FFFC97"
	ExtremeLightBlue     = "#DDFFFF"
	LightBlue            = "#77FFFF"
	Brown                = "#8C4C17"
)

func darkenHexColor(hexString string) string {
	colorBytes, _ := hex.DecodeString(hexString[1:])
	adjusted := make([]byte, len(colorBytes))
	for i := range colorBytes {
		if colorBytes[i] > 0x22 {
			adjusted[i] = colorBytes[i] - 0x20
		} else {
			adjusted[i] = 0x00
		}
	}
	return "#" + hex.EncodeToString(adjusted)
}

func brightenHexColor(hexString string) string {
	colorBytes, _ := hex.DecodeString(hexString[1:])
	adjusted := make([]byte, len(colorBytes))
	for i := range colorBytes {
		if colorBytes[i] < 0xDD {
			adjusted[i] = colorBytes[i] + 0x20
		} else {
			adjusted[i] = 0xFF
		}
	}
	return "#" + hex.EncodeToString(adjusted)
}

func rgbHexColorCriticalRisk() string {
	return "#FF2600"
}

func rgbHexColorHighRisk() string {
	return "#A0281E"
}

func rgbHexColorElevatedRisk() string {
	return "#FF8E00"
}

func rgbHexColorMediumRisk() string {
	return "#C87832"
}

func rgbHexColorLowRisk() string {
	return "#23465F"
}

func rgbHexColorOutOfScope() string {
	return "#7F7F7F"
}

func RgbHexColorRiskStatusUnchecked() string {
	return "#FF0000"
}

func rgbHexColorRiskStatusMitigated() string {
	return "#008F00"
}

func rgbHexColorRiskStatusInProgress() string {
	return "#0000FF"
}

func rgbHexColorRiskStatusAccepted() string {
	return "#FF40FF"
}

func rgbHexColorRiskStatusInDiscussion() string {
	return "#FF9300"
}

func rgbHexColorRiskStatusFalsePositive() string {
	return "#666666"
}

func rgbHexColorTwilight() string {
	return "#3A52C8"
}

// riskSeverityColor is the colour of the severity, as the reports show it.
func riskSeverityColor(severity types.RiskSeverity) string {
	switch severity {
	case types.CriticalSeverity:
		return rgbHexColorCriticalRisk()
	case types.HighSeverity:
		return rgbHexColorHighRisk()
	case types.ElevatedSeverity:
		return rgbHexColorElevatedRisk()
	case types.MediumSeverity:
		return rgbHexColorMediumRisk()
	default:
		return rgbHexColorLowRisk()
	}
}

// riskStatusColor is the colour of the risk status, as the reports show it.
func riskStatusColor(status types.RiskStatus) string {
	switch status {
	case types.Mitigated:
		return rgbHexColorRiskStatusMitigated()
	case types.InProgress:
		return rgbHexColorRiskStatusInProgress()
	case types.Accepted:
		return rgbHexColorRiskStatusAccepted()
	case types.InDiscussion:
		return rgbHexColorRiskStatusInDiscussion()
	case types.FalsePositive:
		return rgbHexColorRiskStatusFalsePositive()
	default:
		return RgbHexColorRiskStatusUnchecked()
	}
}
