package report

import (
	"errors"
	"strings"

	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/xuri/excelize/v2"
)

type ExcelStyles struct {
	severityCriticalBold   int
	severityCriticalCenter int
	severityHighBold       int
	severityHighCenter     int
	severityElevatedBold   int
	severityElevatedCenter int
	severityMediumBold     int
	severityMediumCenter   int
	severityLowBold        int
	severityLowCenter      int
	redCenter              int
	greenCenter            int
	blueCenter             int
	yellowCenter           int
	orangeCenter           int
	grayCenter             int
	blackLeft              int
	blackLeftBold          int
	blackCenter            int
	blackRight             int
	blackSmall             int
	graySmall              int
	blackBold              int
	mitigation             int
	headCenter             int
	headCenterBoldItalic   int
	headCenterBold         int
}

// excelAlignCenter is the horizontal alignment of most cells.
const excelAlignCenter = "center"

// headFill is the light gray background of the header cells.
func headFill() excelize.Fill {
	return excelize.Fill{
		Type:    "pattern",
		Color:   []string{"#eeeeee"},
		Pattern: 1,
	}
}

type styleCreator struct {
	ExcelFile *excelize.File
	Error     error
}

func (what *styleCreator) Init(excel *excelize.File) *styleCreator {
	what.ExcelFile = excel
	return what
}

func (what *styleCreator) NewStyle(style *excelize.Style) int {
	if what.Error != nil {
		return 0
	}

	var styleID int
	styleID, what.Error = what.ExcelFile.NewStyle(style)

	return styleID
}

func (what *ExcelStyles) Init(excel *excelize.File, config reportConfigReader) (*ExcelStyles, error) {
	if excel == nil {
		return what, errors.New("no excel file provided to create styles")
	}

	creator := new(styleCreator).Init(excel)
	alignment := func(horizontal string) *excelize.Alignment {
		return &excelize.Alignment{
			Horizontal:  horizontal,
			ShrinkToFit: config.GetRiskExcelShrinkColumnsToFit(),
			WrapText:    config.GetRiskExcelWrapText(),
		}
	}
	newStyle := func(horizontal string, color string, size float64, bold bool) int {
		return creator.NewStyle(&excelize.Style{
			Alignment: alignment(horizontal),
			Font:      &excelize.Font{Color: color, Size: size, Bold: bold},
		})
	}
	newHeadStyle := func(size float64, bold bool) int {
		return creator.NewStyle(&excelize.Style{
			Alignment: alignment(excelAlignCenter),
			Font:      &excelize.Font{Color: Black, Size: size, Bold: bold},
			Fill:      headFill(),
		})
	}
	textColor := func(color func() string) string {
		if config.GetRiskExcelColorText() {
			return color()
		}
		return Black
	}

	// the styles are created in this order, as their ids are numbered in it
	colorRiskStatusMitigated := what.initRiskStyles(newStyle, textColor)
	what.initTextStyles(newStyle, textColor, colorRiskStatusMitigated)

	what.headCenterBoldItalic = newHeadStyle(14, true)
	what.headCenterBold = newHeadStyle(14, true)
	what.headCenter = newHeadStyle(14, false)

	return what, creator.Error
}

// initRiskStyles creates the styles of the risk severities and risk tracking statuses. It returns
// the text colour of mitigated risks.
func (what *ExcelStyles) initRiskStyles(newStyle func(horizontal string, color string, size float64, bold bool) int,
	textColor func(color func() string) string,
) string {
	colorCriticalRisk := textColor(rgbHexColorCriticalRisk)
	what.severityCriticalBold = newStyle(excelAlignCenter, colorCriticalRisk, 12, true)
	what.severityCriticalCenter = newStyle(excelAlignCenter, colorCriticalRisk, 12, false)

	colorHighRisk := textColor(rgbHexColorHighRisk)
	what.severityHighBold = newStyle(excelAlignCenter, colorHighRisk, 12, true)
	what.severityHighCenter = newStyle(excelAlignCenter, colorHighRisk, 12, false)

	colorElevatedRisk := textColor(rgbHexColorElevatedRisk)
	what.severityElevatedBold = newStyle(excelAlignCenter, colorElevatedRisk, 12, true)
	what.severityElevatedCenter = newStyle(excelAlignCenter, colorElevatedRisk, 12, false)

	colorMediumRisk := textColor(rgbHexColorMediumRisk)
	what.severityMediumBold = newStyle(excelAlignCenter, colorMediumRisk, 12, true)
	what.severityMediumCenter = newStyle(excelAlignCenter, colorMediumRisk, 12, false)

	colorLowRisk := textColor(rgbHexColorLowRisk)
	what.severityLowBold = newStyle(excelAlignCenter, colorLowRisk, 12, true)
	what.severityLowCenter = newStyle(excelAlignCenter, colorLowRisk, 12, false)

	what.redCenter = newStyle(excelAlignCenter, textColor(RgbHexColorRiskStatusUnchecked), 12, false)

	colorRiskStatusMitigated := textColor(rgbHexColorRiskStatusMitigated)
	what.greenCenter = newStyle(excelAlignCenter, colorRiskStatusMitigated, 12, false)
	what.blueCenter = newStyle(excelAlignCenter, textColor(rgbHexColorRiskStatusInProgress), 12, false)
	what.yellowCenter = newStyle(excelAlignCenter, textColor(rgbHexColorRiskStatusAccepted), 12, false)
	what.orangeCenter = newStyle(excelAlignCenter, textColor(rgbHexColorRiskStatusInDiscussion), 12, false)
	what.grayCenter = newStyle(excelAlignCenter, textColor(rgbHexColorRiskStatusFalsePositive), 12, false)
	return colorRiskStatusMitigated
}

// initTextStyles creates the styles of the other cells.
func (what *ExcelStyles) initTextStyles(newStyle func(horizontal string, color string, size float64, bold bool) int,
	textColor func(color func() string) string, colorRiskStatusMitigated string,
) {
	what.blackLeft = newStyle("left", Black, 12, false)
	what.blackCenter = newStyle(excelAlignCenter, Black, 12, false)
	what.blackRight = newStyle("right", Black, 12, false)
	what.blackSmall = newStyle("", Black, 10, false)
	what.graySmall = newStyle("", textColor(rgbHexColorOutOfScope), 10, false)
	what.blackBold = newStyle(excelAlignCenter, Black, 12, true)
	what.blackLeftBold = newStyle("left", Black, 12, true)
	what.mitigation = newStyle("", colorRiskStatusMitigated, 10, false)
}

func (what *ExcelStyles) Get(column string, status types.RiskStatus, severity types.RiskSeverity) int {
	column = strings.ToUpper(column)
	switch column {
	case "A", "B", "C", "D", "E", "F":
		if !status.IsStillAtRisk() {
			return what.blackCenter
		}
		return what.severityCenterStyle(severity)

	case "G", "H", "I":
		if !status.IsStillAtRisk() {
			return what.blackBold
		}
		return what.severityBoldStyle(severity)

	case "P":
		return what.riskStatusStyle(status)
	}

	styles := map[string]int{
		"J": what.blackRight,
		"K": what.blackSmall,
		"L": what.mitigation,
		"M": what.mitigation,
		"N": what.mitigation,
		"O": what.graySmall,
		"Q": what.blackSmall,
		"R": what.blackCenter,
		"S": what.blackCenter,
		"T": what.blackLeft,
	}
	if style, ok := styles[column]; ok {
		return style
	}
	return what.blackRight
}

// severityCenterStyle is the centered style of a risk severity.
func (what *ExcelStyles) severityCenterStyle(severity types.RiskSeverity) int {
	switch severity {
	case types.CriticalSeverity:
		return what.severityCriticalCenter

	case types.HighSeverity:
		return what.severityHighCenter

	case types.ElevatedSeverity:
		return what.severityElevatedCenter

	case types.MediumSeverity:
		return what.severityMediumCenter

	case types.LowSeverity:
		return what.severityLowCenter
	}
	return what.blackRight
}

// severityBoldStyle is the bold style of a risk severity.
func (what *ExcelStyles) severityBoldStyle(severity types.RiskSeverity) int {
	switch severity {
	case types.CriticalSeverity:
		return what.severityCriticalBold

	case types.HighSeverity:
		return what.severityHighBold

	case types.ElevatedSeverity:
		return what.severityElevatedBold

	case types.MediumSeverity:
		return what.severityMediumBold

	case types.LowSeverity:
		return what.severityLowBold
	}
	return what.blackRight
}

// riskStatusStyle is the style of a risk tracking status.
func (what *ExcelStyles) riskStatusStyle(status types.RiskStatus) int {
	switch status {
	case types.Unchecked:
		return what.redCenter

	case types.Mitigated:
		return what.greenCenter

	case types.InProgress:
		return what.blueCenter

	case types.Accepted:
		return what.yellowCenter

	case types.InDiscussion:
		return what.orangeCenter

	case types.FalsePositive:
		return what.grayCenter

	default:
		return what.blackCenter
	}
}
