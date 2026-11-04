package report

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/shopspring/decimal"
	"github.com/xuri/excelize/v2"
)

func WriteRisksExcelToFile(parsedModel *types.Model, filename string, config reportConfigReader) error {
	columns := new(ExcelColumns).GetColumns()
	excel := excelize.NewFile()
	sheetName := parsedModel.Title

	sheetIndex, err := setUpRisksSheet(excel, parsedModel, sheetName, columns)
	if err != nil {
		return err
	}

	cellStyles, createCellStylesError := new(ExcelStyles).Init(excel, config)
	if createCellStylesError != nil {
		return fmt.Errorf("unable to create cell styles: %w", createCellStylesError)
	}

	riskItems := risksExcelItems(parsedModel)

	// group risks
	groupedRisk, groupedRiskError := new(RiskGroup).Make(riskItems, columns, config.GetRiskExcelConfigSortByColumns())
	if groupedRiskError != nil {
		return fmt.Errorf("failed to group risks: %w", groupedRiskError)
	}

	// write data
	writeError := groupedRisk.Write(excel, sheetName, cellStyles)
	if writeError != nil {
		return fmt.Errorf("failed to write data: %w", writeError)
	}

	// set header style
	setCellStyleError := excel.SetCellStyle(sheetName, "A1", "T1", cellStyles.headCenterBoldItalic)
	if setCellStyleError != nil {
		return fmt.Errorf("unable to set cell style: %w", setCellStyleError)
	}

	err = formatRisksColumns(excel, sheetName, columns, config)
	if err != nil {
		return err
	}

	excel.SetActiveSheet(sheetIndex)

	lastColumn, err := excelize.ColumnNumberToName(len(columns))
	if err != nil {
		return fmt.Errorf("failed to get last column name: %w", err)
	}
	lastRow := len(riskItems) + 1
	filterRange := fmt.Sprintf("A1:%s%d", lastColumn, lastRow)
	err = excel.AutoFilter(sheetName, filterRange, []excelize.AutoFilterOptions{})
	if err != nil {
		return fmt.Errorf("failed to add autofilter: %w", err)
	}

	// save file
	saveAsError := excel.SaveAs(filename)
	if saveAsError != nil {
		return fmt.Errorf("unable to save excel file: %w", saveAsError)
	}

	return nil
}

// setUpRisksSheet sets the document properties, adds the risks sheet with its page layout,
// header and footer, and writes its header row. It returns the index of the sheet.
func setUpRisksSheet(excel *excelize.File, parsedModel *types.Model, sheetName string,
	columns ExcelColumns,
) (int, error) {
	setDocPropsError := excel.SetDocProps(&excelize.DocProperties{
		Category:       "Threat Model Risks Summary",
		ContentStatus:  "Final",
		Creator:        parsedModel.Author.Name,
		Description:    sheetName + " via Threagile",
		Identifier:     "xlsx",
		Keywords:       "Threat Model",
		LastModifiedBy: parsedModel.Author.Name,
		Revision:       "0",
		Subject:        sheetName,
		Title:          sheetName,
		Language:       "en-US",
		Version:        "1.0.0",
	})
	if setDocPropsError != nil {
		return 0, fmt.Errorf("failed to set doc properties: %w", setDocPropsError)
	}

	sheetIndex, newSheetError := excel.NewSheet(sheetName)
	if newSheetError != nil {
		return 0, fmt.Errorf("failed to add sheet: %w", newSheetError)
	}

	deleteSheetError := excel.DeleteSheet("Sheet1")
	if deleteSheetError != nil {
		return 0, fmt.Errorf("failed to delete sheet: %w", deleteSheetError)
	}

	orientation := "landscape"
	size := 9 // A4
	setPageLayoutError := excel.SetPageLayout(sheetName,
		&excelize.PageLayoutOptions{Orientation: &orientation, Size: &size})
	if setPageLayoutError != nil {
		return 0, fmt.Errorf("unable to set page layout: %w", setPageLayoutError)
	}

	setHeaderFooterError := excel.SetHeaderFooter(sheetName, &excelize.HeaderFooterOptions{
		DifferentFirst:   false,
		DifferentOddEven: false,
		OddHeader:        "&R&P",
		OddFooter:        "&C&F",
		EvenHeader:       "&L&P",
		EvenFooter:       "&L&D&R&T",
		FirstHeader:      `&Threat Model &"-,` + parsedModel.Title + `"Bold&"-,Regular"Risks Summary+000A&D`,
	})
	if setHeaderFooterError != nil {
		return 0, fmt.Errorf("unable to set header/footer: %w", setHeaderFooterError)
	}

	// set header row (in column order: the shared strings table numbers the strings as they are first written)
	for _, columnLetter := range columns.SortedLetters() {
		setCellValueError := excel.SetCellValue(sheetName, columnLetter+"1", columns[columnLetter].Title)
		if setCellValueError != nil {
			return 0, fmt.Errorf("unable to set cell value: %w", setCellValueError)
		}
	}
	return sheetIndex, nil
}

// risksExcelItems returns a row of the risks sheet for each risk, sorted by category.
func risksExcelItems(parsedModel *types.Model) []RiskItem {
	riskItems := make([]RiskItem, 0)
	for _, category := range parsedModel.SortedRiskCategories() {
		risks := parsedModel.SortedRisksOfCategory(category)
		for _, risk := range risks {
			details := newRiskDetails(parsedModel, category, risk)
			riskItems = append(riskItems, RiskItem{
				Columns: []string{
					risk.Severity.Title(),
					risk.ExploitationLikelihood.Title(),
					risk.ExploitationImpact.Title(),
					category.STRIDE.Title(),
					category.Function.Title(),
					"CWE-" + strconv.Itoa(category.CWE),
					category.Title,
					details.technicalAssetTitle(),
					details.communicationLinkTitle(),
					decimal.NewFromFloat(details.technicalAssetRAA()).StringFixed(0),
					removeFormattingTags(risk.Title),
					category.Action,
					category.Mitigation,
					category.Check,
					risk.SyntheticId,
					details.tracking.Status.Title(),
					details.tracking.Justification,
					details.trackingDate(),
					details.tracking.CheckedBy,
					details.tracking.Ticket,
				},
				Status:   details.tracking.Status,
				Severity: risk.Severity,
			})
		}
	}
	return riskItems
}

// formatRisksColumns sets the column widths of the risks sheet, hides the columns that are
// configured to be hidden and freezes the header row.
func formatRisksColumns(excel *excelize.File, sheetName string, columns ExcelColumns, config reportConfigReader) error {
	// fix column width
	cols, colsError := excel.GetCols(sheetName)
	if colsError == nil {
		for colIndex, col := range cols {
			name, columnNumberToNameError := excelize.ColumnNumberToName(colIndex + 1)
			if columnNumberToNameError != nil {
				return fmt.Errorf("failed to get column name of column %d: %w", colIndex+1, columnNumberToNameError)
			}

			minWidth := risksColumnWidth(excel, sheetName, columns, config, colIndex, name, col)

			setColWidthError := excel.SetColWidth(sheetName, name, name, minWidth)
			if setColWidthError != nil {
				return fmt.Errorf("unable to set column width: %w", setColWidthError)
			}
		}
	}

	// hide some columns
	for _, columnLetter := range columns.SortedLetters() {
		for _, hiddenColumn := range config.GetRiskExcelConfigHideColumns() {
			if strings.EqualFold(hiddenColumn, columns[columnLetter].Title) {
				hideColumnError := excel.SetColVisible(sheetName, columnLetter, false)
				if hideColumnError != nil {
					return fmt.Errorf("unable to hide column: %w", hideColumnError)
				}
			}
		}
	}

	// freeze header
	freezeError := excel.SetPanes(sheetName, &excelize.Panes{
		Freeze:      true,
		Split:       false,
		XSplit:      0,
		YSplit:      1,
		TopLeftCell: "A2",
		ActivePane:  "bottomLeft",
	})
	if freezeError != nil {
		return fmt.Errorf("unable to freeze header: %w", freezeError)
	}
	return nil
}

// risksColumnWidth returns the width of the named column of the risks sheet: the configured
// one, or else one that fits the cells of the column.
func risksColumnWidth(excel *excelize.File, sheetName string, columns ExcelColumns, config reportConfigReader,
	colIndex int, name string, col []string,
) float64 {
	var minWidth float64 = 0
	width, widthOk := config.GetRiskExcelConfigWidthOfColumns()[columns[name].Title]
	if widthOk {
		minWidth = width
	} else {
		var largestWidth float64 = 0
		for rowIndex, rowCell := range col {
			cellWidth := risksCellWidth(excel, sheetName, colIndex, rowIndex, rowCell)

			cellWidth += 5 // add some extra width for auto filter

			if cellWidth > largestWidth {
				largestWidth = cellWidth
			}
		}

		for columnLetter := range columns {
			if strings.EqualFold(columnLetter, name) {
				minWidth = columns[columnLetter].Width
			}
		}

		if largestWidth < 100 {
			minWidth = largestWidth
		}

		if minWidth < 8 {
			minWidth = 8
		}
	}
	return minWidth
}

// risksCellWidth returns the width that the text of a cell of the risks sheet needs, scaled by
// the font size of the cell.
func risksCellWidth(excel *excelize.File, sheetName string, colIndex int, rowIndex int, rowCell string) float64 {
	cellWidth := float64(utf8.RuneCountInString(rowCell) + 2) // + 2 for margin

	cellName, coordinateError := excelize.CoordinatesToCellName(colIndex+1, rowIndex+1)
	if coordinateError == nil {
		style, styleError := excel.GetCellStyle(sheetName, cellName)
		if styleError == nil {
			styleDetails, detailsError := excel.GetStyle(style)
			if detailsError == nil {
				if styleDetails.Font != nil && styleDetails.Font.Size > 0 {
					cellWidth *= styleDetails.Font.Size / 14.
				}
			}
		}
	}
	return cellWidth
}

// WriteTagsExcelToFile writes the tag matrix of the model as an Excel sheet. A model
// without tags currently yields an empty sheet rather than a hint saying so.
func WriteTagsExcelToFile(parsedModel *types.Model, filename string, config reportConfigReader) error {
	excelRow := 0
	excel := excelize.NewFile()
	sheetName := parsedModel.Title
	sheetIndex, err := setUpTagsSheet(excel, parsedModel, sheetName)
	if err != nil {
		return err
	}

	sortedTagsAvailable := parsedModel.TagsActuallyUsed()
	sort.Strings(sortedTagsAvailable)
	lastColumn, err := writeTagsHeader(excel, sheetName, sortedTagsAvailable)
	if err != nil {
		return err
	}

	cellStyles, createCellStylesError := new(ExcelStyles).Init(excel, config)
	if createCellStylesError != nil {
		return fmt.Errorf("unable to create cell styles: %w", createCellStylesError)
	}

	excelRow++ // as we have a header line
	if len(sortedTagsAvailable) > 0 {
		err = writeTagRows(excel, &excelRow, sheetName, lastColumn, cellStyles, parsedModel, sortedTagsAvailable)
		if err != nil {
			return err
		}
	}

	err = excel.SetCellStyle(sheetName, "A1", "A1", cellStyles.headCenterBold)
	if err == nil && len(sortedTagsAvailable) > 0 {
		err = excel.SetCellStyle(sheetName, "B1", lastColumn+"1", cellStyles.headCenter)
	}
	if err != nil {
		return fmt.Errorf("unable to set cell style: %w", err)
	}

	excel.SetActiveSheet(sheetIndex)
	err = excel.SaveAs(filename)
	if err != nil {
		return fmt.Errorf("unable to save excel file: %w", err)
	}
	return nil
}

// setUpTagsSheet sets the document properties and adds the tags sheet with its page layout,
// header and footer. It returns the index of the sheet.
func setUpTagsSheet(excel *excelize.File, parsedModel *types.Model, sheetName string) (int, error) {
	err := excel.SetDocProps(&excelize.DocProperties{
		Category:       "Tag Matrix",
		ContentStatus:  "Final",
		Creator:        parsedModel.Author.Name,
		Description:    sheetName + " via Threagile",
		Identifier:     "xlsx",
		Keywords:       "Tag Matrix",
		LastModifiedBy: parsedModel.Author.Name,
		Revision:       "0",
		Subject:        sheetName,
		Title:          sheetName,
		Language:       "en-US",
		Version:        "1.0.0",
	})
	if err != nil {
		return 0, fmt.Errorf("failed to set doc properties: %w", err)
	}

	sheetIndex, _ := excel.NewSheet(sheetName)
	_ = excel.DeleteSheet("Sheet1")
	orientation := "landscape"
	size := 9
	err = excel.SetPageLayout(sheetName, &excelize.PageLayoutOptions{Orientation: &orientation, Size: &size}) // A4
	if err != nil {
		return 0, fmt.Errorf("unable to set page layout: %w", err)
	}

	err = excel.SetHeaderFooter(sheetName, &excelize.HeaderFooterOptions{
		DifferentFirst:   false,
		DifferentOddEven: false,
		OddHeader:        "&R&P",
		OddFooter:        "&C&F",
		EvenHeader:       "&L&P",
		EvenFooter:       "&L&D&R&T",
		FirstHeader:      `&Tag Matrix &"-,` + parsedModel.Title + `"Bold&"-,Regular"Summary+000A&D`,
	})
	if err != nil {
		return 0, fmt.Errorf("unable to set header/footer: %w", err)
	}
	return sheetIndex, nil
}

// writeTagsHeader writes the header row of the tags sheet and sets the column widths. It returns
// the name of the last column.
func writeTagsHeader(excel *excelize.File, sheetName string, sortedTagsAvailable []string) (string, error) {
	// "Element" is a generic name for assets, links, trust boundaries etc.; a separate
	// "type of element" column (e.g. "technical asset", "data asset") could be added.
	err := excel.SetCellValue(sheetName, "A1", "Element")
	if err != nil {
		return "", fmt.Errorf("unable to set cell value: %w", err)
	}

	for i, tag := range sortedTagsAvailable {
		cellName, coordinatesToCellNameError := excelize.CoordinatesToCellName(i+2, 1)
		if coordinatesToCellNameError != nil {
			return "", fmt.Errorf("failed to get cell coordinates from [%d, %d]: %w", i+2, 1, coordinatesToCellNameError)
		}

		err = excel.SetCellValue(sheetName, cellName, tag)
		if err != nil {
			return "", fmt.Errorf("unable to set cell value: %w", err)
		}
	}

	err = excel.SetColWidth(sheetName, "A", "A", 60)
	if err != nil {
		return "", fmt.Errorf("unable to set column width: %w", err)
	}

	lastColumn, _ := excelize.ColumnNumberToName(len(sortedTagsAvailable) + 2)
	if len(sortedTagsAvailable) > 0 {
		err = excel.SetColWidth(sheetName, "B", lastColumn, 35)
	}
	if err != nil {
		return "", fmt.Errorf("unable to set column width: %w", err)
	}
	return lastColumn, nil
}

// writeTagRows writes a row of the tags sheet for each technical asset with its communication
// links, each data asset, trust boundary and shared runtime.
func writeTagRows(excel *excelize.File, excelRow *int, sheetName string, lastColumn string, cellStyles *ExcelStyles,
	parsedModel *types.Model, sortedTagsAvailable []string,
) error {
	for _, row := range tagRows(parsedModel) {
		err := writeRow(excel, excelRow, sheetName, lastColumn, cellStyles.blackLeftBold, cellStyles.blackCenter,
			sortedTagsAvailable, row.title, row.tags)
		if err != nil {
			return fmt.Errorf("unable to write row: %w", err)
		}
	}
	return nil
}

func writeRow(excel *excelize.File, excelRow *int, sheetName string, _ string,
	styleBlackLeftBold int, styleBlackCenter int, sortedTags []string, assetTitle string, tagsUsed []string,
) error {
	*excelRow++

	firstCellName, firstCoordinatesToCellNameError := excelize.CoordinatesToCellName(1, *excelRow)
	if firstCoordinatesToCellNameError != nil {
		return fmt.Errorf("failed to get cell coordinates from [%d, %d]: %w", 1, *excelRow, firstCoordinatesToCellNameError)
	}

	err := excel.SetCellValue(sheetName, firstCellName, assetTitle)
	if err != nil {
		return fmt.Errorf("unable to write row: %w", err)
	}

	err = markUsedTags(excel, *excelRow, sheetName, sortedTags, tagsUsed)
	if err != nil {
		return err
	}

	err = excel.SetCellStyle(sheetName, firstCellName, firstCellName, styleBlackLeftBold)
	if err != nil {
		return fmt.Errorf("unable to write row: %w", err)
	}

	secondCellName, secondCoordinatesToCellNameError := excelize.CoordinatesToCellName(2, *excelRow)
	if secondCoordinatesToCellNameError != nil {
		return fmt.Errorf("failed to get cell coordinates from [%d, %d]: %w", 2, *excelRow, secondCoordinatesToCellNameError)
	}

	lastCellName, lastCoordinatesToCellNameError := excelize.CoordinatesToCellName(len(sortedTags)+2, *excelRow)
	if lastCoordinatesToCellNameError != nil {
		return fmt.Errorf("failed to get cell coordinates from [%d, %d]: %w",
			len(sortedTags)+2, *excelRow, lastCoordinatesToCellNameError)
	}

	err = excel.SetCellStyle(sheetName, secondCellName, lastCellName, styleBlackCenter)
	if err != nil {
		return fmt.Errorf("unable to write row: %w", err)
	}

	return nil
}

// markUsedTags writes an X into the cell of each tag of the row that is in use.
func markUsedTags(excel *excelize.File, excelRow int, sheetName string, sortedTags []string, tagsUsed []string) error {
	for i, tag := range sortedTags {
		if contains(tagsUsed, tag) {
			cellName, coordinatesToCellNameError := excelize.CoordinatesToCellName(i+2, excelRow)
			if coordinatesToCellNameError != nil {
				return fmt.Errorf("failed to get cell coordinates from [%d, %d]: %w", i+2, excelRow, coordinatesToCellNameError)
			}

			err := excel.SetCellValue(sheetName, cellName, "X")
			if err != nil {
				return fmt.Errorf("unable to write row: %w", err)
			}
		}
	}
	return nil
}

func removeFormattingTags(content string) string {
	result := strings.ReplaceAll(strings.ReplaceAll(content, "<b>", ""), "</b>", "")
	result = strings.ReplaceAll(strings.ReplaceAll(result, "<i>", ""), "</i>", "")
	result = strings.ReplaceAll(strings.ReplaceAll(result, "<u>", ""), "</u>", "")
	return result
}
