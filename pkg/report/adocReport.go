package report

import (
	"errors"
	"fmt"
	"image"
	"io"
	"log"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/Pinguladora/threagile/pkg/types"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type adocReport struct {
	targetDirectory string
	model           *types.Model
	mainFile        *os.File
	imagesDir       string

	riskRules types.RiskRules

	iconsType        string
	tocDepth         int
	hideEmptyChapter bool
}

// writeFile is os.WriteFile with the permissions of os.Create, like copyFile.
func writeFile(destination string, data []byte) error {
	/* #nosec destination is not tainted (see caller restricting it to the desired report output folder) */
	dst, err := os.Create(destination)
	if err != nil {
		return fmt.Errorf("unable to create %q: %w", destination, err)
	}

	_, writeErr := dst.Write(data)
	if err = errors.Join(writeErr, dst.Close()); err != nil {
		return fmt.Errorf("unable to write %q: %w", destination, err)
	}

	return nil
}

func copyFile(source string, destination string) error {
	/* #nosec source is not tainted (see caller restricting it to files we created ourself
	or are legitimate to be copied) */
	src, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("unable to open %q: %w", source, err)
	}
	defer func() { _ = src.Close() }()
	/* #nosec destination is not tainted (see caller restricting it to the desired report output folder) */
	dst, err := os.Create(destination)
	if err != nil {
		return fmt.Errorf("unable to create %q: %w", destination, err)
	}
	defer func() { _ = dst.Close() }()
	_, err = io.Copy(dst, src)
	if err != nil {
		return fmt.Errorf("unable to copy %q to %q: %w", source, destination, err)
	}
	return nil
}

// mustCopyFile copies source to destination and exits the program if that fails.
func mustCopyFile(source string, destination string) {
	err := copyFile(source, destination)
	if err != nil {
		log.Fatal("Could not copy file: »" + source + "« to »" + destination + "«: " + err.Error())
	}
}

func fixBasicHtml(inputWithHtml string) string {
	result := strings.ReplaceAll(inputWithHtml, "<b>", "*")
	result = strings.ReplaceAll(result, "</b>", "*")

	result = strings.ReplaceAll(result, "<i>", "_")
	result = strings.ReplaceAll(result, "</i>", "_")

	result = strings.ReplaceAll(result, "<u>", "[.underline]#")
	result = strings.ReplaceAll(result, "</u>", "#")

	result = strings.ReplaceAll(result, "<br>", "\n")
	result = strings.ReplaceAll(result, "</br>", "\n")

	linkAndName := regexp.MustCompile(`<a href=\"(.*)\".*>(.*)</a>`)
	result = linkAndName.ReplaceAllString(result, "${1}[${2}]")
	return result
}

func NewAdocReport(targetDirectory string, riskRules types.RiskRules, hideEmptyChapter bool) adocReport {
	adoc := adocReport{
		targetDirectory:  filepath.Join(targetDirectory, "adocReport"),
		iconsType:        "font",
		tocDepth:         2,
		imagesDir:        filepath.Join(targetDirectory, "adocReport", "images"),
		riskRules:        riskRules,
		hideEmptyChapter: hideEmptyChapter,
	}
	return adoc
}

func writeLine(file *os.File, line string) {
	_, err := file.WriteString(line + "\n")
	if err != nil {
		log.Fatal("Could not write »" + line + "« into: " + file.Name() + ": " + err.Error())
	}
}

func (adoc adocReport) writeDefaultTheme(logoImagePath string) error {
	err := os.MkdirAll(filepath.Join(adoc.targetDirectory, "theme"), 0o750)
	if err != nil {
		return fmt.Errorf("unable to create the theme folder: %w", err)
	}
	err = os.MkdirAll(adoc.imagesDir, 0o750)
	if err != nil {
		return fmt.Errorf("unable to create %q: %w", adoc.imagesDir, err)
	}
	theme, err := adoc.createFile(filepath.Join("theme", "pdf-theme.yml"))
	defer func() { _ = theme.Close() }()
	if err != nil {
		return err
	}
	adocLogoPath, err := adoc.writeThemeLogo(logoImagePath)
	if err != nil {
		return err
	}

	writeLine(theme, `extends: default
page:
  layout: portrait
  margin: [3cm, 2.5cm, 2.7cm, 2.5cm]
title-page:
  authors:
    content: "{author}, {author-homepage}[]"
`)
	if adocLogoPath != "" {
		// "image:" is both the asciidoctor-pdf theme key and the image macro. They are
		// split into two literals so dupword does not "fix" the repeat away.
		writeLine(theme,
			`  logo:
    image: `+"image:"+adocLogoPath+`[]`)
	}
	writeLine(theme, adoc.themeHeaderAndFooter()+themeRoles())

	return nil
}

// writeThemeLogo copies the logo of the report, if there is one, into the theme folder and
// returns its path relative to the theme.
func (adoc adocReport) writeThemeLogo(logoImagePath string) (string, error) {
	adocLogoPath := ""
	if logoImagePath != "" {
		logo, err := reportLogo(logoImagePath)
		if err != nil {
			return "", err
		}

		if logo != nil {
			adocLogoPath = "logo" + filepath.Ext(logoImagePath)
			logoDestPath := filepath.Join(adoc.targetDirectory, "theme", adocLogoPath)
			err = writeFile(logoDestPath, logo)
			if err != nil {
				return "", err
			}
		} else {
			log.Println("logo image path does not exist: " + logoImagePath)
		}
	}
	return adocLogoPath, nil
}

// themeHeaderAndFooter returns the header and footer of the PDF theme.
func (adoc adocReport) themeHeaderAndFooter() string {
	return `header:
  height: 2cm
  line-height: 1
  recto:
    center:
      content: "{document-title} -- ` + adoc.model.Title + ` -- {section-or-chapter-title}"
  verso:
    center:
      content: "{document-title} -- ` + adoc.model.Title + ` -- {section-or-chapter-title}"
footer:
  height: 2cm
  line-height: 1.2
  recto:
    center:
      content: -- confidential --
    left:
      content: "Version: {DOC_VERSION}"
    right:
      content: "Page {page-number} of {page-count}"
  verso:
    center:
      content: -- confidential --
    left:
      content: "Version: {DOC_VERSION}"
    right:
      content: Page {page-number} of {page-count}
`
}

// themeRoles returns the roles of the PDF theme, which colour the text.
func themeRoles() string {
	return `role:
  LowRisk:
    font-color: ` + rgbHexColorLowRisk() + `
  MediumRisk:
    font-color: ` + rgbHexColorMediumRisk() + `
  ElevatedRisk:
    font-color: ` + rgbHexColorElevatedRisk() + `
  HighRisk:
    font-color: ` + rgbHexColorHighRisk() + `
  CriticalRisk:
    font-color: ` + rgbHexColorCriticalRisk() + `
  OutOfScope:
    font-color: #7f7f7f
  GreyText:
    font-color: #505050
  LightGreyText:
    font-color: #646464
  ModelFailure:
    font-color: #945200
  RiskStatusFalsePositive:
    font-color: ` + rgbHexColorRiskStatusFalsePositive() + `
  RiskStatusMitigated:
    font-color: ` + rgbHexColorRiskStatusMitigated() + `
  RiskStatusInProgress:
    font-color: ` + rgbHexColorRiskStatusInProgress() + `
  RiskStatusAccepted:
    font-color: ` + rgbHexColorRiskStatusAccepted() + `
  RiskStatusInDiscussion:
    font-color: ` + rgbHexColorRiskStatusInDiscussion() + `
  RiskStatusUnchecked:
    font-color: ` + RgbHexColorRiskStatusUnchecked() + `
  Twilight:
    font-color: ` + rgbHexColorTwilight() + `
  SmallGrey:
    font-size: 0.5em
    font-color: #505050
  Silver:
    font-color: #C0C0C0
`
}

func (adoc adocReport) writeMainLine(line string) {
	writeLine(adoc.mainFile, line)
}

func (adoc adocReport) WriteReport(model *types.Model,
	dataFlowDiagramFilenamePNG string,
	dataAssetDiagramFilenamePNG string,
	modelFilename string,
	skipRiskRules []string,
	buildTimestamp string,
	threagileVersion string,
	modelHash string,
	introTextRAA string,
	customRiskRules types.RiskRules,
	logoImagePath string,
	hideChapters map[ChaptersToShowHide]bool,
) error {
	adoc.model = model
	mainFile, err := adoc.initReport()
	if err != nil {
		return err
	}
	adoc.mainFile = mainFile
	err = adoc.writeDefaultTheme(logoImagePath)
	if err != nil {
		return err
	}
	// err = adoc.createDefaultTheme() FIXME
	adoc.writeTitleAndPreamble()
	err = adoc.writeManagementSummery()
	if err != nil {
		return err
	}

	chapters := adoc.chapters(dataFlowDiagramFilenamePNG, dataAssetDiagramFilenamePNG, modelFilename, skipRiskRules,
		buildTimestamp, threagileVersion, modelHash, introTextRAA, customRiskRules, hideChapters)
	for _, chapter := range chapters {
		if chapter.hide {
			continue
		}
		err = chapter.write()
		if err != nil {
			return fmt.Errorf("%s: %w", chapter.errorContext, err)
		}
	}
	err = adoc.writeAppendixRating()
	if err != nil {
		return errors.New("error creating appendix for the rating mappings")
	}
	err = adoc.writeDisclaimer()
	if err != nil {
		return fmt.Errorf("error creating disclaimer: %w", err)
	}
	return nil
}

// adocChapter is a chapter of the AsciiDoc report between the management summary and the appendix.
type adocChapter struct {
	errorContext string
	write        func() error
	hide         bool
}

// chapters returns the chapters of the AsciiDoc report in the order they are written.
func (adoc adocReport) chapters(
	dataFlowDiagramFilenamePNG string,
	dataAssetDiagramFilenamePNG string,
	modelFilename string,
	skipRiskRules []string,
	buildTimestamp string,
	threagileVersion string,
	modelHash string,
	introTextRAA string,
	customRiskRules types.RiskRules,
	hideChapters map[ChaptersToShowHide]bool,
) []adocChapter {
	return []adocChapter{
		{"error creating impact initial risks", adoc.writeImpactInitialRisks, false},
		{"error creating risk mitigation status", adoc.writeRiskMitigationStatus, false},
		{"error creating asset register status", adoc.writeAssetRegister, hideChapters[AssetRegister]},
		{"error creating impact remaining risks", adoc.writeImpactRemainingRisks, false},
		{"error creating target description", func() error {
			return adoc.writeTargetDescription(filepath.Dir(modelFilename))
		}, false},
		{"error creating data flow diagram section", func() error {
			return adoc.writeDataFlowDiagram(dataFlowDiagramFilenamePNG)
		}, false},
		{"error creating security requirements", adoc.writeSecurityRequirements, false},
		{"error creating abuse cases", adoc.writeAbuseCases, false},
		{"error creating tag listing", adoc.writeTagListing, false},
		{"error creating STRIDE", adoc.writeSTRIDE, false},
		{"error creating assignment by function", adoc.writeAssignmentByFunction, false},
		{"error creating RAA", func() error {
			return adoc.writeRAA(introTextRAA)
		}, false},
		{"error creating data risk mapping", func() error {
			return adoc.writeDataRiskMapping(dataAssetDiagramFilenamePNG)
		}, false},
		{"error creating Out of Scope Assets", adoc.writeOutOfScopeAssets, false},
		{"error creating model failures", adoc.writeModelFailures, false},
		{"error creating questions", adoc.writeQuestions, false},
		{"error creating risk categories", adoc.writeRiskCategories, false},
		{"error creating technical assets", adoc.writeTechnicalAssets, false},
		{"error creating data assets", adoc.writeDataAssets, false},
		{"error creating trust boundaries", adoc.writeTrustBoundaries, false},
		{"error creating shared runtimes", adoc.writeSharedRuntimes, false},
		{"error creating risk rules checked", func() error {
			return adoc.writeRiskRulesChecked(modelFilename, skipRiskRules, buildTimestamp, threagileVersion, modelHash,
				customRiskRules)
		}, hideChapters[RiskRulesCheckedByThreagile]},
	}
}

// createFile creates (or truncates) the named file in the target directory.
func (adoc adocReport) createFile(filename string) (*os.File, error) {
	/* #nosec filename is not tainted (see callers passing fixed chapter file names only) */
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	if err != nil {
		return nil, fmt.Errorf("unable to create %q: %w", filename, err)
	}
	return f, nil
}

// initReport recreates the target directory and returns the newly created main file.
func (adoc adocReport) initReport() (*os.File, error) {
	_ = os.RemoveAll(adoc.targetDirectory)
	err := os.MkdirAll(adoc.targetDirectory, 0o750)
	if err != nil {
		return nil, fmt.Errorf("unable to create %q: %w", adoc.targetDirectory, err)
	}
	mainFile, err := os.Create(filepath.Join(adoc.targetDirectory, "000_main.adoc"))
	if err != nil {
		return nil, fmt.Errorf("unable to create the main AsciiDoc file: %w", err)
	}

	return mainFile, nil
}

func (adoc adocReport) writeTitleAndPreamble() {
	adoc.writeMainLine("= Threat Model Report: " + adoc.model.Title)
	adoc.writeMainLine(":title-page:")
	adoc.writeMainLine(":author: " + adoc.model.Author.Name)
	if strings.HasPrefix(adoc.model.Author.Homepage, "http") {
		adoc.writeMainLine(`:author-homepage: ` + adoc.model.Author.Homepage)
	} else {
		adoc.writeMainLine(`:author-homepage: https://` + adoc.model.Author.Homepage)
	}
	adoc.writeMainLine(":email: " + adoc.model.Author.Contact)
	adoc.writeMainLine(":toc:")
	adoc.writeMainLine(":toclevels: " + strconv.Itoa(adoc.tocDepth))
	adoc.writeMainLine(":icons: " + adoc.iconsType)
	reportDate := adoc.model.Date
	if reportDate.IsZero() {
		reportDate = types.Date{Time: types.Now()}
	}
	adoc.writeMainLine(":revdate: " + reportDate.Format("2 January 2006"))
	adoc.writeMainLine("")
}

func (adoc adocReport) writeManagementSummery() error {
	filename := "010_ManagementSummary.adoc"
	ms, err := adoc.createFile(filename)
	defer func() { _ = ms.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	writeLine(ms, "= Management Summary")
	writeLine(ms, "")
	writeLine(ms, "Threagile toolkit was used to model the architecture of \""+adoc.model.Title+"\" and derive risks by "+
		"analyzing the components and data flows.")
	if contributors := contributorsLine(adoc.model); contributors != "" {
		writeLine(ms, contributors+".")
	}
	writeLine(ms, "The risks identified during this analysis are shown in the following chapters.")
	writeLine(ms, "Identified risks during threat modeling do not necessarily mean that the "+
		"vulnerability associated with this risk actually exists: it is more to be seen as a list"+
		" of potential risks and threats, which should be individually reviewed and reduced by removing false positives.")
	writeLine(ms, "For the remaining risks it should be checked in the design and implementation of \""+adoc.model.Title+
		"\" whether the mitigation advices have been applied or not.")
	writeLine(ms, "\n\n")
	writeLine(ms, "Each risk finding references a chapter of the OWASP ASVS (Application Security Verification "+
		"Standard) audit checklist.")
	writeLine(ms, "The OWASP ASVS checklist should be considered as an inspiration by architects and developers to "+
		"further harden the application in a Defense-in-Depth approach.")
	writeLine(ms, "Additionally, for each risk finding a link towards a matching OWASP Cheat Sheet or similar with "+
		"technical details about how to implement a mitigation is given.")
	writeLine(ms, "\n\n")
	writeLine(ms, "In total *"+strconv.Itoa(totalRiskCount(adoc.model))+" initial risks* in *"+
		strconv.Itoa(len(adoc.model.GeneratedRisksByCategory))+" categories* have been identified during the threat "+
		"modeling process:")
	writeLine(ms, "\n\n")

	writeLine(ms, adoc.managementSummaryPieCharts())
	// individual management summary comment
	if len(adoc.model.ManagementSummaryComment) > 0 {
		writeLine(ms, "\n\n\n"+fixBasicHtml(adoc.model.ManagementSummaryComment))
	}

	return nil
}

// managementSummaryPieCharts returns the pie charts of all risks by severity and by risk
// tracking status.
func (adoc adocReport) managementSummaryPieCharts() string {
	countCritical := len(filteredBySeverity(adoc.model, types.CriticalSeverity))
	countHigh := len(filteredBySeverity(adoc.model, types.HighSeverity))
	countElevated := len(filteredBySeverity(adoc.model, types.ElevatedSeverity))
	countMedium := len(filteredBySeverity(adoc.model, types.MediumSeverity))
	countLow := len(filteredBySeverity(adoc.model, types.LowSeverity))

	countStatusUnchecked := len(filteredByRiskStatus(adoc.model, types.Unchecked))
	countStatusInDiscussion := len(filteredByRiskStatus(adoc.model, types.InDiscussion))
	countStatusAccepted := len(filteredByRiskStatus(adoc.model, types.Accepted))
	countStatusInProgress := len(filteredByRiskStatus(adoc.model, types.InProgress))
	countStatusMitigated := len(filteredByRiskStatus(adoc.model, types.Mitigated))
	countStatusFalsePositive := len(filteredByRiskStatus(adoc.model, types.FalsePositive))

	return `[cols="a,a",frame=none,grid=none]
|===
|
[mermaid]
....
%%{init: {'pie' : {'textPosition' : 0.5}, 'theme': 'base', 'themeVariables': { 'pie1': '` + rgbHexColorCriticalRisk() +
		`', 'pie2': '` + rgbHexColorHighRisk() + `', 'pie3': '` + rgbHexColorElevatedRisk() + `', 'pie4': '` +
		rgbHexColorMediumRisk() + `', 'pie5': '` + rgbHexColorLowRisk() + `'}}}%%
pie showData
  "critical risk" : ` + strconv.Itoa(countCritical) + `
  "high risk" : ` + strconv.Itoa(countHigh) + `
  "elevated risk" : ` + strconv.Itoa(countElevated) + `
  "medium risk" : ` + strconv.Itoa(countMedium) + `
  "low risk" : ` + strconv.Itoa(countLow) + `
....

|
[mermaid]
....
%%{init: {'pie' : {'textPosition' : 0.5}, 'theme': 'base', 'themeVariables': { 'pie1': '` +
		RgbHexColorRiskStatusUnchecked() + `', 'pie2': '` + rgbHexColorRiskStatusInDiscussion() + `', 'pie3': '` +
		rgbHexColorRiskStatusAccepted() + `', 'pie4': '` + rgbHexColorRiskStatusInProgress() + `', 'pie5': '` +
		rgbHexColorRiskStatusMitigated() + `', 'pie5': '` + rgbHexColorRiskStatusFalsePositive() + `'}}}%%
pie showData
  "unchecked" : ` + strconv.Itoa(countStatusUnchecked) + `
  "in discussion" : ` + strconv.Itoa(countStatusInDiscussion) + `
  "accepted" : ` + strconv.Itoa(countStatusAccepted) + `
  "in progress" : ` + strconv.Itoa(countStatusInProgress) + `
  "mitigated" : ` + strconv.Itoa(countStatusMitigated) + `
  "false positive" : ` + strconv.Itoa(countStatusFalsePositive) + `
....
|===
`
}

func colorPrefixBySeverity(severity types.RiskSeverity, smallFont bool) (string, string) {
	start := ""
	switch severity {
	case types.CriticalSeverity:
		start = "[.CriticalRisk"
	case types.HighSeverity:
		start = "[.HighRisk"
	case types.ElevatedSeverity:
		start = "[.ElevatedRisk"
	case types.MediumSeverity:
		start = "[.MediumRisk"
	case types.LowSeverity:
		start = "[.LowRisk"
	default:
		return "", ""
	}
	if smallFont {
		start += ".small"
	}
	return start + "]#", "#"
}

func colorPrefixByDataBreachProbability(probability types.DataBreachProbability, smallFont bool) (string, string) {
	switch probability {
	case types.Probable:
		return colorPrefixBySeverity(types.HighSeverity, smallFont)
	case types.Possible:
		return colorPrefixBySeverity(types.MediumSeverity, smallFont)
	case types.Improbable:
		return colorPrefixBySeverity(types.LowSeverity, smallFont)
	default:
		return "", ""
	}
}

func (adoc adocReport) addCategories(f *os.File, risksByCategory map[string][]*types.Risk, initialRisks bool,
	severity types.RiskSeverity, bothInitialAndRemainingRisks bool, describeDescription bool,
) {
	describeImpact := true
	riskCategories := getRiskCategories(adoc.model, reduceToSeverityRisk(risksByCategory, initialRisks, severity))
	sort.Sort(types.ByRiskCategoryTitleSort(riskCategories))
	for _, riskCategory := range riskCategories {
		risksStr := risksByCategory[riskCategory.ID]
		if !initialRisks {
			risksStr = types.ReduceToOnlyStillAtRisk(risksStr)
		}
		if len(risksStr) == 0 {
			continue
		}

		writeLine(f, categoryLine(riskCategory, risksStr, initialRisks, severity, bothInitialAndRemainingRisks))

		switch {
		case describeImpact:
			writeLine(f, firstParagraph(riskCategory.Impact))
		case describeDescription:
			writeLine(f, firstParagraph(riskCategory.Description))
		default:
			writeLine(f, firstParagraph(riskCategory.Mitigation))
		}
		writeLine(f, "")
	}
}

// categoryLine returns the line of a risk category in an impact analysis: a link to the category
// with the number of its risks and their highest exploitation likelihood and impact.
func categoryLine(riskCategory *types.RiskCategory, risksStr []*types.Risk, initialRisks bool,
	severity types.RiskSeverity, bothInitialAndRemainingRisks bool,
) string {
	colorPrefix, colorSuffix := colorPrefixBySeverity(severity, false)
	prefix := severityPrefix(severity)
	if len(types.ReduceToOnlyStillAtRisk(risksStr)) == 0 {
		colorPrefix = ""
		colorSuffix = ""
	}
	fullLine := "<<" + riskCategory.ID + "," + colorPrefix + prefix + "*" + riskCategory.Title + "*: "

	count := len(risksStr)
	initialStr := "Initial"
	if !initialRisks {
		initialStr = "Remaining"
	}
	remainingRisks := types.ReduceToOnlyStillAtRisk(risksStr)
	suffix := strconv.Itoa(count) + " " + initialStr + " Risk"
	if count != 1 {
		suffix += "s"
	}
	if bothInitialAndRemainingRisks {
		suffix = riskSuffix(len(remainingRisks), count)
	}
	suffix += " - Exploitation likelihood is _"
	if initialRisks {
		suffix += highestExploitationLikelihood(risksStr).Title() + "_ with _" +
			highestExploitationImpact(risksStr).Title() + "_ impact."
	} else {
		suffix += highestExploitationLikelihood(remainingRisks).Title() + "_ with _" +
			highestExploitationImpact(remainingRisks).Title() + "_ impact."
	}

	return fullLine + suffix + colorSuffix + ">>::"
}

// severityPrefix returns the severity in front of a risk category in an impact analysis.
func severityPrefix(severity types.RiskSeverity) string {
	switch severity {
	case types.CriticalSeverity:
		return "Critical: "
	case types.HighSeverity:
		return "High: "
	case types.ElevatedSeverity:
		return "Elevated: "
	case types.MediumSeverity:
		return "Medium: "
	case types.LowSeverity:
		return "Low: "
	default:
		return ""
	}
}

func (adoc adocReport) impactAnalysis(f *os.File, initialRisks bool) int {
	count := 0
	catCount := 0
	initialStr := ""
	if initialRisks {
		count = totalRiskCount(adoc.model)
		catCount = len(adoc.model.GeneratedRisksByCategory)
		initialStr = "initial"
	} else {
		count = len(filteredByStillAtRisk(adoc.model))
		catCount = len(reduceToOnlyStillAtRisk(adoc.model.GeneratedRisksByCategoryWithCurrentStatus()))
		initialStr = "remaining"
	}

	riskText := "risks"
	if count == 1 {
		riskText = textRiskLower
	}
	catText := "categories"
	if catCount == 1 {
		catText = textCategory
	}

	titleCaser := cases.Title(language.English)
	chapTitle := titleCaser.String("= Impact Analysis of " + strconv.Itoa(count) + " " + initialStr + " " + riskText +
		" in " + strconv.Itoa(catCount) + " " + catText)
	writeLine(f, chapTitle)
	writeLine(f, adocFootnoteRiskFindings)

	writeLine(f,
		"The most prevalent impacts of the *"+strconv.Itoa(count)+" "+initialStr+" "+riskText+"*"+
			" (distributed over *"+strconv.Itoa(catCount)+" risk categories*) are "+
			"(taking the severity ratings into account and using the highest for each category)!{fn-risk-findings}")
	writeLine(f, "")
	for _, severity := range []types.RiskSeverity{
		types.CriticalSeverity, types.HighSeverity, types.ElevatedSeverity, types.MediumSeverity, types.LowSeverity,
	} {
		adoc.addCategories(f, adoc.model.GeneratedRisksByCategoryWithCurrentStatus(), initialRisks, severity, false, false)
	}

	return count
}

func (adoc adocReport) writeImpactInitialRisks() error {
	filename := "020_ImpactIntialRisks.adoc"
	ir, err := adoc.createFile(filename)
	defer func() { _ = ir.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.impactAnalysis(ir, true)
	return nil
}

func (adoc adocReport) riskMitigationStatus(f *os.File) {
	writeLine(f, "= Risk Mitigation")
	writeLine(f, "The following chart gives a high-level overview of the risk tracking status (including mitigated "+
		"risks):")

	writeLine(f, adoc.riskStatusChart())
	writeLine(f, "")
	stillAtRisk := filteredByStillAtRisk(adoc.model)
	count := len(stillAtRisk)
	if count == 0 {
		writeLine(f, "After removal of risks with status _mitigated_ and _false positive_ "+
			"*"+strconv.Itoa(count)+" remain unmitigated*.")
	} else {
		writeLine(f, "After removal of risks with status _mitigated_ and _false positive_ "+
			"the following *"+strconv.Itoa(count)+" remain unmitigated*:")

		writeLine(f, adoc.unmitigatedRisksPieCharts())
	}
}

// riskStatusChart returns the bar chart of the risk tracking status of the risks by severity.
func (adoc adocReport) riskStatusChart() string {
	countStatusUnchecked := len(filteredByRiskStatus(adoc.model, types.Unchecked))
	countStatusInDiscussion := len(filteredByRiskStatus(adoc.model, types.InDiscussion))
	countStatusAccepted := len(filteredByRiskStatus(adoc.model, types.Accepted))
	countStatusInProgress := len(filteredByRiskStatus(adoc.model, types.InProgress))
	countStatusMitigated := len(filteredByRiskStatus(adoc.model, types.Mitigated))
	countStatusFalsePositive := len(filteredByRiskStatus(adoc.model, types.FalsePositive))

	return `
[vegalite]
....
{
  "width": 400,
  "$schema": "https://vega.github.io/schema/vega-lite/v4.json",
  "data": {
    "values": [
` + adoc.riskStatusChartValues(types.LowSeverity) + `,

` + adoc.riskStatusChartValues(types.MediumSeverity) + `,

` + adoc.riskStatusChartValues(types.ElevatedSeverity) + `,

` + adoc.riskStatusChartValues(types.HighSeverity) + `,

` + adoc.riskStatusChartValues(types.CriticalSeverity) + `
    ]
  },
  "mark": {"type": "bar", "cornerRadiusTopLeft": 3, "cornerRadiusTopRight": 3},
  "encoding": {
    "x": {"field": "risk", "type": "ordinal", "title": "", "sort": [], "axis": {
        "labelAngle": 0
    }},
    "y": {"field": "value", "type": "quantitative", "title": "", "axis": {
      "orient": "right"
    }},
    "color": {
      "field": "status",
      "scale": {
        "domain": ["Unchecked", "InDiscussion", "Accepted", "InProgress", "Mitigated", "FalsePositive"],
        "range": ["` + RgbHexColorRiskStatusUnchecked() + `", "` + rgbHexColorRiskStatusInDiscussion() + `", "` +
		rgbHexColorRiskStatusAccepted() + `", "` + rgbHexColorRiskStatusInProgress() + `", "` +
		rgbHexColorRiskStatusMitigated() + `", "` + rgbHexColorRiskStatusFalsePositive() + `"]
      },
      "legend" : {
        "title": "",
        "labelExpr": "datum.label == \"Unchecked\" ? \"` + strconv.Itoa(countStatusUnchecked) +
		` unchecked\" : datum.label == \"InDiscussion\" ? \"` + strconv.Itoa(countStatusInDiscussion) +
		` in discussion\" : datum.label == \"Accepted\" ? \"` + strconv.Itoa(countStatusAccepted) +
		` accepted\" : datum.label == \"InProgress\" ? \"` + strconv.Itoa(countStatusInProgress) +
		` in progress\" : datum.label == \"Mitigated\" ? \"` + strconv.Itoa(countStatusMitigated) +
		` mitigated\" : datum.label == \"FalsePositive\" ? \"` + strconv.Itoa(countStatusFalsePositive) +
		` false positive\" : \"\""
      }
    }
  }
}
....
`
}

// riskStatusChartValues returns the data values of the risk tracking status chart for the risks
// of one severity, one value per risk status.
func (adoc adocReport) riskStatusChartValues(severity types.RiskSeverity) string {
	risks := filteredBySeverity(adoc.model, severity)
	title := severity.Title() + " (" + strconv.Itoa(len(risks)) + ")"
	statuses := []struct {
		status types.RiskStatus
		name   string
		color  string
	}{
		{types.Unchecked, "Unchecked", RgbHexColorRiskStatusUnchecked()},
		{types.InDiscussion, "InDiscussion", rgbHexColorRiskStatusInDiscussion()},
		{types.Accepted, "Accepted", rgbHexColorRiskStatusAccepted()},
		{types.InProgress, "InProgress", rgbHexColorRiskStatusInProgress()},
		{types.Mitigated, "Mitigated", rgbHexColorRiskStatusMitigated()},
		{types.FalsePositive, "FalsePositive", rgbHexColorRiskStatusFalsePositive()},
	}
	values := make([]string, 0, len(statuses))
	for _, status := range statuses {
		values = append(values, `      {"risk": "`+title+`", "value": `+
			strconv.Itoa(len(reduceToRiskStatus(risks, status.status)))+`, "status": "`+status.name+
			`", "color": "`+status.color+`"}`)
	}
	return strings.Join(values, ",\n")
}

// unmitigatedRisksPieCharts returns the pie charts of the risks still at risk by severity and by
// function.
func (adoc adocReport) unmitigatedRisksPieCharts() string {
	countCritical := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(adoc.model, types.CriticalSeverity)))
	countHigh := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(adoc.model, types.HighSeverity)))
	countElevated := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(adoc.model, types.ElevatedSeverity)))
	countMedium := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(adoc.model, types.MediumSeverity)))
	countLow := len(types.ReduceToOnlyStillAtRisk(filteredBySeverity(adoc.model, types.LowSeverity)))

	countBusinessSide := len(types.ReduceToOnlyStillAtRisk(filteredByRiskFunction(adoc.model, types.BusinessSide)))
	countArchitecture := len(types.ReduceToOnlyStillAtRisk(filteredByRiskFunction(adoc.model, types.Architecture)))
	countDevelopment := len(types.ReduceToOnlyStillAtRisk(filteredByRiskFunction(adoc.model, types.Development)))
	countOperation := len(types.ReduceToOnlyStillAtRisk(filteredByRiskFunction(adoc.model, types.Operations)))

	return `[cols="a,a",frame=none,grid=none]
|===
|
[mermaid]
....
%%{init: {'pie' : {'textPosition' : 0.5}, 'theme': 'base', 'themeVariables': { 'pie1': '` + rgbHexColorCriticalRisk() +
		`', 'pie2': '` + rgbHexColorHighRisk() + `', 'pie3': '` + rgbHexColorElevatedRisk() + `', 'pie4': '` +
		rgbHexColorMediumRisk() + `', 'pie5': '` + rgbHexColorLowRisk() + `'}}}%%
pie showData
  "unmitigated critical risk" : ` + strconv.Itoa(countCritical) + `
  "unmitigated high risk" : ` + strconv.Itoa(countHigh) + `
  "unmitigated elevated risk" : ` + strconv.Itoa(countElevated) + `
  "unmitigated medium risk" : ` + strconv.Itoa(countMedium) + `
  "unmitigated low risk" : ` + strconv.Itoa(countLow) + `
....

|
[mermaid]
....
%%{init: {'pie' : {'textPosition' : 0.5}, 'theme': 'base', 'themeVariables': { 'pie1': '` + rgbHexColorBusiness() +
		`', 'pie2': '` + rgbHexColorArchitecture() + `', 'pie3': '` + rgbHexColorDevelopment() + `', 'pie4': '` +
		rgbHexColorOperation() + `'}}}%%
pie showData
  "business side related" : ` + strconv.Itoa(countBusinessSide) + `
  "architecture related" : ` + strconv.Itoa(countArchitecture) + `
  "development related" : ` + strconv.Itoa(countDevelopment) + `
  "operations related" : ` + strconv.Itoa(countOperation) + `
....
|===
`
}

func (adoc adocReport) writeRiskMitigationStatus() error {
	filename := "030_RiskMitigationStatus.adoc"
	rms, err := adoc.createFile(filename)
	defer func() { _ = rms.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.riskMitigationStatus(rms)
	return nil
}

func (adoc adocReport) assetRegister(f *os.File) {
	writeLine(f, "= Asset Register")
	writeLine(f, "")

	writeLine(f, "== Technical Assets")
	writeLine(f, "")
	for _, technicalAsset := range sortedTechnicalAssetsByTitle(adoc.model) {
		fullLine := "<<" + technicalAsset.Id + ",*" + technicalAsset.Title + "*"
		if technicalAsset.OutOfScope {
			fullLine += ": out-of-scope"
		}
		writeLine(f, fullLine+">>::")
		writeLine(f, "  "+technicalAsset.Description)
		writeLine(f, "")
	}

	writeLine(f, "== Data Assets")
	writeLine(f, "")

	for _, dataAsset := range sortedDataAssetsByTitle(adoc.model) {
		writeLine(f, "<<dataAsset:"+dataAsset.Id+",*"+dataAsset.Title+"*"+">>::")
		writeLine(f, "  "+dataAsset.Description)
		writeLine(f, "")
	}
}

func (adoc adocReport) writeAssetRegister() error {
	filename := "035_AssetRegister.adoc"
	ar, err := adoc.createFile(filename)
	defer func() { _ = ar.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.assetRegister(ar)
	return nil
}

func (adoc adocReport) writeImpactRemainingRisks() error {
	filename := "040_ImpactRemainingRisks.adoc"
	irr, err := adoc.createFile(filename)
	defer func() { _ = irr.Close() }()
	if err != nil {
		return err
	}

	nRemaining := adoc.impactAnalysis(irr, false)
	if nRemaining > 0 || !adoc.hideEmptyChapter {
		adoc.writeMainLine("<<<")
		adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")
	}

	return nil
}

func addCustomImages(f *os.File, customImages []map[string]string, baseFolder string) {
	for _, customImage := range customImages {
		for _, imageFilename := range slices.Sorted(maps.Keys(customImage)) {
			imageFilenameWithoutPath := filepath.Base(imageFilename)
			imageFullFilename := filepath.Join(baseFolder, imageFilenameWithoutPath)
			writeLine(f, "image::"+imageFullFilename+"[]")
		}
	}
}

func (adoc adocReport) targetDescription(f *os.File, baseFolder string) {
	writeLine(f, "= Application Overview")
	writeLine(f, "== Business Criticality\n")
	writeLine(f, "The overall business criticality of \""+adoc.model.Title+"\" was rated as:\n")

	critString := "( "
	criticality := adoc.model.BusinessCriticality
	first := true
	for _, critValue := range types.CriticalityValues() {
		if !first {
			critString += " |"
		}
		if critValue == criticality {
			critString += " [.underline]#*" + strings.ToUpper(critValue.String()) + "*#"
		} else {
			critString += " [GreyText]#" + critValue.String() + "#"
		}
		first = false
	}
	critString += "  )"
	writeLine(f, critString)

	writeLine(f, "\n\n")
	writeLine(f, "== Business Overview")
	writeLine(f, fixBasicHtml(adoc.model.BusinessOverview.Description))
	addCustomImages(f, adoc.model.BusinessOverview.Images, baseFolder)

	writeLine(f, "\n\n")
	writeLine(f, "== Technical Overview")
	writeLine(f, fixBasicHtml(adoc.model.TechnicalOverview.Description))
	addCustomImages(f, adoc.model.TechnicalOverview.Images, baseFolder)
}

func (adoc adocReport) writeTargetDescription(baseFolder string) error {
	filename := "050_TargetDescription.adoc"
	td, err := adoc.createFile(filename)
	defer func() { _ = td.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.targetDescription(td, baseFolder)
	return nil
}

func (adoc adocReport) dataFlowDiagram(f *os.File, diagramFilenamePNG string) {
	writeLine(f, "= Data-Flow Diagram")
	// intermediate newlines are ignored in asciidoctor
	writeLine(f, `
The following diagram was generated by Threagile based on the model input and gives a high-level overview of the `+
		`data-flow
between technical assets. The RAA value is the calculated _Relative Attacker Attractiveness_ in percent.
For a full high-resolution version of this diagram please refer to the PNG image file alongside this report.
	`)
	writeLine(f, "\nimage::"+diagramFilenamePNG+"[]")
}

func imageIsWiderThanHigh(diagramFilenamePNG string) bool {
	/* #nosec diagramFilenamePNG is not tainted (see caller restricting it to image files of model folder only) */
	imagePath, err := os.Open(diagramFilenamePNG)
	if err != nil {
		log.Fatalln("error opening image file: %w", err)
		return false
	}
	defer func() { _ = imagePath.Close() }()
	srcImage, _, _ := image.Decode(imagePath)
	srcDimensions := srcImage.Bounds()
	// wider than high?
	muchWiderThanHigh := srcDimensions.Dx() > int(float64(srcDimensions.Dy())*1.25)
	return muchWiderThanHigh
}

func (adoc adocReport) writeDataFlowDiagram(diagramFilenamePNG string) error {
	filename := "060_DataFlowDiagram.adoc"
	dfd, err := adoc.createFile(filename)
	defer func() { _ = dfd.Close() }()
	if err != nil {
		return err
	}
	adocDfdFilename := filepath.Join(adoc.imagesDir, "data-flow-diagram.png")
	mustCopyFile(diagramFilenamePNG, adocDfdFilename)

	landScape := imageIsWiderThanHigh(adocDfdFilename)
	if landScape {
		adoc.writeMainLine("[page-layout=landscape]")
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.dataFlowDiagram(dfd, "images/data-flow-diagram.png")
	if landScape {
		adoc.writeMainLine("[page-layout=portrait]")
	}
	return nil
}

func (adoc adocReport) securityRequirements(f *os.File) int {
	writeLine(f, "= Security Requirements")
	writeLine(f, "This chapter lists the custom security requirements which have been defined for the modeled target.")

	writeLine(f, "\n")
	requirements := sortedKeysOfSecurityRequirements(adoc.model)
	for _, title := range requirements {
		description := adoc.model.SecurityRequirements[title]
		writeLine(f, title+"::")
		writeLine(f, "  "+description)
		writeLine(f, "")
	}
	writeLine(f, "\n\n")
	writeLine(f, "_This list is not complete and regulatory or law relevant security requirements have to be "+
		"taken into account as well. Also custom individual security requirements might exist for the project._")
	return len(requirements)
}

func (adoc adocReport) writeSecurityRequirements() error {
	filename := "070_SecurityRequirements.adoc"
	sr, err := adoc.createFile(filename)
	defer func() { _ = sr.Close() }()
	if err != nil {
		return err
	}

	nRequirements := adoc.securityRequirements(sr)
	if nRequirements > 0 || !adoc.hideEmptyChapter {
		adoc.writeMainLine("<<<")
		adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")
	}
	return nil
}

func (adoc adocReport) abuseCases(f *os.File) int {
	writeLine(f, "= Abuse Cases")
	writeLine(f, "This chapter lists the custom abuse cases which have been defined for the modeled target.")
	writeLine(f, "\n")
	cases := sortedKeysOfAbuseCases(adoc.model)
	for _, title := range cases {
		description := adoc.model.AbuseCases[title]
		writeLine(f, title+"::")
		writeLine(f, "  "+description)
		writeLine(f, "")
	}
	writeLine(f, "\n\n")
	writeLine(f, "_This list is not complete and regulatory or law relevant abuse cases have to be "+
		"taken into account as well. Also custom individual abuse cases might exist for the project._")
	return len(cases)
}

func (adoc adocReport) writeAbuseCases() error {
	filename := "080_AbuseCases.adoc"
	ac, err := adoc.createFile(filename)
	defer func() { _ = ac.Close() }()
	if err != nil {
		return err
	}

	nCases := adoc.abuseCases(ac)
	if nCases > 0 || !adoc.hideEmptyChapter {
		adoc.writeMainLine("<<<")
		adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")
	}
	return nil
}

func (adoc adocReport) tagListing(f *os.File) {
	writeLine(f, "= Tag Listing")

	writeLine(f, "This chapter lists what tags are used by which elements.")
	writeLine(f, "\n")
	sorted := adoc.model.TagsAvailable
	sort.Strings(sorted)
	for _, tag := range sorted {
		// could hold a separation text to distinguish technical assets, data assets etc.
		description := taggedTitles(adoc.model, tag)
		if len(description) > 0 {
			writeLine(f, tag+"::")
			writeLine(f, "  "+description)
			writeLine(f, "")
		}
	}
}

func (adoc adocReport) writeTagListing() error {
	filename := "090_TagListing.adoc"
	f, err := adoc.createFile(filename)
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.tagListing(f)
	return nil
}

// The footnotes that the AsciiDoc chapters attach to their clickable paragraphs.
const (
	adocFootnoteRiskFindings = ":fn-risk-findings: footnote:riskfinding[Risk finding paragraphs are clickable " +
		"and link to the corresponding chapter.]"
	adocFootnoteTechAssets = ":fn-tech-assets: footnote:techAssets[Technical asset paragraphs are clickable " +
		"and link to the corresponding chapter.]"
)

func (adoc adocReport) stride(f *os.File) {
	writeLine(f, "= STRIDE Classification of Identified Risks")
	writeLine(f, adocFootnoteRiskFindings)
	writeLine(f, "")

	risksByCategory := adoc.model.GeneratedRisksByCategory
	risksSTRIDESpoofing := reduceToSTRIDERisk(adoc.model, risksByCategory, types.Spoofing)
	risksSTRIDETampering := reduceToSTRIDERisk(adoc.model, risksByCategory, types.Tampering)
	risksSTRIDERepudiation := reduceToSTRIDERisk(adoc.model, risksByCategory, types.Repudiation)
	risksSTRIDEInformationDisclosure := reduceToSTRIDERisk(adoc.model, risksByCategory, types.InformationDisclosure)
	risksSTRIDEDenialOfService := reduceToSTRIDERisk(adoc.model, risksByCategory, types.DenialOfService)
	risksSTRIDEElevationOfPrivilege := reduceToSTRIDERisk(adoc.model, risksByCategory, types.ElevationOfPrivilege)

	countSTRIDESpoofing := countRisks(risksSTRIDESpoofing)
	countSTRIDETampering := countRisks(risksSTRIDETampering)
	countSTRIDERepudiation := countRisks(risksSTRIDERepudiation)
	countSTRIDEInformationDisclosure := countRisks(risksSTRIDEInformationDisclosure)
	countSTRIDEDenialOfService := countRisks(risksSTRIDEDenialOfService)
	countSTRIDEElevationOfPrivilege := countRisks(risksSTRIDEElevationOfPrivilege)

	writeLine(f, "This chapter clusters and classifies the risks by STRIDE categories: "+
		"In total *"+strconv.Itoa(totalRiskCount(adoc.model))+" potential risks* have been identified during the threat "+
		"modeling process "+
		"of which *"+strconv.Itoa(countSTRIDESpoofing)+" in the "+types.Spoofing.Title()+"* category, "+
		"*"+strconv.Itoa(countSTRIDETampering)+" in the "+types.Tampering.Title()+"* category, "+
		"*"+strconv.Itoa(countSTRIDERepudiation)+" in the "+types.Repudiation.Title()+"* category, "+
		"*"+strconv.Itoa(countSTRIDEInformationDisclosure)+" in the "+types.InformationDisclosure.Title()+"* category, "+
		"*"+strconv.Itoa(countSTRIDEDenialOfService)+" in the "+types.DenialOfService.Title()+"* category, "+
		"and *"+strconv.Itoa(countSTRIDEElevationOfPrivilege)+" in the "+types.ElevationOfPrivilege.Title()+"* "+
		"category.{fn-risk-findings}")
	writeLine(f, "")

	reverseRiskSeverity := []types.RiskSeverity{
		types.CriticalSeverity,
		types.HighSeverity,
		types.ElevatedSeverity,
		types.MediumSeverity,
		types.LowSeverity,
	}
	strides := []types.STRIDE{
		types.Spoofing,
		types.Tampering,
		types.Repudiation,
		types.InformationDisclosure,
		types.DenialOfService,
		types.ElevationOfPrivilege,
	}

	for _, strideValue := range strides {
		writeLine(f, "== "+strideValue.Title())
		risksSTRIDE := reduceToSTRIDERisk(adoc.model, adoc.model.GeneratedRisksByCategoryWithCurrentStatus(), strideValue)
		if len(risksSTRIDE) > 0 {
			for _, critValue := range reverseRiskSeverity {
				adoc.addCategories(f, risksSTRIDE, true, critValue, true, true)
			}
		} else {
			writeLine(f, "No risk identified.")
		}
		writeLine(f, "")
	}
}

func (adoc adocReport) writeSTRIDE() error {
	filename := "100_STRIDE.adoc"
	f, err := adoc.createFile(filename)
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.stride(f)
	return nil
}

func (adoc adocReport) assignmentByFunction(f *os.File) {
	writeLine(f, "= Assignment by Function")
	writeLine(f, adocFootnoteRiskFindings)
	writeLine(f, "")

	risksBusinessSideFunction := reduceToFunctionRisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.BusinessSide)
	risksArchitectureFunction := reduceToFunctionRisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.Architecture)
	risksDevelopmentFunction := reduceToFunctionRisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.Development)
	risksOperationFunction := reduceToFunctionRisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.Operations)

	countBusinessSideFunction := countRisks(risksBusinessSideFunction)
	countArchitectureFunction := countRisks(risksArchitectureFunction)
	countDevelopmentFunction := countRisks(risksDevelopmentFunction)
	countOperationFunction := countRisks(risksOperationFunction)
	writeLine(f, "This chapter clusters and assigns the risks by functions which are most likely able to "+
		"check and mitigate them: "+
		"In total *"+strconv.Itoa(totalRiskCount(adoc.model))+" potential risks* have been identified during the threat "+
		"modeling process "+
		"of which *"+strconv.Itoa(countBusinessSideFunction)+" should be checked by "+types.BusinessSide.Title()+"*, "+
		"*"+strconv.Itoa(countArchitectureFunction)+" should be checked by "+types.Architecture.Title()+"*, "+
		"*"+strconv.Itoa(countDevelopmentFunction)+" should be checked by "+types.Development.Title()+"*, "+
		"and *"+strconv.Itoa(countOperationFunction)+" should be checked by "+types.Operations.Title()+"*.{fn-risk-findings}")
	writeLine(f, "")

	riskFunctionValues := []types.RiskFunction{
		types.BusinessSide,
		types.Architecture,
		types.Development,
		types.Operations,
	}
	reverseRiskSeverity := []types.RiskSeverity{
		types.CriticalSeverity,
		types.HighSeverity,
		types.ElevatedSeverity,
		types.MediumSeverity,
		types.LowSeverity,
	}

	for _, riskFunctionValue := range riskFunctionValues {
		writeLine(f, "== "+riskFunctionValue.Title())
		risksFunction := reduceToFunctionRisk(adoc.model, adoc.model.GeneratedRisksByCategoryWithCurrentStatus(),
			riskFunctionValue)
		for _, critValue := range reverseRiskSeverity {
			adoc.addCategories(f, risksFunction, true, critValue, true, false)
		}
		writeLine(f, "")
	}
}

func (adoc adocReport) writeAssignmentByFunction() error {
	filename := "110_AssignmentByFunction.adoc"
	f, err := adoc.createFile(filename)
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.assignmentByFunction(f)
	return nil
}

func (adoc adocReport) raa(f *os.File, introTextRAA string) {
	writeLine(f, "= RAA Analysis")
	writeLine(f, adocFootnoteRiskFindings)
	writeLine(f, "")
	writeLine(f, fixBasicHtml(introTextRAA)+"{fn-risk-findings}")
	writeLine(f, "")

	for _, technicalAsset := range sortedTechnicalAssetsByRAAAndTitle(adoc.model) {
		if technicalAsset.OutOfScope {
			continue
		}
		newRisksStr := adoc.model.GeneratedRisks(technicalAsset)
		colorPrefix := ""
		switch types.HighestSeverityStillAtRisk(newRisksStr) {
		case types.HighSeverity:
			colorPrefix = "[HighRisk]#"
		case types.MediumSeverity:
			colorPrefix = "[MediumRisk]#"
		case types.LowSeverity:
			colorPrefix = "[LowRisk]#"
		default:
			colorPrefix = ""
		}
		if len(types.ReduceToOnlyStillAtRisk(newRisksStr)) == 0 {
			colorPrefix = ""
		}

		fullLine := "<<" + technicalAsset.Id + "," + colorPrefix + "*" + technicalAsset.Title + "*"
		if technicalAsset.OutOfScope {
			fullLine += ": out-of-scope"
		} else {
			fullLine += ": RAA " + fmt.Sprintf("%.0f", technicalAsset.RAA) + "%"
		}
		if len(colorPrefix) > 0 {
			fullLine += "#"
		}
		writeLine(f, fullLine+">>::")
		writeLine(f, "  "+technicalAsset.Description)
		writeLine(f, "")
	}
}

func (adoc adocReport) writeRAA(introTextRAA string) error {
	filename := "120_RAA.adoc"
	f, err := adoc.createFile(filename)
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.raa(f, introTextRAA)
	return nil
}

func (adoc adocReport) dataRiskMapping(f *os.File, diagramFilenamePNG string) {
	writeLine(f, "= Data Mapping")

	writeLine(f, `
The following diagram was generated by Threagile based on the model input and gives a high-level distribution of
data assets across technical assets. The color matches the identified data breach probability and risk level (see
the "Data Breach Probabilities" chapter for more details). A solid line stands for _data is stored by the asset_
and a dashed one means _data is processed by the asset_. For a full high-resolution version of this diagram please
refer to the PNG image file alongside this report.`)
	writeLine(f, "\nimage::"+diagramFilenamePNG+"[]")
}

func (adoc adocReport) writeDataRiskMapping(dataAssetDiagramFilenamePNG string) error {
	filename := "130_DataRiskMapping.adoc"
	f, err := adoc.createFile(filename)
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adocDataRiskMappingFilename := filepath.Join(adoc.imagesDir, "data-asset-diagram.png")
	mustCopyFile(dataAssetDiagramFilenamePNG, adocDataRiskMappingFilename)

	landScape := imageIsWiderThanHigh(adocDataRiskMappingFilename)
	if landScape {
		adoc.writeMainLine("[page-layout=landscape]")
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.dataRiskMapping(f, "images/data-asset-diagram.png")
	if landScape {
		adoc.writeMainLine("[page-layout=portrait]")
	}
	return nil
}

func (adoc adocReport) outOfScopeAssets(f *os.File) {
	assets := textAsset
	count := len(adoc.model.OutOfScopeTechnicalAssets())
	if count > 1 {
		assets += "s"
	}
	writeLine(f, "= Out-of-Scope Assets: "+strconv.Itoa(count)+" "+assets)
	writeLine(f, adocFootnoteTechAssets)
	writeLine(f, "")
	writeLine(f, `
This chapter lists all technical assets that have been defined as out-of-scope.
Each one should be checked in the model whether it should better be included in the overall risk `+
		`analysis{fn-tech-assets}:
`)
	writeLine(f, "")

	outOfScopeAssetCount := 0
	for _, technicalAsset := range sortedTechnicalAssetsByRAAAndTitle(adoc.model) {
		if technicalAsset.OutOfScope {
			JustificationOutOfScope := technicalAsset.JustificationOutOfScope
			if len(JustificationOutOfScope) == 0 {
				JustificationOutOfScope = "Missing out of scope justification."
			}

			outOfScopeAssetCount++
			writeLine(f, "<<"+technicalAsset.Id+",[OutOfScope]#"+technicalAsset.Title+" : out-of-scope#>>::")
			writeLine(f, "  "+JustificationOutOfScope)
			writeLine(f, "")
		}
	}

	if outOfScopeAssetCount == 0 {
		writeLine(f, "[GreyText]#No technical assets have been defined as out-of-scope.#")
	}
}

func (adoc adocReport) writeOutOfScopeAssets() error {
	filename := "140_OutOfScopeAssets.adoc"
	f, err := adoc.createFile(filename)
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.outOfScopeAssets(f)
	return nil
}

func (adoc adocReport) modelFailures(f *os.File) {
	modelFailures := flattenRiskSlice(filterByModelFailures(adoc.model,
		adoc.model.GeneratedRisksByCategoryWithCurrentStatus()))
	count := len(modelFailures)
	countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(modelFailures))
	colorPrefix := ""
	colorSuffix := ""
	if countStillAtRisk > 0 {
		colorPrefix = "[ModelFailure]#"
		colorSuffix = "#"
	}
	suffix := riskSuffix(countStillAtRisk, count)
	writeLine(f, "= "+colorPrefix+"Potential Model Failures: "+suffix+colorSuffix)
	writeLine(f, adocFootnoteRiskFindings)
	writeLine(f, "")

	writeLine(f, `
This chapter lists potential model failures where not all relevant assets have been
modeled or the model might itself contain inconsistencies. Each potential model failure should be checked
in the model against the architecture design:{fn-risk-findings}`)
	writeLine(f, "")

	modelFailuresByCategory := filterByModelFailures(adoc.model, adoc.model.GeneratedRisksByCategoryWithCurrentStatus())
	if len(modelFailuresByCategory) == 0 {
		writeLine(f, "No potential model failures have been identified.")
	} else {
		adoc.addCategories(f, modelFailuresByCategory, true, types.CriticalSeverity, true, true)
		adoc.addCategories(f, modelFailuresByCategory, true, types.HighSeverity, true, true)
		adoc.addCategories(f, modelFailuresByCategory, true, types.ElevatedSeverity, true, true)
		adoc.addCategories(f, modelFailuresByCategory, true, types.MediumSeverity, true, true)
		adoc.addCategories(f, modelFailuresByCategory, true, types.LowSeverity, true, true)
	}
}

func (adoc adocReport) writeModelFailures() error {
	filename := "150_ModelFailures.adoc"
	f, err := adoc.createFile(filename)
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.modelFailures(f)
	return nil
}

func (adoc adocReport) questions(f *os.File) int {
	questionStr := textQuestion
	count := len(adoc.model.Questions)
	if count > 1 {
		questionStr += "s"
	}
	colorPrefix := ""
	colorSuffix := ""
	if questionsUnanswered(adoc.model) > 0 {
		colorPrefix = "[ModelFailure]#"
		colorSuffix = "#"
	}
	writeLine(f, "= "+colorPrefix+"Questions: "+strconv.Itoa(questionsUnanswered(adoc.model))+" / "+strconv.Itoa(count)+
		" "+questionStr+colorSuffix)
	writeLine(f, "")
	writeLine(f, "This chapter lists custom questions that arose during the threat modeling process.")
	writeLine(f, "")

	if len(adoc.model.Questions) == 0 {
		writeLine(f, "")
		writeLine(f, "[GreyText]#No custom questions arose during the threat modeling process.#")
	}
	writeLine(f, "")

	questions := sortedKeysOfQuestions(adoc.model)
	for _, question := range questions {
		answer := adoc.model.Questions[question]
		if len(strings.TrimSpace(answer)) > 0 {
			writeLine(f, "*"+question+"*::")
			writeLine(f, "_"+strings.TrimSpace(answer)+"_")
		} else {
			writeLine(f, "*[ModelFailure]#"+question+"#*::")
			writeLine(f, "[GreyText]#_- answer pending -_#")
		}
		writeLine(f, "")
	}
	return len(questions)
}

func (adoc adocReport) writeQuestions() error {
	filename := "160_Questions.adoc"
	f, err := adoc.createFile(filename)
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}

	nQuestions := adoc.questions(f)
	if nQuestions > 0 || !adoc.hideEmptyChapter {
		adoc.writeMainLine("<<<")
		adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")
	}

	return nil
}

// riskStatusRole returns the theme role that colours a risk tracking status.
func riskStatusRole(status types.RiskStatus) string {
	switch status {
	case types.Unchecked:
		return "RiskStatusUnchecked"
	case types.InDiscussion:
		return "RiskStatusInDiscussion"
	case types.Accepted:
		return "RiskStatusAccepted"
	case types.InProgress:
		return "RiskStatusInProgress"
	case types.Mitigated:
		return "RiskStatusMitigated"
	case types.FalsePositive:
		return "RiskStatusFalsePositive"
	default:
		return ""
	}
}

func (adoc adocReport) riskTrackingStatus(f *os.File, risk *types.Risk) {
	tracking := adoc.model.GetRiskTrackingWithDefault(risk)

	colorName := riskStatusRole(tracking.Status)
	bold := ""
	if tracking.Status == types.Unchecked {
		bold = "*"
	}

	if tracking.Status != types.Unchecked {
		dateStr := tracking.Date.Format("2006-01-02")
		if dateStr == "0001-01-01" {
			dateStr = ""
		}
		justificationStr := tracking.Justification
		ticket := tracking.Ticket
		if len(ticket) == 0 {
			ticket = "-"
		}
		writeLine(f, `
[cols="a,c,c,2c",frame=none,grid=none,options="unbreakable"]
|===
| [.`+colorName+`.small]#`+bold+tracking.Status.Title()+bold+`#
| [.GreyText.small]#`+dateStr+`#
| [.GreyText.small]#`+tracking.CheckedBy+`#
| [.GreyText.small]#`+ticket+`#

4+|[.small]#`+justificationStr+`#
|===
`)
	} else {
		writeLine(f, `
[cols="a,c,c,2c",frame=none,grid=none,options="unbreakable"]
|===
4+| [.`+colorName+`.small]#`+bold+tracking.Status.Title()+bold+`#
|===
`)
	}
}

func (adoc adocReport) riskCategories(f *os.File) {
	writeLine(f, "= Identified Risks by Vulnerability category")
	writeLine(f, "In total *"+strconv.Itoa(totalRiskCount(adoc.model))+" potential risks* have been identified during "+
		"the threat modeling process of which "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.CriticalSeverity)))+" are rated as critical*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.HighSeverity)))+" as high*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.ElevatedSeverity)))+" as elevated*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.MediumSeverity)))+" as medium*, "+
		"and *"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.LowSeverity)))+" as low*. "+
		"\n\nThese risks are distributed across *"+strconv.Itoa(len(adoc.model.GeneratedRisksByCategory))+" vulnerability "+
		"categories*. ")
	// a longer explanation could follow here
	writeLine(f, "The following sub-chapters of this section describe each identified risk category.")
	writeLine(f, "")

	for _, category := range adoc.model.SortedRiskCategories() {
		risksStr := adoc.model.SortedRisksOfCategory(category)

		writeRiskCategoryHeading(f, category, risksStr)
		writeRiskCategoryDetails(f, category)
		adoc.writeRiskCategoryFindings(f, category, risksStr)
	}
}

// writeRiskCategoryHeading writes the heading of a risk category, coloured by the highest severity
// of its risks still at risk.
func writeRiskCategoryHeading(f *os.File, category *types.RiskCategory, risksStr []*types.Risk) {
	// category color
	colorPrefix, colorSuffix := colorPrefixBySeverity(types.HighestSeverityStillAtRisk(risksStr), false)
	if len(types.ReduceToOnlyStillAtRisk(risksStr)) == 0 {
		colorPrefix = ""
		colorSuffix = ""
	}

	// category title
	countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(risksStr))
	suffix := riskSuffix(countStillAtRisk, len(risksStr))
	title := colorPrefix + category.Title + ": " + suffix + colorSuffix
	writeLine(f, "[["+category.ID+"]]")
	writeLine(f, "== "+title)
	writeLine(f, "")
}

// writeRiskCategoryDetails writes the description, impact, detection logic, rating, false
// positives, mitigation and check of a risk category.
func writeRiskCategoryDetails(f *os.File, category *types.RiskCategory) {
	// category details
	cweLink := textNotApplicable
	if category.CWE > 0 {
		cweLink = "https://cwe.mitre.org/data/definitions/" + strconv.Itoa(category.CWE) + ".html[CWE " +
			strconv.Itoa(category.CWE) + "]"
	}
	writeLine(f, "*Description* ("+category.STRIDE.Title()+"): "+cweLink+"::")
	writeLine(f, fixBasicHtml(category.Description))
	writeLine(f, "")
	writeLine(f, "*Impact*::")
	writeLine(f, fixBasicHtml(category.Impact))
	writeLine(f, "")
	writeLine(f, "*Detection Logic*::")
	writeLine(f, fixBasicHtml(category.DetectionLogic))
	writeLine(f, "")
	writeLine(f, "*Risk Rating*::")
	writeLine(f, fixBasicHtml(category.RiskAssessment))
	writeLine(f, "")

	writeLine(f, "[RiskStatusFalsePositive]#*False Positives*#::")
	if len(category.FalsePositives) > 0 {
		writeLine(f, "[RiskStatusFalsePositive]#"+category.FalsePositives+"#")
	}
	writeLine(f, "")

	writeLine(f, "[RiskStatusMitigated]#*Mitigation*# ("+category.Function.Title()+"): "+category.Action+"::")
	writeLine(f, fixBasicHtml(category.Mitigation))
	writeLine(f, "")

	asvsChapter := category.ASVS
	asvsLink := textNotApplicable
	if len(asvsChapter) > 0 {
		asvsLink = "https://owasp.org/www-project-application-security-verification-standard/[" + asvsChapter + "]"
	}

	cheatSheetLink := adocCheatSheetLink(category.CheatSheet)
	writeLine(f, "")
	writeLine(f, "* [RiskStatusMitigated]#ASVS Chapter#: "+asvsLink)
	writeLine(f, "* [RiskStatusMitigated]#Cheat Sheet#: "+cheatSheetLink)
	writeLine(f, "\n\n*Check*\n")
	writeLine(f, category.Check)
}

// adocCheatSheetLink returns the AsciiDoc link to a cheat sheet, named after its file.
func adocCheatSheetLink(cheatSheetLink string) string {
	if len(cheatSheetLink) == 0 {
		cheatSheetLink = textNotApplicable
	} else {
		lastLinkParts := strings.Split(cheatSheetLink, "/")
		linkText := lastLinkParts[len(lastLinkParts)-1]
		if strings.HasSuffix(linkText, ".html") || strings.HasSuffix(linkText, ".htm") {
			extension := filepath.Ext(linkText)
			linkText = linkText[0 : len(linkText)-len(extension)]
		}
		cheatSheetLink = cheatSheetLink + "[" + linkText + "]"
	}
	return cheatSheetLink
}

// writeRiskCategoryFindings writes the risks of a risk category.
func (adoc adocReport) writeRiskCategoryFindings(f *os.File, category *types.RiskCategory, risksStr []*types.Risk) {
	// risk details
	writeLine(f, "")
	writeLine(f, "=== Risk Findings")
	writeLine(f, adocFootnoteRiskFindings)
	times := strconv.Itoa(len(risksStr)) + " time"
	if len(risksStr) > 1 {
		times += "s"
	}
	writeLine(f, "")
	writeLine(f, "The risk *"+category.Title+"* was found *"+times+"* in the analyzed architecture to be "+
		"potentially possible. Each spot should be checked individually by reviewing the implementation whether all "+
		"controls have been applied properly in order to mitigate each risk.{fn-risk-findings}")

	for _, risk := range risksStr {
		colorPrefix, colorSuffix := colorPrefixBySeverity(risk.Severity, false)
		if len(colorPrefix) == 0 {
			colorSuffix = ""
		}

		title := titleOfSeverity(risk.Severity)
		if len(title) > 0 {
			writeLine(f, "")
			writeLine(f, "==== "+colorPrefix+"_"+title+"_"+colorSuffix)
		}

		if !risk.RiskStatus.IsStillAtRisk() {
			colorPrefix = ""
			colorSuffix = ""
		}
		writeLine(f, colorPrefix+fixBasicHtml(risk.Title)+": Exploitation likelihood is _"+
			risk.ExploitationLikelihood.Title()+"_ with _"+risk.ExploitationImpact.Title()+"_ impact."+colorSuffix)
		linkId := mostRelevantLinkId(risk)
		writeLine(f, "")
		writeLine(f, "<<"+linkId+",[SmallGrey]#"+risk.SyntheticId+"#>>")

		adoc.riskTrackingStatus(f, risk)
	}
}

// mostRelevantLinkId returns the id of the shared runtime, trust boundary or technical asset that
// a risk is most relevant for, in this order.
func mostRelevantLinkId(risk *types.Risk) string {
	linkId := ""
	switch {
	case len(risk.MostRelevantSharedRuntimeId) > 0:
		linkId = risk.MostRelevantSharedRuntimeId
	case len(risk.MostRelevantTrustBoundaryId) > 0:
		linkId = risk.MostRelevantTrustBoundaryId
	case len(risk.MostRelevantTechnicalAssetId) > 0:
		linkId = risk.MostRelevantTechnicalAssetId
	}
	return linkId
}

func (adoc adocReport) writeRiskCategories() error {
	filename := "170_RiskCategories.adoc"
	f, err := adoc.createFile(filename)
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.riskCategories(f)
	return nil
}

func joinedOrNoneString(strs []string, noneValue string) string {
	if noneValue == "" {
		noneValue = "[GrayText]#none#"
	}
	sort.Strings(strs)
	singleLine := strings.Join(strs, ", ")
	if len(singleLine) == 0 {
		singleLine = noneValue
	}
	return singleLine
}

func dataAssetListTitleJoinOrNone(assets []*types.DataAsset) string {
	dataAssetTitles := make([]string, 0, len(assets))
	for _, dataAsset := range assets {
		dataAssetTitles = append(dataAssetTitles, dataAsset.Title)
	}
	return joinedOrNoneString(dataAssetTitles, "")
}

func technicalAssetTitleOrNone(links []*types.TechnicalAsset, noneValue string) string {
	titles := make([]string, 0, len(links))
	for _, asset := range links {
		titles = append(titles, asset.Title)
	}
	return joinedOrNoneString(titles, noneValue)
}

func dataFormatTitleJoinOrNone(assets []types.DataFormat, noneValue string) string {
	dataAssetTitles := make([]string, 0, len(assets))
	for _, dataFormat := range assets {
		dataAssetTitles = append(dataAssetTitles, dataFormat.Title())
	}
	return joinedOrNoneString(dataAssetTitles, noneValue)
}

func communicationLinkTitleOrNone(links []*types.CommunicationLink, noneValue string) string {
	titles := make([]string, 0, len(links))
	for _, link := range links {
		titles = append(titles, link.Title)
	}
	return joinedOrNoneString(titles, noneValue)
}

func (adoc adocReport) technicalAssets(f *os.File) {
	writeLine(f, "= Identified Risks by Technical Asset")
	writeLine(f, "In total *"+strconv.Itoa(totalRiskCount(adoc.model))+" potential risks* have been identified during "+
		"the threat modeling process of which "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.CriticalSeverity)))+" are rated as critical*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.HighSeverity)))+" as high*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.ElevatedSeverity)))+" as elevated*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.MediumSeverity)))+" as medium*, "+
		"and *"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.LowSeverity)))+" as low*. "+
		"\n\nThese risks are distributed across *"+strconv.Itoa(len(adoc.model.InScopeTechnicalAssets()))+" in-scope "+
		"technical assets*. ")
	// a longer explanation could follow here
	writeLine(f, "The following sub-chapters of this section describe each identified risk grouped by technical asset. ")
	writeLine(f, "The RAA value of a technical asset is the calculated \"Relative Attacker Attractiveness\" value in "+
		"percent.")

	for _, technicalAsset := range sortedTechnicalAssetsByRiskSeverityAndTitle(adoc.model) {
		risksStr := adoc.model.GeneratedRisks(technicalAsset)
		writeTechnicalAssetHeading(f, technicalAsset, risksStr)
		adoc.writeTechnicalAssetRisks(f, technicalAsset, risksStr)
		adoc.writeTechnicalAssetInformation(f, technicalAsset)

		if len(technicalAsset.CommunicationLinks) > 0 {
			writeLine(f, "=== Outgoing Communication Links: "+strconv.Itoa(len(technicalAsset.CommunicationLinks)))
			for _, outgoingCommLink := range technicalAsset.CommunicationLinksSorted() {
				adoc.writeCommunicationLink(f, outgoingCommLink, "outgoing", "Target", outgoingCommLink.TargetId)
			}
		}

		incomingCommLinks := adoc.model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		if len(incomingCommLinks) > 0 {
			writeLine(f, "=== Incoming Communication Links: "+strconv.Itoa(len(incomingCommLinks)))
			for _, incomingCommLink := range incomingCommLinks {
				adoc.writeCommunicationLink(f, incomingCommLink, "incoming", "Source", incomingCommLink.SourceId)
			}
		}
	}
}

// writeTechnicalAssetHeading writes the heading of a technical asset, coloured by the highest
// severity of its risks still at risk.
func writeTechnicalAssetHeading(f *os.File, technicalAsset *types.TechnicalAsset, risksStr []*types.Risk) {
	countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(risksStr))
	suffix := riskSuffix(countStillAtRisk, len(risksStr))
	colorPrefix, colorSuffix := colorPrefixBySeverity(types.HighestSeverityStillAtRisk(risksStr), false)
	if technicalAsset.OutOfScope {
		colorPrefix = "[OutOfScope]#"
		suffix = textOutOfScope
	} else if len(types.ReduceToOnlyStillAtRisk(risksStr)) == 0 {
		colorPrefix = ""
		colorSuffix = ""
	}

	// asset title
	title := colorPrefix + technicalAsset.Title + ": " + suffix + colorSuffix
	writeLine(f, "[["+technicalAsset.Id+"]]")
	writeLine(f, "== "+title)
}

// writeTechnicalAssetRisks writes the description and the risks of a technical asset.
func (adoc adocReport) writeTechnicalAssetRisks(f *os.File, technicalAsset *types.TechnicalAsset,
	risksStr []*types.Risk,
) {
	// asset description
	writeLine(f, "=== Description")
	writeLine(f, technicalAsset.Description)
	writeLine(f, "")

	// and more metadata of asset in tabular view
	writeLine(f, "=== Identified Risks of Asset")
	if len(risksStr) > 0 {
		writeLine(f, adocFootnoteRiskFindings)
		for _, risk := range risksStr {
			colorPrefix, colorSuffix := colorPrefixBySeverity(types.HighestSeverityStillAtRisk(risksStr), false)
			if !risk.RiskStatus.IsStillAtRisk() {
				colorPrefix = ""
				colorSuffix = ""
			}
			writeLine(f, "\n==== "+colorPrefix+titleOfSeverity(risk.Severity)+colorSuffix+"\n")
			writeLine(f, colorPrefix+fixBasicHtml(risk.Title)+": Exploitation likelihood is _"+
				risk.ExploitationLikelihood.Title()+"_ with _"+risk.ExploitationImpact.Title()+"_ impact."+colorSuffix)
			writeLine(f, "")

			writeLine(f, "<<"+risk.CategoryId+",[SmallGrey]#"+risk.SyntheticId+"#>>")
			adoc.riskTrackingStatus(f, risk)
		}
	} else {
		text := "No risksStr were identified."
		if technicalAsset.OutOfScope {
			text = "Asset was defined as out-of-scope."
		}
		writeLine(f, "[GrayText]#"+text+"#")
	}
}

// writeTechnicalAssetInformation writes the information and the rating of a technical asset.
func (adoc adocReport) writeTechnicalAssetInformation(f *os.File, technicalAsset *types.TechnicalAsset) {
	// ASSET INFORMATION
	writeLine(f, "")
	writeLine(f, "<<<")
	writeLine(f, "")
	writeLine(f, "=== Asset Information")
	textRAA := fmt.Sprintf("%.0f", technicalAsset.RAA) + " %"
	if technicalAsset.OutOfScope {
		textRAA = "[GrayText]#out-of-scope#"
	}

	tagsUsedText := joinedOrNoneString(technicalAsset.Tags, "")
	dataAssetsProcessedText := dataAssetListTitleJoinOrNone(adoc.model.DataAssetsProcessedSorted(technicalAsset))
	dataAssetsStoredText := dataAssetListTitleJoinOrNone(adoc.model.DataAssetsStoredSorted(technicalAsset))
	formatsAcceptedText := dataFormatTitleJoinOrNone(technicalAsset.DataFormatsAcceptedSorted(), "[GrayText]#none of "+
		"the special data formats accepted#")

	writeLine(f, `
[cols="h,1,h,1",frame=none,grid=none]
|===
| ID:             3+| `+technicalAsset.Id+`
| Type:             | `+technicalAsset.Type.String()+`| Usage: | `+technicalAsset.Usage.String()+`
| RAA:              | `+textRAA+`| Size: | `+technicalAsset.Size.String()+`
| Technology:       | `+technicalAsset.Technologies.String()+`| Tags: | `+tagsUsedText+`
| Internet:         | `+strconv.FormatBool(technicalAsset.Internet)+`| Machine: | `+technicalAsset.Machine.String()+`
| Encryption:       | `+technicalAsset.Encryption.String()+`| Multi-Tenant: | `+
		strconv.FormatBool(technicalAsset.MultiTenant)+`
| Redundant:        | `+strconv.FormatBool(technicalAsset.Redundant)+`| Custom-Developed: | `+
		strconv.FormatBool(technicalAsset.CustomDevelopedParts)+`
| Client by Human:  | `+strconv.FormatBool(technicalAsset.UsedAsClientByHuman)+`| Formats Accepted: | `+
		formatsAcceptedText+`
| Data Processed: 3+| `+dataAssetsProcessedText+`
| Data Stored:    3+| `+dataAssetsStoredText+`
|===
`)

	writeLine(f, "=== Asset Rating")
	writeLine(f, `
[cols="h,2",frame=none,grid=none]
|===
| Owner:             | `+technicalAsset.Owner+`
| Confidentiality:   | `+technicalAsset.Confidentiality.String()+`<<ref-confidentiality-values,*>>
| Integrity:         | `+technicalAsset.Integrity.String()+`<<ref-criticality-values,*>>
| Availability:      | `+technicalAsset.Availability.String()+`<<ref-criticality-values,*>>
| CIA-Justification: | `+technicalAsset.JustificationCiaRating)
	if technicalAsset.OutOfScope {
		writeLine(f, "| Asset Out-of-Scope Justification: 2+| "+technicalAsset.JustificationOutOfScope)
	}
	writeLine(f, "|===\n")
}

// writeCommunicationLink writes the details of an outgoing or incoming communication link of a
// technical asset, with the technical asset at its other end.
func (adoc adocReport) writeCommunicationLink(f *os.File, commLink *types.CommunicationLink, direction string,
	peerLabel string, peerId string,
) {
	writeLine(f, "==== "+commLink.Title+" ("+direction+")")
	writeLine(f, fixBasicHtml(commLink.Description))

	tagsUsedText := joinedOrNoneString(commLink.Tags, "")
	dataAssetsSentText := dataAssetListTitleJoinOrNone(adoc.model.DataAssetsSentSorted(commLink))
	dataAssetsReceivedText := dataAssetListTitleJoinOrNone(adoc.model.DataAssetsReceivedSorted(commLink))

	writeLine(f, `
[cols="h,1,h,1",frame=none,grid=none]
|===
| `+peerLabel+`:         | <<`+peerId+`,`+adoc.model.TechnicalAssets[peerId].Title+
		`>>| Protocol:       | `+commLink.Protocol.String()+`
| Encrypted:      | `+strconv.FormatBool(commLink.Protocol.IsEncrypted())+`| Authentication: | `+
		commLink.Authentication.String()+`
| Authorization:  | `+commLink.Authorization.String()+`| Read-Only:      | `+
		strconv.FormatBool(commLink.Readonly)+`
| Usage:          | `+commLink.Usage.String()+`| Tags:           | `+tagsUsedText+`
| VPN:            | `+strconv.FormatBool(commLink.VPN)+`| IP-Filtered:    | `+
		strconv.FormatBool(commLink.IpFiltered)+`
| Data Sent:      | `+dataAssetsSentText+`| Data Received:  | `+dataAssetsReceivedText+`
|===
`)
}

func (adoc adocReport) writeTechnicalAssets() error {
	filename := "180_TechnicalAssets.adoc"
	f, err := adoc.createFile(filename)
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.technicalAssets(f)
	return nil
}

func (adoc adocReport) dataAssets(f *os.File) {
	writeLine(f, "= Identified Data Breach Probabilities by Data Asset")
	writeLine(f, "In total *"+strconv.Itoa(totalRiskCount(adoc.model))+" potential risks* have been identified during "+
		"the threat modeling process of which "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.CriticalSeverity)))+" are rated as critical*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.HighSeverity)))+" as high*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.ElevatedSeverity)))+" as elevated*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.MediumSeverity)))+" as medium*, "+
		"and *"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.LowSeverity)))+" as low*. "+
		"\n\nThese risks are distributed across *"+strconv.Itoa(len(adoc.model.DataAssets))+" data assets*. ")
	// a longer explanation could follow here
	writeLine(f, "The following sub-chapters of this section describe the derived data breach probabilities "+
		"grouped by data asset.")
	writeLine(f, "")
	for _, dataAsset := range sortedDataAssetsByDataBreachProbabilityAndTitle(adoc.model) {
		dataBreachProbability := identifiedDataBreachProbabilityStillAtRisk(adoc.model, dataAsset)
		colorPrefix, colorSuffix := colorPrefixByDataBreachProbability(dataBreachProbability, false)
		if !isDataBreachPotentialStillAtRisk(adoc.model, dataAsset) {
			colorPrefix = ""
			colorSuffix = ""
		}
		risksStr := adoc.model.IdentifiedDataBreachProbabilityRisks(dataAsset)
		countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(risksStr))
		suffix := riskSuffix(countStillAtRisk, len(risksStr))
		writeLine(f, "<<<")
		writeLine(f, "[[dataAsset:"+dataAsset.Id+"]]")
		writeLine(f, "== "+colorPrefix+dataAsset.Title+": "+suffix+colorSuffix)
		writeLine(f, fixBasicHtml(dataAsset.Description)+"\n\n")

		tagsUsedText := joinedOrNoneString(dataAsset.Tags, "")
		processedByText := technicalAssetTitleOrNone(adoc.model.ProcessedByTechnicalAssetsSorted(dataAsset), "")
		storedByText := technicalAssetTitleOrNone(adoc.model.StoredByTechnicalAssetsSorted(dataAsset), "")
		sentViaText := communicationLinkTitleOrNone(adoc.model.SentViaCommLinksSorted(dataAsset), "")
		receivedViaText := communicationLinkTitleOrNone(adoc.model.ReceivedViaCommLinksSorted(dataAsset), "")
		dataBreachRisksStillAtRisk := identifiedDataBreachProbabilityRisksStillAtRisk(adoc.model, dataAsset)
		sortByDataBreachProbability(dataBreachRisksStillAtRisk)
		dataBreachText := "This data asset has no data breach potential."
		if len(dataBreachRisksStillAtRisk) > 0 {
			riskRemainingStr := textRiskLower
			if countStillAtRisk > 1 {
				riskRemainingStr += "s"
			}
			dataBreachText = "This data asset has data breach potential because of " +
				"" + strconv.Itoa(countStillAtRisk) + " remaining " + riskRemainingStr + ":"
		}

		riskText := dataBreachProbability.String()
		if !isDataBreachPotentialStillAtRisk(adoc.model, dataAsset) {
			colorPrefix = ""
			colorSuffix = ""
			riskText = textNone
		}

		writeLine(f, `
[cols="h,1,h,1",frame=none,grid=none]
|===
| ID:                3+| `+dataAsset.Id+`
| Usage:               | `+dataAsset.Usage.String()+`| Quantity:          | `+dataAsset.Quantity.String()+`
| Tags:                | `+tagsUsedText+`| Origin:            | `+dataAsset.Origin+`
| Owner:               | `+dataAsset.Owner+`| Confidentiality:   | `+dataAsset.Confidentiality.String()+
			`<<ref-confidentiality-values,*>>
| Integrity:           | `+dataAsset.Integrity.String()+`<<ref-criticality-values,*>>| Availability:      | `+
			dataAsset.Availability.String()+`<<ref-criticality-values,*>>
| CIA-Justification: 3+| `+dataAsset.JustificationCiaRating+`
| Processed by:      3+| `+processedByText+`
| Stored by:         3+| `+storedByText+`
| Sent via:            | `+sentViaText+`| Received via:        | `+receivedViaText+`
| Data Breach:       3+| `+colorPrefix+riskText+colorSuffix+`
| Data Breach Risks: 3+| `+dataBreachText)

		if len(dataBreachRisksStillAtRisk) > 0 {
			for _, dataBreachRisk := range dataBreachRisksStillAtRisk {
				colorPrefix, colorSuffix := colorPrefixByDataBreachProbability(dataBreachRisk.DataBreachProbability, true)
				if !dataBreachRisk.RiskStatus.IsStillAtRisk() {
					colorPrefix = ""
				}

				txt := dataBreachRisk.DataBreachProbability.Title() + ": " + dataBreachRisk.SyntheticId
				writeLine(f, "|                    2+| <<"+dataBreachRisk.CategoryId+","+colorPrefix+txt+colorSuffix+">>")
			}
		}

		writeLine(f, `
|===
`)
	}
}

func (adoc adocReport) writeDataAssets() error {
	filename := "190_DataAssets.adoc"
	f, err := adoc.createFile(filename)
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.dataAssets(f)
	return nil
}

func (adoc adocReport) trustBoundaries(f *os.File) {
	writeLine(f, "= Trust Boundaries")

	word := textHas
	if len(adoc.model.TrustBoundaries) > 1 {
		word = textHave
	}
	writeLine(f, "In total *"+strconv.Itoa(len(adoc.model.TrustBoundaries))+" trust boundaries* "+word+" been "+
		"modeled during the threat modeling process.")
	writeLine(f, "")
	for _, trustBoundary := range sortedTrustBoundariesByTitle(adoc.model) {
		colorPrefix := "[.Twilight]#"
		colorSuffix := "#"
		if !trustBoundary.Type.IsNetworkBoundary() {
			colorPrefix = "[.LightGreyText]#"
		}
		writeLine(f, "[["+trustBoundary.Id+"]]")
		writeLine(f, "== "+colorPrefix+trustBoundary.Title+colorSuffix)
		writeLine(f, colorPrefix+trustBoundary.Description+colorSuffix)
		writeLine(f, "")

		tagsUsedText := joinedOrNoneString(trustBoundary.Tags, "")
		assetsInsideText := joinedOrNoneString(trustBoundary.TechnicalAssetsInside, "")
		boundariesNestedText := joinedOrNoneString(trustBoundary.TrustBoundariesNested, "")

		writeLine(f, `
[cols="h,1",frame=none,grid=none]
|===
| ID:                | `+trustBoundary.Id+`
| Type:              | `+colorPrefix+trustBoundary.Type.String()+colorSuffix+`
| Tags:              | `+tagsUsedText+`
| Assets inside:     | `+assetsInsideText+`
| Boundaries nested: | `+boundariesNestedText+`
|===
`)
	}
}

func (adoc adocReport) writeTrustBoundaries() error {
	filename := "200_TrustBoundaries.adoc"
	f, err := adoc.createFile(filename)
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.trustBoundaries(f)
	return nil
}

func (adoc adocReport) sharedRuntimes(f *os.File) {
	writeLine(f, "= Shared Runtimes")
	word, runtime := textHas, "runtime"
	if len(adoc.model.SharedRuntimes) > 1 {
		word, runtime = textHave, "runtimes"
	}
	writeLine(f, "In total *"+strconv.Itoa(len(adoc.model.SharedRuntimes))+" shared "+runtime+"* "+word+" been "+
		"modeled during the threat modeling process.")
	writeLine(f, "")
	for _, sharedRuntime := range sortedSharedRuntimesByTitle(adoc.model) {
		writeLine(f, "[["+sharedRuntime.Id+"]]")
		writeLine(f, "== "+sharedRuntime.Title)
		writeLine(f, sharedRuntime.Description)
		writeLine(f, "")

		tagsUsedText := joinedOrNoneString(sharedRuntime.Tags, "")
		assetsRunningText := joinedOrNoneString(sharedRuntime.TechnicalAssetsRunning, "")
		writeLine(f, `
[cols="h,1",frame=none,grid=none]
|===
| ID:             | `+sharedRuntime.Id+`
| Tags:           | `+tagsUsedText+`
| Assets running: | `+assetsRunningText+`
|===
`)
	}
}

func (adoc adocReport) writeSharedRuntimes() error {
	filename := "210_SharedRuntimes.adoc"
	f, err := adoc.createFile(filename)
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.sharedRuntimes(f)
	return nil
}

func (adoc adocReport) riskRulesChecked(f *os.File, modelFilename string, skipRiskRules []string, buildTimestamp string, threagileVersion string, modelHash string, customRiskRules types.RiskRules) {
	writeLine(f, "= Risk Rules Checked by Threagile")
	writeLine(f, "")
	timestamp := types.Now()
	writeLine(f, `
[cols="h,1",frame=none,grid=none]
|===
| Threagile Version:             | `+threagileVersion+`
| Threagile Build Timestamp:     | `+buildTimestamp+`
| Threagile Execution Timestamp: | `+timestamp.Format("20060102150405")+`
| Model Filename:                | `+modelFilename+`
| Model Hash (SHA256):           | `+modelHash+`
|===
`)
	writeLine(f, "\n\n")
	writeLine(f, "Threagile (see https://threagile.io[] for more details) is an open-source toolkit for agile threat "+
		"modeling, created by Christian Schneider (https://christian-schneider.net[]): It allows to model an architecture "+
		"with its assets in an agile fashion as a YAML file directly inside the IDE. Upon execution of the Threagile "+
		"toolkit all standard risk rules (as well as individual custom rules if present) are checked against the "+
		"architecture model. At the time the Threagile toolkit was executed on the model input file "+
		"the following risk rules were checked:")
	writeLine(f, "")

	// The risk rules are listed explicitly here rather than discovered through the run system:
	skipped := ""

	for _, id := range slices.Sorted(maps.Keys(customRiskRules)) {
		customRule := customRiskRules[id]
		if contains(skipRiskRules, id) {
			skipped = textSkipped
		} else {
			skipped = ""
		}
		writeLine(f, "== "+skipped+customRule.Category().Title)
		writeLine(f, "[.small]#"+id+"#")
		writeLine(f, "")
		writeLine(f, "_Custom Risk Rule_")
		writeLine(f, `
[cols="h,1",frame=none,grid=none]
|===
| STRIDE:      | `+customRule.Category().STRIDE.Title()+`
| Description: | `+firstParagraph(customRule.Category().Description)+`
| Detection:   | `+customRule.Category().DetectionLogic+`
| Rating:      | `+customRule.Category().RiskAssessment+`
|===
`)
	}

	sort.Sort(types.ByRiskCategoryTitleSort(adoc.model.CustomRiskCategories))
	for _, individualRiskCategory := range adoc.model.CustomRiskCategories {
		writeLine(f, "== "+individualRiskCategory.Title)
		writeLine(f, "[.small]#"+individualRiskCategory.ID+"#")
		writeLine(f, "")
		writeLine(f, "_Individual Risk category_")
		writeLine(f, `
[cols="h,1",frame=none,grid=none]
|===
| STRIDE:      | `+individualRiskCategory.STRIDE.Title()+`
| Description: | `+firstParagraph(individualRiskCategory.Description)+`
| Detection:   | `+individualRiskCategory.DetectionLogic+`
| Rating:      | `+individualRiskCategory.RiskAssessment+`
|===
`)
	}

	for _, id := range slices.Sorted(maps.Keys(adoc.riskRules)) {
		rule := adoc.riskRules[id]
		if contains(skipRiskRules, rule.Category().ID) {
			skipped = textSkipped
		} else {
			skipped = ""
		}
		writeLine(f, "== "+skipped+rule.Category().Title)
		writeLine(f, "[.small]#"+rule.Category().ID+"#")
		writeLine(f, "")
		writeLine(f, `
[cols="h,1",frame=none,grid=none]
|===
| STRIDE:      | `+rule.Category().STRIDE.Title()+`
| Description: | `+firstParagraph(rule.Category().Description)+`
| Detection:   | `+rule.Category().DetectionLogic+`
| Rating:      | `+rule.Category().RiskAssessment+`
|===
`)
	}
}

func (adoc adocReport) writeRiskRulesChecked(modelFilename string, skipRiskRules []string, buildTimestamp string,
	threagileVersion string, modelHash string, customRiskRules types.RiskRules,
) error {
	filename := "220_RiskRulesChecked.adoc"
	f, err := adoc.createFile(filename)
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.riskRulesChecked(f, modelFilename, skipRiskRules, buildTimestamp, threagileVersion, modelHash, customRiskRules)
	return nil
}

func (adoc adocReport) appendixRating(f *os.File) {
	writeLine(f, "[appendix]")
	writeLine(f, "= Ratings")

	confValues := map[types.Confidentiality]string{
		types.Public:               "1",
		types.Internal:             "2",
		types.Restricted:           "3",
		types.Confidential:         "4",
		types.StrictlyConfidential: "5",
	}

	critValues := map[types.Criticality]string{
		types.Archive:         "1",
		types.Operational:     "2",
		types.Important:       "3",
		types.Critical:        "4",
		types.MissionCritical: "5",
	}

	writeLine(f, "")
	writeLine(f, "[[ref-confidentiality-values]]")
	writeLine(f, ".Confidentiality Values")
	writeLine(f, "[%header,cols=\"3,1,8\"]")
	writeLine(f, "|===")
	writeLine(f, "| Name | Value | Description")
	writeLine(f, "")
	for _, key := range slices.Sorted(maps.Keys(confValues)) {
		writeLine(f, "| "+key.String()+" | "+confValues[key]+" | "+key.Explain())
	}
	writeLine(f, "|===")
	writeLine(f, "")

	writeLine(f, "[[ref-criticality-values]]")
	writeLine(f, ".Criticality Values")
	writeLine(f, "[%header,cols=\"3,1,8\"]")
	writeLine(f, "|===")
	writeLine(f, "| Name | Value | Description")
	writeLine(f, "")
	for _, key := range slices.Sorted(maps.Keys(critValues)) {
		writeLine(f, "| "+key.String()+" | "+critValues[key]+" | "+key.Explain())
	}
	writeLine(f, "|===")
}

func (adoc adocReport) writeAppendixRating() error {
	filename := "400_AppendixRating.adoc"
	f, err := adoc.createFile(filename)
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.appendixRating(f)
	return nil
}

func (adoc adocReport) disclaimer(f *os.File) {
	writeLine(f, "[appendix]")
	writeLine(f, "= Disclaimer")

	disclaimerColor := "\n[.Silver]\n"

	writeLine(f, disclaimerColor+
		adoc.model.Author.Name+" conducted this threat analysis using the open-source Threagile toolkit "+
		"on the applications and systems that were modeled as of this report's date. Information security threats are "+
		"continually changing, with new vulnerabilities discovered on a daily basis, and no application can ever be 100% "+
		"secure no matter how much threat modeling is conducted. It is recommended to execute threat modeling and also "+
		"penetration testing on a regular basis (for example yearly) to ensure a high ongoing level of security and "+
		"constantly check for new attack vectors. "+
		"\n\n"+
		disclaimerColor+
		"This report cannot and does not protect against personal or business loss as the result of use of the "+
		"applications or systems described. "+adoc.model.Author.Name+" and the Threagile toolkit offers no warranties, "+
		"representations or legal certifications concerning the applications or systems it tests. All software includes "+
		"defects: nothing in this document is intended to represent or warrant that threat modeling was complete and "+
		"without error, nor does this document represent or warrant that the architecture analyzed is suitable to task, "+
		"free of other defects than reported, fully compliant with any industry standards, or fully compatible with any "+
		"operating system, hardware, or other application. Threat modeling tries to analyze the modeled architecture "+
		"without having access to a real working system and thus cannot and does not test the implementation for defects "+
		"and vulnerabilities. These kinds of checks would only be possible with a separate code review and penetration test "+
		"against a working system and not via a threat model."+
		"\n\n"+
		disclaimerColor+
		"By using the resulting information you agree that "+adoc.model.Author.Name+" and the Threagile toolkit "+
		"shall be held harmless in any event."+
		"\n\n"+
		disclaimerColor+
		"This report is confidential and intended for internal, confidential use by the client. The recipient "+
		"is obligated to ensure the highly confidential contents are kept secret. The recipient assumes responsibility "+
		"for further distribution of this document."+
		"\n\n"+
		disclaimerColor+
		"In this particular project, a time box approach was used to define the analysis effort. This means that the author "+
		"allotted a prearranged amount of time to identify and document threats. Because of this, there is no guarantee "+
		"that all possible threats and risks are discovered. Furthermore, the analysis applies to a snapshot of the current "+
		"state of the modeled architecture (based on the architecture information provided by the customer) at the "+
		"examination time."+
		"\n\n"+
		"== Report Distribution"+
		disclaimerColor+
		"Distribution of this report (in full or in part like diagrams or risk findings) requires that this disclaimer "+
		"as well as the chapter about the Threagile toolkit and method used is kept intact as part of the "+
		"distributed report or referenced from the distributed parts.")
}

func (adoc adocReport) writeDisclaimer() error {
	filename := "500_Disclaimer.adoc"
	f, err := adoc.createFile(filename)
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.disclaimer(f)
	return nil
}
