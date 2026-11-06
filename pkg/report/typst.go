package report

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Pinguladora/threagile/pkg/types"
)

//go:embed templates/report.typ
var typstTemplate []byte

// The bold and oblique DejaVu Sans 2.37 that the PDF report uses besides the regular one of the diagrams, with the
// same license (see fonts/DejaVuSans-LICENSE).
var (
	//go:embed fonts/DejaVuSans-Bold.ttf
	typstFontBold []byte
	//go:embed fonts/DejaVuSans-Oblique.ttf
	typstFontOblique []byte
)

// typstPDFStandards are the standards that typst checks the PDF report against: PDF/A-3a for archiving and
// PDF/UA-1 for accessibility.
const typstPDFStandards = "a-3a,ua-1"

// ErrTypstMissing is returned when the typst command, which renders the PDF report, is not installed.
var ErrTypstMissing = errors.New("the PDF report needs typst (https://typst.app) on the PATH")

// PDFReportOptions are the inputs of the PDF report besides the model.
type PDFReportOptions struct {
	ReportOptions
	// DataFlowDiagramDOT and DataAssetDiagramDOT are the Graphviz sources of the diagrams, which the report shows as
	// SVG; without them, it leaves the diagrams out.
	DataFlowDiagramDOT  []byte
	DataAssetDiagramDOT []byte
	// Logo is an image for the title page, nil for none, and LogoExtension the extension of its format, like ".png".
	Logo          []byte
	LogoExtension string
	// TempFolder is where the sources of the report go while typst renders it.
	TempFolder string
}

// WriteReportPDF writes the report as PDF/A-3a and PDF/UA-1, rendered by typst from the chapters of the Markdown
// report. It returns ErrTypstMissing, before writing anything, when typst is not installed.
func WriteReportPDF(parsedModel *types.Model, filename string, options PDFReportOptions,
	progressReporter progressReporter,
) error {
	typst, err := exec.LookPath("typst")
	if err != nil {
		return ErrTypstMissing
	}
	dir, err := os.MkdirTemp(options.TempFolder, "report-pdf-")
	if err != nil {
		return fmt.Errorf("error creating a folder for the PDF report sources: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	if err := writeTypstSources(dir, parsedModel, options, progressReporter); err != nil {
		return err
	}
	output, err := filepath.Abs(filename)
	if err != nil {
		return fmt.Errorf("error resolving the PDF report file name: %w", err)
	}
	// #nosec G204 -- the arguments are file names of this run and constants, not shell input
	command := exec.CommandContext(context.Background(), typst, "compile",
		"--root", dir, "--font-path", dir, "--ignore-system-fonts",
		"--pdf-standard", typstPDFStandards, "--creation-timestamp", strconv.FormatInt(types.Now().Unix(), 10),
		filepath.Join(dir, "report.typ"), output)
	var messages bytes.Buffer
	command.Stdout, command.Stderr = &messages, &messages
	if err := command.Run(); err != nil {
		return fmt.Errorf("typst failed to render the PDF report: %w\n%s", err, messages.String())
	}
	return nil
}

// writeTypstSources writes into the folder what typst renders the report from: the template, its data, the font and
// the diagrams.
func writeTypstSources(dir string, parsedModel *types.Model, options PDFReportOptions,
	progressReporter progressReporter,
) error {
	view := newReportView(parsedModel, options.ReportOptions)
	diagrams := make([]typstDiagram, 0, 2)
	files := map[string][]byte{
		"report.typ": typstTemplate, "DejaVuSans.ttf": diagramFontTTF,
		"DejaVuSans-Bold.ttf": typstFontBold, "DejaVuSans-Oblique.ttf": typstFontOblique,
	}
	for _, diagram := range []struct {
		file, alt string
		dot       []byte
	}{
		{"data-flow-diagram.svg", "Data-flow diagram", options.DataFlowDiagramDOT},
		{"data-asset-diagram.svg", "Data asset diagram", options.DataAssetDiagramDOT},
	} {
		if len(diagram.dot) == 0 {
			continue
		}
		svg, err := typstDiagramSVG(diagram.dot, diagram.alt)
		if err != nil {
			progressReporter.Warn(fmt.Sprintf("The PDF report leaves out the %s: %v", diagram.alt, err))
			continue
		}
		files[diagram.file] = svg
		diagrams = append(diagrams, typstDiagram{File: diagram.file, Alt: diagram.alt})
	}

	document := typstDocument{
		Title:    view.Title,
		Subtitle: "Threat Model Report",
		Author:   view.Author.Name,
		Date:     view.Date,
		Version:  view.Run.ThreagileVersion,
		Colors:   typstColors(),
		Blocks:   newTypstDocument(renderReportMarkdownView(view), diagrams),
	}
	for _, contributor := range view.Contributors {
		document.Contributors = append(document.Contributors, contributor.Name)
	}
	if len(options.Logo) > 0 {
		document.Logo = "logo" + options.LogoExtension
		files[document.Logo] = options.Logo
	}
	data, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("error writing the PDF report data: %w", err)
	}
	files["data.json"] = data

	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			return fmt.Errorf("error writing the PDF report source %s: %w", name, err)
		}
	}
	return nil
}

// svgRootWidth matches the width attribute of the root element of a diagram.
var svgRootWidth = regexp.MustCompile(` width="[^"]*"`)

// typstDiagramSVG renders the diagram as the HTML report shows it, scaled to fit and with nothing but what Graphviz
// draws with, as a file of its own in the font that the report embeds.
func typstDiagramSVG(dot []byte, label string) ([]byte, error) {
	svg, err := renderDiagramSVG(dot)
	if err != nil {
		return nil, err
	}
	inline, err := inlineSVG(svg, label)
	if err != nil {
		return nil, err
	}
	// the root gets the namespace of a file of its own, and loses its width in points, which typst would draw the
	// diagram smaller than the space it takes for: the viewBox sizes it
	rootEnd := strings.IndexByte(inline, '>')
	if rootEnd < 0 {
		return nil, errors.New("error reading the diagram: no svg element")
	}
	root := svgRootWidth.ReplaceAllString(inline[:rootEnd], "")
	if !strings.Contains(root, "xmlns=") {
		root = strings.Replace(root, "<svg", `<svg xmlns="`+svgNamespace+`"`, 1)
	}
	inline = root + inline[rootEnd:]
	return []byte(strings.ReplaceAll(inline, `font-family="Verdana"`, `font-family="DejaVu Sans"`)), nil
}

// typstColors are the colours of the text of the PDF report besides black: of the severities and statuses that the
// tables show, of the links and of the muted text of the page headers. Each is darkened as far as needed for the
// contrast that WCAG 2.2 asks at level AAA on the white page; the words name the level, so the colour only adds to
// them.
func typstColors() map[string]string {
	colors := map[string]string{"link": rgbHexColorTwilight(), "muted": "#5A5A5A"}
	for _, severity := range viewSeverities {
		colors[severityLevel(severity).Title] = riskSeverityColor(severity)
	}
	for _, status := range viewStatuses {
		colors[statusLevel(status).Title] = riskStatusColor(status)
	}
	for name, color := range colors {
		colors[name] = darkenedForContrast(color, "#FFFFFF", contrastAAA)
	}
	return colors
}
