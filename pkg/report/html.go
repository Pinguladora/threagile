package report

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"

	"github.com/Pinguladora/threagile/pkg/types"
)

// HTMLReportOptions are the inputs of the HTML report besides the model.
type HTMLReportOptions struct {
	ModelFilename    string
	ModelHash        string
	BuildTimestamp   string
	ThreagileVersion string
	IntroTextRAA     string
	SkipRiskRules    []string
	RiskRules        types.RiskRules
	CustomRiskRules  types.RiskRules
	HideChapters     map[ChaptersToShowHide]bool
	// HideEmptyChapters leaves out the chapter of the remaining risks when there are none, as
	// the AsciiDoc report does; the optional chapters of the model are left out when empty anyway.
	HideEmptyChapters bool
	// DataFlowDiagramDOT and DataAssetDiagramDOT are the Graphviz sources of the diagrams, the
	// same as for the PNG images. A diagram without a source is left out.
	DataFlowDiagramDOT  []byte
	DataAssetDiagramDOT []byte
}

var (
	//go:embed templates/report.html.tmpl
	htmlReportTemplateFiles embed.FS

	//go:embed templates/report.css
	htmlReportCSS string

	htmlReportTemplate = template.Must(template.New("report.html.tmpl").
				Funcs(template.FuncMap{"markup": basicMarkup, "yesNo": yesNo}).
				ParseFS(htmlReportTemplateFiles, "templates/report.html.tmpl"))
)

// WriteReportHTML writes the report as a single HTML page that needs nothing else: the styles and
// the diagrams (as SVG) are inline, and the page loads nothing, which its content security
// policy enforces.
func WriteReportHTML(parsedModel *types.Model, filename string, options HTMLReportOptions,
	progressReporter progressReporter,
) error {
	page, err := renderReportHTML(parsedModel, options, progressReporter)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Clean(filename), page, 0o600); err != nil {
		return fmt.Errorf("failed to write the HTML report: %w", err)
	}
	return nil
}

func renderReportHTML(parsedModel *types.Model, options HTMLReportOptions,
	progressReporter progressReporter,
) ([]byte, error) {
	report := newHTMLReport(parsedModel, options)
	report.DataFlowDiagram = htmlDiagram(options.DataFlowDiagramDOT, "Data-flow diagram", progressReporter)
	report.DataAssetDiagram = htmlDiagram(options.DataAssetDiagramDOT, "Data mapping diagram", progressReporter)

	var page bytes.Buffer
	if err := htmlReportTemplate.Execute(&page, report); err != nil {
		return nil, fmt.Errorf("failed to render the HTML report: %w", err)
	}
	return page.Bytes(), nil
}

// htmlDiagram renders a diagram for inlining; one that fails to render is left out with a warning.
func htmlDiagram(dot []byte, label string, progressReporter progressReporter) template.HTML {
	if len(dot) == 0 {
		return ""
	}
	svg, err := renderDiagramSVG(dot)
	if err == nil {
		var inlined string
		if inlined, err = inlineSVG(svg, label); err == nil {
			return template.HTML(inlined) // #nosec G203 -- inlineSVG writes the SVG anew, all escaped
		}
	}
	progressReporter.Warn(fmt.Sprintf("leaving the %s out of the HTML report: %v", strings.ToLower(label), err))
	return ""
}

// htmlContentSecurityPolicy allows the page its own style sheet and nothing else: no scripts, no
// requests of any kind, no forms.
func htmlContentSecurityPolicy(css string) string {
	hash := sha256.Sum256([]byte(css))
	return "default-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(hash[:]) +
		"'; base-uri 'none'; form-action 'none'"
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
