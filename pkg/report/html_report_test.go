package report_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pinguladora/threagile/internal/threagile"
	"github.com/Pinguladora/threagile/pkg/model"
	"github.com/Pinguladora/threagile/pkg/report"
	"github.com/Pinguladora/threagile/pkg/risks"
	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
)

// hostile is model text that tries to break out of every context the report puts text in: an
// element, an attribute, a link, the style sheet and the threagile markup.
const hostile = `<script>alert("x")</script>"><img src=x onerror=alert(1)></style><script>alert(2)</script>` +
	` <a href="javascript:alert(3)">link</a><b onclick="alert(4)">bold</b><B>upper</B></title><svg onload=alert(5)>'`

const hostileModel = `
threagile_version: 1.0.0
title: TITLE
date: 2024-01-01
author:
  name: NAME
  contact: CONTACT
  homepage: "javascript:alert(6)"
contributors:
  - name: NAME
    contact: CONTACT
    homepage: HOMEPAGE
management_summary_comment: TEXT
business_criticality: important
business_overview:
  description: TEXT
technical_overview:
  description: TEXT
questions:
  QUESTION: TEXT
  QUESTION2: ""
abuse_cases:
  QUESTION: TEXT
security_requirements:
  QUESTION: TEXT
tags_available:
  - TAG
data_assets:
  TITLE1:
    id: customer-data
    description: TEXT
    usage: business
    origin: TEXT
    owner: TEXT
    quantity: few
    tags:
      - TAG
    confidentiality: confidential
    integrity: important
    availability: operational
    justification_cia_rating: TEXT
technical_assets:
  TITLE2:
    id: customer-service
    description: TEXT
    type: process
    usage: business
    used_as_client_by_human: false
    out_of_scope: false
    size: service
    technology: web-service-rest
    internet: true
    machine: container
    encryption: none
    owner: TEXT
    confidentiality: confidential
    integrity: important
    availability: operational
    justification_cia_rating: TEXT
    multi_tenant: false
    redundant: false
    custom_developed_parts: true
    tags:
      - TAG
    data_assets_processed:
      - customer-data
    data_assets_stored:
      - customer-data
    data_formats_accepted:
      - json
    communication_links:
      LINK:
        target: customer-database
        description: TEXT
        protocol: http
        authentication: none
        authorization: none
        tags:
          - TAG
        usage: business
        data_assets_sent:
          - customer-data
  TITLE3:
    id: customer-database
    description: TEXT
    type: datastore
    usage: business
    size: component
    technology: database
    machine: virtual
    encryption: none
    owner: TEXT
    confidentiality: confidential
    integrity: important
    availability: operational
    justification_cia_rating: TEXT
    data_assets_stored:
      - customer-data
  TITLE4:
    id: legacy-system
    description: TEXT
    type: process
    usage: business
    out_of_scope: true
    justification_out_of_scope: TEXT
    size: system
    technology: web-server
    machine: virtual
    encryption: none
    confidentiality: internal
    integrity: operational
    availability: operational
trust_boundaries:
  TITLE5:
    id: boundary
    description: TEXT
    type: network-cloud-security-group
    tags:
      - TAG
    technical_assets_inside:
      - customer-service
      - customer-database
shared_runtimes:
  TITLE6:
    id: runtime
    description: TEXT
    tags:
      - TAG
    technical_assets_running:
      - customer-service
custom_risk_categories:
  - id: hostile-category
    title: TITLE
    description: TEXT
    impact: TEXT
    asvs: TEXT
    cheat_sheet: "javascript:alert(7)"
    action: TEXT
    mitigation: TEXT
    check: TEXT
    function: business-side
    stride: repudiation
    detection_logic: TEXT
    risk_assessment: TEXT
    false_positives: TEXT
    cwe: 693
    risks_identified:
      TITLE:
        severity: critical
        exploitation_likelihood: likely
        exploitation_impact: medium
        data_breach_probability: probable
        data_breach_technical_assets:
          - customer-service
        most_relevant_technical_asset: customer-service
`

// TestHTMLReportOfAHostileModelIsInert puts hostile text into every text of a model that the
// report shows, including ids, which the model checks but other sources might not, and parses
// the report the way a browser does: nothing in it may run, load or link anywhere but http(s).
func TestHTMLReportOfAHostileModelIsInert(t *testing.T) {
	parsedModel, options := analyzeHostileModel(t)
	reporter := testReporter{t}
	outputDir := t.TempDir()

	htmlOptions := report.HTMLReportOptions{ReportOptions: options}
	htmlOptions.DataFlowDiagramDOT = writeDOT(t, func(filename string) (*os.File, error) {
		return report.WriteDataFlowDiagramGraphvizDOT(parsedModel, filename, 96, true, true, reporter)
	})
	htmlOptions.DataAssetDiagramDOT = writeDOT(t, func(filename string) (*os.File, error) {
		return report.WriteDataAssetDiagramGraphvizDOT(parsedModel, filename, 96, reporter)
	})
	filename := filepath.Join(outputDir, "report.html")
	require.NoError(t, report.WriteReportHTML(parsedModel, filename, htmlOptions, reporter))
	page, err := os.ReadFile(filepath.Clean(filename))
	require.NoError(t, err)

	document, err := html.Parse(bytes.NewReader(page))
	require.NoError(t, err)
	ids, links, styles, texts := make(map[string]bool), make([]string, 0), make([]string, 0), new(strings.Builder)
	policy, diagrams := "", 0
	for node := range document.Descendants() {
		switch node.Type {
		case html.TextNode:
			texts.WriteString(node.Data)
		case html.ElementNode:
			assertInertElement(t, node)
			for _, attribute := range node.Attr {
				switch attribute.Key {
				case "id":
					ids[attribute.Val] = true
				case "href":
					links = append(links, attribute.Val)
				}
			}
			if node.Data == "style" {
				styles = append(styles, node.FirstChild.Data)
			}
			if node.Data == "svg" && attributeOf(node, "role") == "img" {
				diagrams++
			}
			if node.Data == "meta" && attributeOf(node, "http-equiv") == "Content-Security-Policy" {
				policy = attributeOf(node, "content")
			}
		default:
		}
	}

	// hostile titles are escaped in the DOT source, so both diagrams render rather than being left out
	assert.Equal(t, 2, diagrams, "the data-flow and data-asset diagrams")

	// the only style sheet is the report's own, which the content security policy allows by its hash
	require.Len(t, styles, 1)
	hash := sha256.Sum256([]byte(styles[0]))
	assert.Equal(t, "default-src 'none'; style-src 'sha256-"+base64.StdEncoding.EncodeToString(hash[:])+"'; "+
		"base-uri 'none'; form-action 'none'", policy)

	for _, link := range links {
		if anchor, isAnchor := strings.CutPrefix(link, "#"); isAnchor {
			assert.True(t, ids[anchor], "link to the missing anchor %q", link)
			continue
		}
		parsed, parseErr := url.Parse(link)
		if assert.NoError(t, parseErr, link) {
			assert.Contains(t, []string{"http", "https"}, parsed.Scheme, "link %q", link)
		}
	}

	// the hostile text is shown, as text
	assert.Contains(t, texts.String(), `<script>alert("x")</script>"><img src=x onerror=alert(1)></style>`)
	assert.Contains(t, texts.String(), `<B>upper</B></title><svg onload=alert(5)>'`)
	assert.Contains(t, texts.String(), `x"><script>alert(8)</script>`, "the hostile id")
	assert.Contains(t, texts.String(), "Contributors")
}

// assertInertElement fails for elements and attributes that run, load or style anything.
func assertInertElement(t *testing.T, node *html.Node) {
	t.Helper()
	switch node.Data {
	case "script", "iframe", "object", "embed", "img", "image", "link", "base", "form", "input", "textarea",
		"foreignObject", "foreignobject", "use", "animate", "set", "audio", "video", "source":
		t.Errorf("element <%s> in the report", node.Data)
	case "meta":
		name := attributeOf(node, "name") + attributeOf(node, "http-equiv") + attributeOf(node, "charset")
		assert.Contains(t, []string{"utf-8", "viewport", "Content-Security-Policy", "referrer"}, name)
	case "style":
		assert.Equal(t, "head", node.Parent.Data, "a style element outside the head")
	}
	for _, attribute := range node.Attr {
		key := strings.ToLower(attribute.Key)
		assert.False(t, strings.HasPrefix(key, "on"), "event handler %s=%q on <%s>", key, attribute.Val, node.Data)
		assert.NotEqual(t, "style", key, "style attribute on <%s>", node.Data)
		assert.NotContains(t, strings.ToLower(attribute.Val), "javascript:", "%s on <%s>", key, node.Data)
		assert.NotContains(t, attribute.Val, "url(", "%s on <%s>", key, node.Data)
	}
}

func attributeOf(node *html.Node, key string) string {
	for _, attribute := range node.Attr {
		if attribute.Key == key {
			return attribute.Val
		}
	}
	return ""
}

func analyzeHostileModel(t *testing.T) (*types.Model, report.ReportOptions) {
	t.Helper()
	quote := func(text string) string {
		quoted, err := json.Marshal(text) // a JSON string is a YAML string as well
		require.NoError(t, err)
		return string(quoted)
	}
	replacements := make([]string, 0, 14)
	for _, key := range []string{"TITLE1", "TITLE2", "TITLE3", "TITLE4", "TITLE5", "TITLE6", "QUESTION2"} {
		replacements = append(replacements, key, quote(key+" "+hostile)) // before the keys they start with
	}
	yaml := strings.NewReplacer(append(replacements,
		"TITLE", quote("Title "+hostile), "NAME", quote("Name "+hostile), "CONTACT", quote("Contact "+hostile),
		"HOMEPAGE", quote("https://example.com/\"><script>alert(9)</script>"), "TEXT", quote("Text "+hostile),
		"QUESTION", quote("Question "+hostile), "TAG", quote("tag "+hostile), "LINK", quote("Link "+hostile),
	)...).Replace(hostileModel)
	modelFile := filepath.Join(t.TempDir(), "threagile.yaml")
	require.NoError(t, os.WriteFile(modelFile, []byte(yaml), 0o600))

	config := new(threagile.Config).Defaults("")
	config.SetAppFolder(t.TempDir())
	config.SetPluginFolder(t.TempDir())
	config.SetInputFile(modelFile)
	config.SetOutputFolder(t.TempDir())
	config.SetTempFolder(t.TempDir())
	result, err := model.ReadAndAnalyzeModel(config, risks.GetBuiltInRiskRules(), testReporter{t})
	require.NoError(t, err)
	parsedModel := result.ParsedModel

	// an id the model would reject, on an asset and a tracked risk
	hostileID := `x"><script>alert(8)</script>`
	parsedModel.TechnicalAssets[hostileID] = &types.TechnicalAsset{Id: hostileID, Title: "Title " + hostile}
	risk := parsedModel.GeneratedRisksByCategory["hostile-category"][0]
	risk.SyntheticId, risk.MostRelevantTechnicalAssetId = hostileID, hostileID
	if parsedModel.RiskTracking == nil {
		parsedModel.RiskTracking = make(map[string]*types.RiskTracking)
	}
	parsedModel.RiskTracking[hostileID] = &types.RiskTracking{
		SyntheticRiskId: hostileID, Status: types.Accepted, Justification: "Justification " + hostile,
		Ticket: "Ticket " + hostile, CheckedBy: "Checker " + hostile,
	}

	return parsedModel, report.ReportOptions{
		ModelFilename:    "Model " + hostile,
		ModelHash:        "Hash " + hostile,
		BuildTimestamp:   "Build " + hostile,
		ThreagileVersion: "Version " + hostile,
		IntroTextRAA:     result.IntroTextRAA,
		RiskRules:        risks.GetBuiltInRiskRules(),
		CustomRiskRules:  result.CustomRiskRules,
	}
}

func writeDOT(t *testing.T, write func(filename string) (*os.File, error)) []byte {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "diagram.gv")
	_, err := write(filename)
	require.NoError(t, err)
	return readFile(t, filename)
}
