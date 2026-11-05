package otm_test

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Pinguladora/threagile/internal/threagile"
	"github.com/Pinguladora/threagile/pkg/interchange"
	"github.com/Pinguladora/threagile/pkg/model"
	"github.com/Pinguladora/threagile/pkg/otm"
	"github.com/Pinguladora/threagile/pkg/risks"
	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const exampleModelFile = "../../demo/example/threagile.yaml"

// TestRoundTrip takes the example model through OTM and back: analyze it, write it as OTM, read
// that, import it as a model YAML file, and analyze that again. The structure survives, and so do
// the threagile details that OTM has no field for, as they travel as "threagile:" attributes.
//
// Lossy, as OTM has nothing to hold them and the import does not create them:
//   - risk tracking: threats are not imported, so every risk of the imported model is unchecked
//   - custom risk categories and their individual risks
//   - shared runtimes, and with them the risks about them
//   - questions, abuse cases, security requirements, management summary, business and technical
//     overview, contributors, the author's homepage, and the diagram tweaks
//   - technical assets carry the confidentiality, integrity and availability of the analyzed model,
//     which raises them to those of their data assets, and process the data assets the analysis
//     adds; the analysis of the imported model arrives at the same values
func TestRoundTrip(t *testing.T) {
	original := analyze(t, exampleModelFile)

	otmJSON, err := json.Marshal(otm.FromInterchange(interchange.FromModel(original)))
	require.NoError(t, err)
	document, err := otm.Parse(otmJSON)
	require.NoError(t, err)

	modelInput, notes := interchange.ToInput(otm.ToInterchange(document), technologies(t))
	assert.Empty(t, notes, "a model written by threagile needs no defaults")

	modelYAML, err := yaml.Marshal(modelInput)
	require.NoError(t, err)
	modelFile := filepath.Join(t.TempDir(), "threagile.yaml")
	require.NoError(t, os.WriteFile(modelFile, modelYAML, 0o600))
	imported := analyze(t, modelFile)

	assert.Equal(t, original.Title, imported.Title)
	assert.Equal(t, original.Author.Name, imported.Author.Name)
	assert.Equal(t, original.Date, imported.Date)
	assert.Equal(t, original.BusinessCriticality, imported.BusinessCriticality)
	assert.ElementsMatch(t, original.TagsAvailable, imported.TagsAvailable)

	assertSameKeys(t, original.TrustBoundaries, imported.TrustBoundaries)
	for id, boundary := range original.TrustBoundaries {
		again := imported.TrustBoundaries[id]
		assert.Equal(t, boundary.Title, again.Title, id)
		assert.Equal(t, boundary.Type, again.Type, id)
		assert.Equal(t, boundary.Description, again.Description, id)
		assert.ElementsMatch(t, boundary.Tags, again.Tags, id)
		assert.ElementsMatch(t, boundary.TechnicalAssetsInside, again.TechnicalAssetsInside, id)
		assert.ElementsMatch(t, boundary.TrustBoundariesNested, again.TrustBoundariesNested, id)
	}

	assertSameKeys(t, original.TechnicalAssets, imported.TechnicalAssets)
	for id, asset := range original.TechnicalAssets {
		again := imported.TechnicalAssets[id]
		// everything but the links (compared below) and the RAA (which the analysis computes)
		asset, again = clearComputed(asset), clearComputed(again)
		assert.Equal(t, asset, again, id)
	}

	assertSameKeys(t, original.CommunicationLinks, imported.CommunicationLinks)
	for id, link := range original.CommunicationLinks {
		again := *imported.CommunicationLinks[id]
		assert.ElementsMatch(t, link.DataAssetsSent, again.DataAssetsSent, id)
		assert.ElementsMatch(t, link.DataAssetsReceived, again.DataAssetsReceived, id)
		again.DataAssetsSent, again.DataAssetsReceived = link.DataAssetsSent, link.DataAssetsReceived
		assert.Equal(t, *link, again, id)
	}

	assertSameKeys(t, original.DataAssets, imported.DataAssets)
	for id, asset := range original.DataAssets {
		assert.Equal(t, *asset, *imported.DataAssets[id], id)
	}

	// the risks survive, but for those of the custom risk categories and the shared runtime
	lost := make([]string, 0)
	for id := range original.GeneratedRisksBySyntheticId {
		if _, found := imported.GeneratedRisksBySyntheticId[id]; !found {
			lost = append(lost, id)
		}
	}
	assert.ElementsMatch(t, []string{
		"something-strange@contract-file-server",
		"something-strange@sql-database",
		"mixed-targets-on-shared-runtime@webapp-virtualization",
	}, lost)
	assert.Len(t, imported.GeneratedRisksBySyntheticId, len(original.GeneratedRisksBySyntheticId)-len(lost),
		"the import adds no risks")
	assert.Empty(t, imported.RiskTracking, "risk tracking is lossy")
	assert.Empty(t, imported.SharedRuntimes, "shared runtimes are lossy")
}

func TestParseReadsYAMLAndToleratesOddAttributes(t *testing.T) {
	document, err := otm.Parse([]byte(`
otmVersion: 0.2.0
project: {name: Shop, id: shop, attributes: [{owner: someone}]}
trustZones:
  - {id: internet, name: Internet, risk: {trustRating: 1}}
components:
  - id: web
    name: Web
    type: web-server
    parent: {trustZone: internet}
    attributes: {threagile:machine: container, threagile:redundant: true, cmdbId: 7}
assets:
  - {id: orders, name: Orders, risk: {confidentiality: 62.5, integrity: 140, availability: -3}}
`))
	require.NoError(t, err)
	assert.Nil(t, document.Project.Attributes, "attributes that are no object are left out")
	assert.Equal(t, otm.Attributes{"threagile:machine": "container", "threagile:redundant": "true", "cmdbId": "7"},
		document.Components[0].Attributes)

	elements := otm.ToInterchange(document)
	assert.Equal(t, interchange.Properties{"machine": "container", "redundant": "true"}, elements.Components[0].Properties,
		"only the threagile attributes are properties")
	assert.Equal(t, "internet", elements.Components[0].ParentID)
	assert.Equal(t, types.Confidential, elements.DataAssets[0].Confidentiality, "62.5 is nearest to 75")
	assert.Equal(t, types.MissionCritical, elements.DataAssets[0].Integrity, "beyond 100 is the highest level")
	assert.Equal(t, types.Archive, elements.DataAssets[0].Availability, "below 0 is the lowest level")
}

func TestParseRejectsOtherDocuments(t *testing.T) {
	_, err := otm.Parse([]byte(`title: A threagile model`))
	require.ErrorContains(t, err, "no otmVersion")

	_, err = otm.Parse([]byte(`{"otmVersion": `))
	require.Error(t, err)
}

func TestToInterchangeLeavesTheOutsideZoneOut(t *testing.T) {
	document := otm.FromInterchange(&interchange.Model{Components: []interchange.Component{{ID: "a"}}})
	require.Len(t, document.TrustZones, 1)

	elements := otm.ToInterchange(document)
	assert.Empty(t, elements.Zones)
	assert.Empty(t, elements.Components[0].ParentID)
}

func clearComputed(asset *types.TechnicalAsset) *types.TechnicalAsset {
	result := *asset
	result.CommunicationLinks = nil
	result.RAA = 0
	slices.Sort(result.DataAssetsProcessed)
	slices.Sort(result.DataAssetsStored)
	return &result
}

func assertSameKeys[T any](t *testing.T, want map[string]T, got map[string]T) {
	t.Helper()
	assert.Equal(t, slices.Sorted(maps.Keys(want)), slices.Sorted(maps.Keys(got)))
}

func analyze(t *testing.T, modelFile string) *types.Model {
	t.Helper()
	config := new(threagile.Config).Defaults("")
	config.SetAppFolder(t.TempDir())
	config.SetPluginFolder(t.TempDir())
	config.SetInputFile(modelFile)
	config.SetOutputFolder(t.TempDir())
	config.SetTempFolder(t.TempDir())

	result, err := model.ReadAndAnalyzeModel(config, risks.GetBuiltInRiskRules(), quietReporter{})
	require.NoError(t, err)
	return result.ParsedModel
}

func technologies(t *testing.T) types.TechnologyMap {
	t.Helper()
	result := make(types.TechnologyMap)
	require.NoError(t, result.LoadDefault())
	result.PropagateAttributes()
	return result
}

type quietReporter struct{}

func (quietReporter) Info(...any)           {}
func (quietReporter) Infof(string, ...any)  {}
func (quietReporter) Warn(...any)           {}
func (quietReporter) Warnf(string, ...any)  {}
func (quietReporter) Error(...any)          {}
func (quietReporter) Errorf(string, ...any) {}
