package interchange_test

import (
	"testing"

	"github.com/Pinguladora/threagile/internal/threagile"
	"github.com/Pinguladora/threagile/pkg/interchange"
	"github.com/Pinguladora/threagile/pkg/model"
	"github.com/Pinguladora/threagile/pkg/risks"
	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const exampleModelFile = "../../demo/example/threagile.yaml"

func TestFromModelMapsTheElements(t *testing.T) {
	parsedModel := analyze(t, exampleModelFile)
	result := interchange.FromModel(parsedModel)

	assert.Equal(t, "some-example-application", result.Project.ID)
	assert.Equal(t, "Some Example Application", result.Project.Name)
	assert.Equal(t, parsedModel.Author.Name, result.Project.Owner)
	assert.Equal(t, parsedModel.TagsAvailable, result.Project.Tags)
	assert.Equal(t, "important", result.Project.Properties["business_criticality"])
	assert.Equal(t, "2020-07-01", result.Project.Properties["date"])

	require.Len(t, result.Zones, len(parsedModel.TrustBoundaries))
	zones := byID(result.Zones, func(zone interchange.Zone) string { return zone.ID })
	assert.Empty(t, zones["application-network"].ParentID)
	assert.Equal(t, "application-network", zones["web-dmz"].ParentID, "a nested boundary names its parent")
	assert.Equal(t, "network-cloud-security-group", zones["web-dmz"].Type)
	assert.Equal(t, "some-erp", zones["erp-dmz"].Properties["tags"])

	require.Len(t, result.Components, len(parsedModel.TechnicalAssets))
	components := byID(result.Components, func(component interchange.Component) string { return component.ID })
	assert.Equal(t, "web-dmz", components["apache-webserver"].ParentID)
	assert.Empty(t, components["customer-client"].ParentID, "an asset outside of all boundaries has no parent")
	assert.Equal(t, "web-server", components["apache-webserver"].Type)
	assert.Equal(t, "datastore", components["sql-database"].Properties["type"])
	assert.Equal(t, "true", components["customer-client"].Properties["internet"])
	assert.Equal(t, parsedModel.TechnicalAssets["sql-database"].Tags, components["sql-database"].Tags)
	assert.Contains(t, components["sql-database"].Stored, "customer-accounts")

	require.Len(t, result.Flows, len(parsedModel.CommunicationLinks))
	for _, flow := range result.Flows {
		link := parsedModel.CommunicationLinks[flow.ID]
		assert.Equal(t, link.SourceId, flow.SourceID, flow.ID)
		assert.Equal(t, link.TargetId, flow.DestinationID, flow.ID)
		assert.Equal(t, link.IsBidirectional(), flow.Bidirectional, flow.ID)
	}

	require.Len(t, result.DataAssets, len(parsedModel.DataAssets))
	dataAssets := byID(result.DataAssets, func(asset interchange.DataAsset) string { return asset.ID })
	assert.Equal(t, types.StrictlyConfidential, dataAssets["customer-accounts"].Confidentiality)
	assert.Equal(t, types.Critical, dataAssets["customer-accounts"].Availability)
	assert.Equal(t, "many", dataAssets["customer-accounts"].Properties["quantity"])
}

func TestFromModelTurnsRisksIntoThreats(t *testing.T) {
	parsedModel := analyze(t, exampleModelFile)
	result := interchange.FromModel(parsedModel)

	require.Len(t, result.Threats, len(parsedModel.GeneratedRisksByCategory), "one threat per risk category with risks")
	threats := byID(result.Threats, func(threat interchange.Threat) string { return threat.ID })
	custom := threats["something-strange"]
	assert.Equal(t, "Some Individual Risk Example", custom.Name)
	assert.Equal(t, types.Repudiation, custom.STRIDE)
	assert.Equal(t, 693, custom.CWE)
	assert.Equal(t, types.Frequent, custom.Likelihood, "the highest likelihood of the risks")
	assert.Equal(t, types.VeryHighImpact, custom.Impact, "the highest impact of the risks")
	assert.Equal(t, "Some text describing the action...", custom.Mitigation.Name)
	assert.Equal(t, "Check if XYZ...", custom.Mitigation.Check)

	statuses := make(map[types.RiskStatus]int)
	for _, component := range result.Components {
		for _, instance := range component.Threats {
			statuses[instance.Status]++
		}
	}
	for _, flow := range result.Flows {
		for _, instance := range flow.Threats {
			statuses[instance.Status]++
		}
	}

	// every risk is at its link or asset, and a risk with neither at each of its data breach assets
	want := make(map[types.RiskStatus]int)
	for _, risk := range parsedModel.AllRisks() {
		count := 1
		if risk.MostRelevantCommunicationLinkId == "" && risk.MostRelevantTechnicalAssetId == "" {
			count = len(risk.DataBreachTechnicalAssetIDs)
		}
		want[parsedModel.GetRiskTrackingWithDefault(risk).Status] += count
	}
	assert.Equal(t, want, statuses)
	assert.Positive(t, statuses[types.Mitigated], "the example tracks risks as mitigated")
}

func TestSlug(t *testing.T) {
	assert.Equal(t, "some-example-application", interchange.Slug("Some Example Application"))
	assert.Equal(t, "a-b-c", interchange.Slug("  A/b: C! "))
}

func analyze(t *testing.T, modelFile string) *types.Model {
	t.Helper()
	config := new(threagile.Config).Defaults("")
	config.SetAppFolder(t.TempDir())
	config.SetPluginFolder(t.TempDir())
	config.SetInputFile(modelFile)
	config.SetOutputFolder(t.TempDir())
	config.SetTempFolder(t.TempDir())

	result, err := model.ReadAndAnalyzeModel(config, risks.GetBuiltInRiskRules(), testReporter{t})
	require.NoError(t, err)
	return result.ParsedModel
}

func byID[T any](elements []T, id func(T) string) map[string]T {
	result := make(map[string]T, len(elements))
	for _, element := range elements {
		result[id(element)] = element
	}
	return result
}

// testReporter sends warnings to the test log and fails the test on errors.
type testReporter struct {
	t *testing.T
}

func (r testReporter) Info(...any) {}

func (r testReporter) Infof(string, ...any) {}

func (r testReporter) Warn(a ...any) {
	r.t.Log(a...)
}

func (r testReporter) Warnf(format string, a ...any) {
	r.t.Logf(format, a...)
}

func (r testReporter) Error(a ...any) {
	r.t.Error(a...)
}

func (r testReporter) Errorf(format string, a ...any) {
	r.t.Errorf(format, a...)
}
