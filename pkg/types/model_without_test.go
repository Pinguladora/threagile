package types

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModelWithout(t *testing.T) {
	deploys := &CommunicationLink{Id: "ci>deploys", SourceId: "ci", TargetId: "app", DataAssetsSent: []string{"build"}}
	logs := &CommunicationLink{Id: "app>logs", SourceId: "app", TargetId: "db", DataAssetsSent: []string{"logs"}}
	appRisk := &Risk{
		CategoryId: "a", SyntheticId: "a@app", MostRelevantTechnicalAssetId: "app",
		DataBreachTechnicalAssetIDs: []string{"app", "ci"},
	}
	ciRisk := &Risk{CategoryId: "a", SyntheticId: "a@ci", MostRelevantTechnicalAssetId: "ci"}
	linkRisk := &Risk{CategoryId: "b", SyntheticId: "b@ci>deploys", MostRelevantCommunicationLinkId: "ci>deploys"}
	modelRisk := &Risk{CategoryId: "c", SyntheticId: "c"}
	runtimeRisk := &Risk{CategoryId: "d", SyntheticId: "d@runners", MostRelevantSharedRuntimeId: "runners"}
	model := &Model{
		TechnicalAssets: map[string]*TechnicalAsset{
			"app": {
				Id: "app", Usage: Business, CommunicationLinks: []*CommunicationLink{logs},
				DataAssetsProcessed: []string{"orders", "logs"},
			},
			"db": {Id: "db", Usage: Business, DataAssetsStored: []string{"logs"}},
			"ci": {
				Id: "ci", Usage: DevOps, CommunicationLinks: []*CommunicationLink{deploys},
				DataAssetsProcessed: []string{"build"},
			},
		},
		CommunicationLinks: map[string]*CommunicationLink{"ci>deploys": deploys, "app>logs": logs},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*CommunicationLink{
			"app": {deploys}, "db": {logs},
		},
		DataAssets: map[string]*DataAsset{
			"orders": {Id: "orders", Usage: Business},
			"build":  {Id: "build", Usage: DevOps},
			"logs":   {Id: "logs", Usage: DevOps},
			"unused": {Id: "unused", Usage: Business},
		},
		TrustBoundaries: map[string]*TrustBoundary{
			"cloud":   {Id: "cloud", TrustBoundariesNested: []string{"vpc", "github"}},
			"vpc":     {Id: "vpc", TechnicalAssetsInside: []string{"app", "db"}},
			"github":  {Id: "github", TrustBoundariesNested: []string{"runners"}},
			"runners": {Id: "runners", TechnicalAssetsInside: []string{"ci"}},
			"spare":   {Id: "spare"},
		},
		SharedRuntimes: map[string]*SharedRuntime{
			"runners": {Id: "runners", TechnicalAssetsRunning: []string{"ci"}},
			"hosts":   {Id: "hosts", TechnicalAssetsRunning: []string{"app", "ci"}},
			"spare":   {Id: "spare"},
		},
		GeneratedRisksByCategory: map[string][]*Risk{
			"a": {appRisk, ciRisk}, "b": {linkRisk}, "c": {modelRisk}, "d": {runtimeRisk},
		},
	}
	model.DirectContainingTrustBoundaryMappedByTechnicalAssetId = map[string]*TrustBoundary{
		"app": model.TrustBoundaries["vpc"], "db": model.TrustBoundaries["vpc"], "ci": model.TrustBoundaries["runners"],
	}

	exclusion := ReportExclusion{Layers: []Layer{DeliveryLayer}}
	reported, leftOut := model.Without(exclusion)

	assert.Equal(t, &LeftOut{Exclusion: exclusion, TechnicalAssets: 1, Risks: 3}, leftOut)
	assert.ElementsMatch(t, []string{"app", "db"}, keys(reported.TechnicalAssets))
	assert.ElementsMatch(t, []string{"app>logs"}, keys(reported.CommunicationLinks))
	assert.Empty(t, reported.IncomingTechnicalCommunicationLinksMappedByTargetId["app"], "no links from devops assets")
	assert.ElementsMatch(t, []string{"orders", "logs", "unused"}, keys(reported.DataAssets),
		"devops data a business asset holds stays, business data stays even when unused")
	assert.ElementsMatch(t, []string{"cloud", "vpc", "spare"}, keys(reported.TrustBoundaries),
		"boundaries the devops assets leave empty go, from the inside out, one that was empty stays")
	assert.Equal(t, []string{"vpc"}, reported.TrustBoundaries["cloud"].TrustBoundariesNested)
	assert.Same(t, reported.TrustBoundaries["vpc"], reported.DirectContainingTrustBoundaryMappedByTechnicalAssetId["app"])
	assert.ElementsMatch(t, []string{"hosts", "spare"}, keys(reported.SharedRuntimes))
	assert.Equal(t, []string{"app"}, reported.SharedRuntimes["hosts"].TechnicalAssetsRunning)

	risks := reported.AllRisks()
	ids := make([]string, 0, len(risks))
	for _, risk := range risks {
		ids = append(ids, risk.SyntheticId)
	}
	assert.Equal(t, []string{"a@app", "c"}, ids)
	require.Contains(t, reported.GeneratedRisksBySyntheticId, "a@app")
	assert.Equal(t, []string{"app"}, reported.GeneratedRisksBySyntheticId["a@app"].DataBreachTechnicalAssetIDs)

	// the model itself keeps everything
	assert.Len(t, model.TechnicalAssets, 3)
	assert.Len(t, model.AllRisks(), 5)
	assert.Equal(t, []string{"app", "ci"}, appRisk.DataBreachTechnicalAssetIDs)
	assert.Equal(t, []string{"runners"}, model.TrustBoundaries["github"].TrustBoundariesNested)
	assert.Len(t, model.SharedRuntimes["hosts"].TechnicalAssetsRunning, 2)
}

func TestModelWithoutNothing(t *testing.T) {
	model := &Model{TechnicalAssets: map[string]*TechnicalAsset{"ci": {Id: "ci", Usage: DevOps}}}

	reported, leftOut := model.Without(ReportExclusion{})

	assert.Same(t, model, reported)
	assert.Nil(t, leftOut)
}

func TestExcludedTechnicalAssets(t *testing.T) {
	model := &Model{
		TagsAvailable: []string{"bot"},
		TechnicalAssets: map[string]*TechnicalAsset{
			"app":     {Id: "app", Usage: Business},
			"cluster": {Id: "cluster", Usage: DevOps, Layer: PlatformLayer},
			"ci":      {Id: "ci", Usage: DevOps},
			"bot":     {Id: "bot", Usage: Business, Tags: []string{"bot"}},
			"runner":  {Id: "runner", Usage: Business},
		},
		TrustBoundaries: map[string]*TrustBoundary{
			"github":  {Id: "github", TechnicalAssetsInside: []string{"bot"}, TrustBoundariesNested: []string{"runners"}},
			"runners": {Id: "runners", TechnicalAssetsInside: []string{"runner"}},
		},
	}
	for name, test := range map[string]struct {
		exclusion ReportExclusion
		excluded  []string
	}{
		"delivery layer, from devops usage": {ReportExclusion{Layers: []Layer{DeliveryLayer}}, []string{"ci"}},
		"platform layer, named":             {ReportExclusion{Layers: []Layer{PlatformLayer}}, []string{"cluster"}},
		"application layer, from business usage": {
			ReportExclusion{Layers: []Layer{ApplicationLayer}}, []string{"app", "bot", "runner"},
		},
		"tag":             {ReportExclusion{Tags: []string{"bot"}}, []string{"bot"}},
		"technical asset": {ReportExclusion{TechnicalAssets: []string{"app"}}, []string{"app"}},
		"trust boundary, nested ones included": {
			ReportExclusion{TrustBoundaries: []string{"github"}}, []string{"bot", "runner"},
		},
		"several": {
			ReportExclusion{Layers: []Layer{DeliveryLayer}, TechnicalAssets: []string{"cluster"}},
			[]string{"ci", "cluster"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, model.CheckReportExclusion(test.exclusion))
			assert.ElementsMatch(t, test.excluded, keys(model.excludedTechnicalAssets(test.exclusion)))
		})
	}

	for _, unknown := range []ReportExclusion{
		{Tags: []string{"bots"}}, {TechnicalAssets: []string{"apps"}}, {TrustBoundaries: []string{"gitlab"}},
	} {
		assert.Error(t, model.CheckReportExclusion(unknown), "%+v", unknown)
	}
}

func TestParseReportExclusion(t *testing.T) {
	exclusion, err := ParseReportExclusion([]string{
		"layer:delivery", " tag:CI ", "asset:renovate", "boundary:github", "", "layer:platform",
	})
	require.NoError(t, err)
	assert.Equal(t, ReportExclusion{
		Layers:          []Layer{DeliveryLayer, PlatformLayer},
		Tags:            []string{"ci"},
		TechnicalAssets: []string{"renovate"},
		TrustBoundaries: []string{"github"},
	}, exclusion)
	assert.Equal(t, "layer delivery, layer platform, tag ci, technical asset renovate and trust boundary github",
		exclusion.String())
	assert.Equal(t, "tag ci", ReportExclusion{Tags: []string{"ci"}}.String())

	empty, err := ParseReportExclusion([]string{""})
	require.NoError(t, err)
	assert.True(t, empty.IsEmpty(), "an empty --report-exclude shows everything")

	for _, wrong := range []string{"layer:build", "layer:", "delivery", "host:node"} {
		_, err := ParseReportExclusion([]string{wrong})
		assert.Error(t, err, wrong)
	}
}

func keys[V any](m map[string]V) []string {
	result := make([]string, 0, len(m))
	for key := range m {
		result = append(result, key)
	}
	slices.Sort(result)
	return result
}
