package types

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModelWithoutDevOps(t *testing.T) {
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

	reported, leftOut := model.WithoutDevOps()

	assert.Equal(t, LeftOut{TechnicalAssets: 1, Risks: 3}, leftOut)
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

func keys[V any](m map[string]V) []string {
	result := make([]string, 0, len(m))
	for key := range m {
		result = append(result, key)
	}
	slices.Sort(result)
	return result
}
