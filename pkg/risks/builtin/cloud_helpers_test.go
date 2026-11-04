package builtin

import (
	"testing"

	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestIsCloudTechnicalAsset(t *testing.T) {
	testCases := map[string]struct {
		assetTags         []string
		trustBoundaryType types.TrustBoundaryType
		trustBoundaryTags []string
		parentType        types.TrustBoundaryType
		parentTags        []string
		sharedRuntimeTags []string

		expected bool
	}{
		"no cloud at all":                     {},
		"unrelated asset tag":                 {assetTags: []string{"linux"}},
		"provider tag on the asset":           {assetTags: []string{"aws"}, expected: true},
		"provider sub-tag on the asset":       {assetTags: []string{"gcp:storage"}, expected: true},
		"cloud provider trust boundary":       {trustBoundaryType: types.NetworkCloudProvider, expected: true},
		"cloud security group trust boundary": {trustBoundaryType: types.NetworkCloudSecurityGroup, expected: true},
		"tagged trust boundary":               {trustBoundaryTags: []string{"azure"}, expected: true},
		"cloud parent trust boundary":         {parentType: types.NetworkCloudProvider, expected: true},
		"tagged parent trust boundary":        {parentTags: []string{"ocp"}, expected: true},
		"tagged shared runtime":               {sharedRuntimeTags: []string{"aws:ec2"}, expected: true},
		"on-prem trust boundaries only":       {trustBoundaryTags: []string{"vmware"}, parentTags: []string{"linux"}},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			model := &types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {Id: "ta1", Tags: testCase.assetTags},
				},
				TrustBoundaries: map[string]*types.TrustBoundary{
					"tb1": {Id: "tb1", Type: testCase.trustBoundaryType, Tags: testCase.trustBoundaryTags, TechnicalAssetsInside: []string{"ta1"}},
					"tb2": {Id: "tb2", Type: testCase.parentType, Tags: testCase.parentTags, TrustBoundariesNested: []string{"tb1"}},
				},
				SharedRuntimes: map[string]*types.SharedRuntime{
					"sr1": {Id: "sr1", Tags: testCase.sharedRuntimeTags, TechnicalAssetsRunning: []string{"ta1"}},
				},
			}

			assert.Equal(t, testCase.expected, isCloudTechnicalAsset(model, model.TechnicalAssets["ta1"]))
		})
	}
}

func TestCloudAccountTrustBoundary(t *testing.T) {
	model := &types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"in-security-group": {Id: "in-security-group"},
			"in-account":        {Id: "in-account"},
			"in-organization":   {Id: "in-organization"},
			"on-prem":           {Id: "on-prem"},
			"outside":           {Id: "outside"},
		},
		TrustBoundaries: map[string]*types.TrustBoundary{
			"security-group": {Id: "security-group", Type: types.NetworkCloudSecurityGroup, TechnicalAssetsInside: []string{"in-security-group"}},
			"account":        {Id: "account", Type: types.NetworkCloudProvider, TechnicalAssetsInside: []string{"in-account"}, TrustBoundariesNested: []string{"security-group"}},
			"organization":   {Id: "organization", Type: types.NetworkCloudProvider, TechnicalAssetsInside: []string{"in-organization"}, TrustBoundariesNested: []string{"account"}},
			"datacenter":     {Id: "datacenter", Type: types.NetworkOnPrem, TechnicalAssetsInside: []string{"on-prem"}},
		},
	}

	for asset, expected := range map[string]string{
		"in-security-group": "account",
		"in-account":        "account",
		"in-organization":   "organization",
		"on-prem":           "",
		"outside":           "",
	} {
		t.Run(asset, func(t *testing.T) {
			trustBoundary := cloudAccountTrustBoundary(model, model.TechnicalAssets[asset])
			if expected == "" {
				assert.Nil(t, trustBoundary)
				return
			}
			assert.Equal(t, expected, trustBoundary.Id)
		})
	}
}

func TestCloudRiskImpact(t *testing.T) {
	testCases := map[string]struct {
		confidentiality types.Confidentiality
		integrity       types.Criticality
		availability    types.Criticality

		expected types.RiskExploitationImpact
	}{
		"lowest ratings":        {types.Public, types.Archive, types.Archive, types.MediumImpact},
		"restricted":            {types.Restricted, types.Important, types.Important, types.MediumImpact},
		"confidential":          {types.Confidential, types.Archive, types.Archive, types.HighImpact},
		"critical integrity":    {types.Public, types.Critical, types.Archive, types.HighImpact},
		"critical availability": {types.Public, types.Archive, types.Critical, types.HighImpact},
		"strictly confidential": {types.StrictlyConfidential, types.Archive, types.Archive, types.VeryHighImpact},
		"mission-critical integrity": {
			types.Public, types.MissionCritical, types.Archive, types.VeryHighImpact,
		},
		"mission-critical availability": {
			types.Public, types.Archive, types.MissionCritical, types.VeryHighImpact,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, testCase.expected, cloudRiskImpact(testCase.confidentiality, testCase.integrity, testCase.availability))
		})
	}
}
