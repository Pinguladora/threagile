package otm_test

import (
	"slices"
	"testing"

	"github.com/Pinguladora/threagile/pkg/interchange"
	"github.com/Pinguladora/threagile/pkg/otm"
	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFromInterchangeRatesTrustZones(t *testing.T) {
	document := otm.FromInterchange(&interchange.Model{
		Zones: []interchange.Zone{
			{ID: "cloud", Type: "network-cloud-provider"},
			{ID: "group", Type: "network-cloud-security-group", ParentID: "cloud"},
			{ID: "env", Type: "execution-environment", ParentID: "group"},
			{ID: "logical", Type: "execution-environment"},
			{ID: "other", Type: "internet"},
		},
		Components: []interchange.Component{{ID: "inside", ParentID: "env"}},
	})

	ratings := make(map[string]float64)
	for _, zone := range document.TrustZones {
		ratings[zone.ID] = zone.Risk.TrustRating
	}
	assert.Equal(t, map[string]float64{"cloud": 40, "group": 60, "env": 60, "logical": 50, "other": 50}, ratings,
		"an execution environment has the rating of the zone it is in")

	group := document.TrustZones[slices.IndexFunc(document.TrustZones, func(zone otm.TrustZone) bool { return zone.ID == "group" })]
	require.NotNil(t, group.Parent)
	assert.Equal(t, "cloud", group.Parent.TrustZone)
	assert.Equal(t, "env", document.Components[0].Parent.TrustZone)
}

func TestFromInterchangeAddsTheOutsideZoneWhenNeeded(t *testing.T) {
	document := otm.FromInterchange(&interchange.Model{
		Zones:      []interchange.Zone{{ID: "zone", Type: "network-on-prem"}},
		Components: []interchange.Component{{ID: "b", ParentID: "zone"}, {ID: "a"}},
	})

	require.Len(t, document.TrustZones, 2)
	assert.Equal(t, otm.OutsideZoneID, document.TrustZones[0].ID, "zones are sorted by id")
	assert.Zero(t, document.TrustZones[0].Risk.TrustRating)
	assert.Equal(t, "a", document.Components[0].ID, "components are sorted by id")
	assert.Equal(t, otm.OutsideZoneID, document.Components[0].Parent.TrustZone)

	document = otm.FromInterchange(&interchange.Model{
		Zones:      []interchange.Zone{{ID: "zone", Type: "network-on-prem"}},
		Components: []interchange.Component{{ID: "b", ParentID: "zone"}},
	})
	assert.Len(t, document.TrustZones, 1, "no outside zone without components outside")
}

func TestFromInterchangeMapsThreats(t *testing.T) {
	document := otm.FromInterchange(&interchange.Model{
		Components: []interchange.Component{{ID: "c", Threats: []interchange.ThreatInstance{
			{ThreatID: "t", Status: types.Unchecked},
			{ThreatID: "t", Status: types.InDiscussion},
			{ThreatID: "t", Status: types.InProgress},
			{ThreatID: "t", Status: types.Accepted},
			{ThreatID: "t", Status: types.Mitigated},
			{ThreatID: "t", Status: types.FalsePositive},
			{ThreatID: "t", Status: types.Mitigated},
		}}},
		DataAssets: []interchange.DataAsset{
			{ID: "d", Confidentiality: types.Confidential, Integrity: types.MissionCritical, Availability: types.Archive},
		},
		Threats: []interchange.Threat{{
			ID: "t", Name: "Threat", STRIDE: types.InformationDisclosure, CWE: 79,
			Likelihood: types.Likely, Impact: types.VeryHighImpact, ImpactText: "Bad",
			Mitigation: interchange.Mitigation{Name: "Fix", Description: "Fix it", Check: "Fixed?"},
		}},
	})

	states := make([]string, 0, len(document.Components[0].Threats))
	for _, instance := range document.Components[0].Threats {
		require.Len(t, instance.Mitigations, 1)
		assert.Equal(t, "t-mitigation", instance.Mitigations[0].Mitigation)
		states = append(states, instance.State+"/"+instance.Mitigations[0].State)
	}
	assert.Equal(t, []string{
		"exposed/recommended", "exposed/required",
		"accepted/rejected", "mitigated/implemented", "not-applicable/not-applicable",
	}, states, "in discussion is in the same states as unchecked, and an element lists each threat once per states")

	assert.Equal(t, otm.AssetRisk{Confidentiality: 75, Integrity: 100, Availability: 0}, document.Assets[0].Risk)

	require.Len(t, document.Threats, 1)
	threat := document.Threats[0]
	assert.Equal(t, []string{"Information Disclosure"}, threat.Categories)
	assert.Equal(t, []string{"CWE-79"}, threat.CWEs)
	assert.Equal(t, otm.ThreatRisk{Likelihood: 50, Impact: 100, ImpactComment: "Bad"}, threat.Risk)

	require.Len(t, document.Mitigations, 1)
	mitigation := document.Mitigations[0]
	assert.Equal(t, "t-mitigation", mitigation.ID)
	assert.Equal(t, "Fix", mitigation.Name)
	assert.Equal(t, "Fix it", mitigation.Description)
	assert.InDelta(t, 100, mitigation.RiskReduction, 0)
	assert.Equal(t, otm.Attributes{"threagile:check": "Fixed?"}, mitigation.Attributes)
}
