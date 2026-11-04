/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package model

import (
	"slices"
	"testing"

	"github.com/Pinguladora/threagile/pkg/input"
	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultInputNotFail(t *testing.T) {
	parsedModel, err := ParseModel(&mockConfig{}, createInputModel(make(map[string]input.TechnicalAsset), make(map[string]input.DataAsset)), make(types.RiskRules), make(types.RiskRules))

	assert.NoError(t, err)
	assert.NotNil(t, parsedModel)
}

func TestInferConfidentiality_NotSet_NoOthers_ExpectTODO(t *testing.T) {
	ta := make(map[string]input.TechnicalAsset)
	da := make(map[string]input.DataAsset)

	_, err := ParseModel(&mockConfig{}, createInputModel(ta, da), make(types.RiskRules), make(types.RiskRules))
	// TODO: rename test and check if everyone agree that by default it should be public if there are no other assets

	assert.NoError(t, err)
}

func TestInferConfidentiality_ExpectHighestConfidentiality(t *testing.T) {
	ta := make(map[string]input.TechnicalAsset)
	da := make(map[string]input.DataAsset)

	daConfidentialConfidentiality := createDataAsset(types.Confidential, types.Critical, types.Critical)
	da[daConfidentialConfidentiality.ID] = daConfidentialConfidentiality

	daRestrictedConfidentiality := createDataAsset(types.Restricted, types.Important, types.Important)
	da[daRestrictedConfidentiality.ID] = daRestrictedConfidentiality

	daPublicConfidentiality := createDataAsset(types.Public, types.Archive, types.Archive)
	da[daPublicConfidentiality.ID] = daPublicConfidentiality

	taWithConfidentialConfidentialityDataAsset := createTechnicalAsset(types.Internal, types.Operational, types.Operational)
	taWithConfidentialConfidentialityDataAsset.DataAssetsProcessed = append(taWithConfidentialConfidentialityDataAsset.DataAssetsProcessed, daConfidentialConfidentiality.ID)
	ta[taWithConfidentialConfidentialityDataAsset.ID] = taWithConfidentialConfidentialityDataAsset

	taWithRestrictedConfidentialityDataAsset := createTechnicalAsset(types.Internal, types.Operational, types.Operational)
	taWithRestrictedConfidentialityDataAsset.DataAssetsProcessed = append(taWithRestrictedConfidentialityDataAsset.DataAssetsProcessed, daRestrictedConfidentiality.ID)
	ta[taWithRestrictedConfidentialityDataAsset.ID] = taWithRestrictedConfidentialityDataAsset

	taWithPublicConfidentialityDataAsset := createTechnicalAsset(types.Internal, types.Operational, types.Operational)
	taWithPublicConfidentialityDataAsset.DataAssetsProcessed = append(taWithPublicConfidentialityDataAsset.DataAssetsProcessed, daPublicConfidentiality.ID)
	ta[taWithPublicConfidentialityDataAsset.ID] = taWithPublicConfidentialityDataAsset

	parsedModel, err := ParseModel(&mockConfig{}, createInputModel(ta, da), make(types.RiskRules), make(types.RiskRules))

	assert.NoError(t, err)
	assert.Equal(t, types.Confidential, parsedModel.TechnicalAssets[taWithConfidentialConfidentialityDataAsset.ID].Confidentiality)
	assert.Equal(t, types.Restricted, parsedModel.TechnicalAssets[taWithRestrictedConfidentialityDataAsset.ID].Confidentiality)
	assert.Equal(t, types.Internal, parsedModel.TechnicalAssets[taWithPublicConfidentialityDataAsset.ID].Confidentiality)
}

func TestInferIntegrity_NotSet_NoOthers_ExpectTODO(t *testing.T) {
	ta := make(map[string]input.TechnicalAsset)
	da := make(map[string]input.DataAsset)

	_, err := ParseModel(&mockConfig{}, createInputModel(ta, da), make(types.RiskRules), make(types.RiskRules))
	// TODO: rename test and check if everyone agree that by default it should be public if there are no other assets

	assert.NoError(t, err)
}

func TestInferIntegrity_ExpectHighestIntegrity(t *testing.T) {
	ta := make(map[string]input.TechnicalAsset)
	da := make(map[string]input.DataAsset)

	daCriticalIntegrity := createDataAsset(types.Confidential, types.Critical, types.Critical)
	da[daCriticalIntegrity.ID] = daCriticalIntegrity

	daImportantIntegrity := createDataAsset(types.Restricted, types.Important, types.Important)
	da[daImportantIntegrity.ID] = daImportantIntegrity

	daArchiveIntegrity := createDataAsset(types.Public, types.Archive, types.Archive)
	da[daArchiveIntegrity.ID] = daArchiveIntegrity

	taWithCriticalIntegrityDataAsset := createTechnicalAsset(types.Internal, types.Operational, types.Operational)
	taWithCriticalIntegrityDataAsset.DataAssetsProcessed = append(taWithCriticalIntegrityDataAsset.DataAssetsProcessed, daCriticalIntegrity.ID)
	ta[taWithCriticalIntegrityDataAsset.ID] = taWithCriticalIntegrityDataAsset

	taWithImportantIntegrityDataAsset := createTechnicalAsset(types.Internal, types.Operational, types.Operational)
	taWithImportantIntegrityDataAsset.DataAssetsProcessed = append(taWithImportantIntegrityDataAsset.DataAssetsProcessed, daImportantIntegrity.ID)
	ta[taWithImportantIntegrityDataAsset.ID] = taWithImportantIntegrityDataAsset

	taWithArchiveIntegrityDataAsset := createTechnicalAsset(types.Internal, types.Operational, types.Operational)
	taWithArchiveIntegrityDataAsset.DataAssetsProcessed = append(taWithArchiveIntegrityDataAsset.DataAssetsProcessed, daArchiveIntegrity.ID)
	ta[taWithArchiveIntegrityDataAsset.ID] = taWithArchiveIntegrityDataAsset

	parsedModel, err := ParseModel(&mockConfig{}, createInputModel(ta, da), make(types.RiskRules), make(types.RiskRules))

	assert.NoError(t, err)
	assert.Equal(t, types.Critical, parsedModel.TechnicalAssets[taWithCriticalIntegrityDataAsset.ID].Integrity)
	assert.Equal(t, types.Important, parsedModel.TechnicalAssets[taWithImportantIntegrityDataAsset.ID].Integrity)
	assert.Equal(t, types.Operational, parsedModel.TechnicalAssets[taWithArchiveIntegrityDataAsset.ID].Integrity)
}

func TestInferAvailability_NotSet_NoOthers_ExpectTODO(t *testing.T) {
	ta := make(map[string]input.TechnicalAsset)
	da := make(map[string]input.DataAsset)

	_, err := ParseModel(&mockConfig{}, createInputModel(ta, da), make(types.RiskRules), make(types.RiskRules))

	assert.NoError(t, err)
}

func TestInferAvailability_ExpectHighestAvailability(t *testing.T) {
	ta := make(map[string]input.TechnicalAsset)
	da := make(map[string]input.DataAsset)

	daCriticalAvailability := createDataAsset(types.Confidential, types.Critical, types.Critical)
	da[daCriticalAvailability.ID] = daCriticalAvailability

	daImportantAvailability := createDataAsset(types.Restricted, types.Important, types.Important)
	da[daImportantAvailability.ID] = daImportantAvailability

	daArchiveAvailability := createDataAsset(types.Public, types.Archive, types.Archive)
	da[daArchiveAvailability.ID] = daArchiveAvailability

	taWithCriticalAvailabilityDataAsset := createTechnicalAsset(types.Internal, types.Operational, types.Operational)
	taWithCriticalAvailabilityDataAsset.DataAssetsProcessed = append(taWithCriticalAvailabilityDataAsset.DataAssetsProcessed, daCriticalAvailability.ID)
	ta[taWithCriticalAvailabilityDataAsset.ID] = taWithCriticalAvailabilityDataAsset

	taWithImportantAvailabilityDataAsset := createTechnicalAsset(types.Internal, types.Operational, types.Operational)
	taWithImportantAvailabilityDataAsset.DataAssetsProcessed = append(taWithImportantAvailabilityDataAsset.DataAssetsProcessed, daImportantAvailability.ID)
	ta[taWithImportantAvailabilityDataAsset.ID] = taWithImportantAvailabilityDataAsset

	taWithArchiveAvailabilityDataAsset := createTechnicalAsset(types.Internal, types.Operational, types.Operational)
	taWithArchiveAvailabilityDataAsset.DataAssetsProcessed = append(taWithArchiveAvailabilityDataAsset.DataAssetsProcessed, daArchiveAvailability.ID)
	ta[taWithArchiveAvailabilityDataAsset.ID] = taWithArchiveAvailabilityDataAsset

	parsedModel, err := ParseModel(&mockConfig{}, createInputModel(ta, da), make(types.RiskRules), make(types.RiskRules))

	assert.NoError(t, err)
	assert.Equal(t, types.Critical, parsedModel.TechnicalAssets[taWithCriticalAvailabilityDataAsset.ID].Availability)
	assert.Equal(t, types.Important, parsedModel.TechnicalAssets[taWithImportantAvailabilityDataAsset.ID].Availability)
	assert.Equal(t, types.Operational, parsedModel.TechnicalAssets[taWithArchiveAvailabilityDataAsset.ID].Availability)
}

func createInputModel(technicalAssets map[string]input.TechnicalAsset, dataAssets map[string]input.DataAsset) *input.Model {
	return &input.Model{
		TechnicalAssets: technicalAssets,
		DataAssets:      dataAssets,

		// set some dummy values to bypass validation
		BusinessCriticality: "archive",
	}
}

func createTechnicalAsset(confidentiality types.Confidentiality, integrity types.Criticality, availability types.Criticality) input.TechnicalAsset {
	return input.TechnicalAsset{
		ID: uuid.New().String(),
		// those values are required to bypass validation
		Usage:           "business",
		Type:            "process",
		Size:            "system",
		Technology:      "unknown-technology",
		Encryption:      "none",
		Machine:         "virtual",
		Confidentiality: confidentiality.String(),
		Integrity:       integrity.String(),
		Availability:    availability.String(),
	}
}

func createDataAsset(confidentiality types.Confidentiality, integrity types.Criticality, availability types.Criticality) input.DataAsset {
	return input.DataAsset{
		ID:              uuid.New().String(),
		Usage:           "business",
		Quantity:        "few",
		Confidentiality: confidentiality.String(),
		Integrity:       integrity.String(),
		Availability:    availability.String(),
	}
}

type mockConfig struct{}

func (m *mockConfig) GetAppFolder() string {
	return ""
}

func (m *mockConfig) GetTechnologyFilename() string {
	return ""
}

func TestCommunicationLinksOrderedByTitle(t *testing.T) {
	source := createTechnicalAsset(types.Internal, types.Operational, types.Operational)
	target := createTechnicalAsset(types.Internal, types.Operational, types.Operational)
	titles := []string{"hotel", "charlie", "foxtrot", "alpha", "golf", "echo", "bravo", "delta"}
	source.CommunicationLinks = make(map[string]input.CommunicationLink)
	for _, title := range titles {
		source.CommunicationLinks[title] = input.CommunicationLink{
			Target:         target.ID,
			Protocol:       "https",
			Authentication: "none",
			Authorization:  "none",
			Usage:          "business",
		}
	}
	ta := map[string]input.TechnicalAsset{"source": source, "target": target}

	parsedModel, err := ParseModel(&mockConfig{}, createInputModel(ta, make(map[string]input.DataAsset)), make(types.RiskRules), make(types.RiskRules))

	assert.NoError(t, err)
	sorted := slices.Sorted(slices.Values(titles))
	outgoing := make([]string, 0, len(titles))
	for _, link := range parsedModel.TechnicalAssets[source.ID].CommunicationLinks {
		outgoing = append(outgoing, link.Title)
	}
	assert.Equal(t, sorted, outgoing)
	incoming := make([]string, 0, len(titles))
	for _, link := range parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[target.ID] {
		incoming = append(incoming, link.Title)
	}
	assert.Equal(t, sorted, incoming)
}

// viaModel has a client whose link to a web server passes through a load balancer and a WAF
// (threagile#15); the load balancer also has a link of its own titled like the one of the client.
func viaModel(via ...string) *input.Model {
	asset := func(id string) input.TechnicalAsset {
		asset := createTechnicalAsset(types.Internal, types.Operational, types.Operational)
		asset.ID = id
		return asset
	}
	client := asset("client")
	client.CommunicationLinks = map[string]input.CommunicationLink{
		"Customer Traffic": {
			Target:                 "web-server",
			Via:                    via,
			Description:            "Customer requests",
			Protocol:               "https",
			Authentication:         "token",
			Authorization:          "end-user-identity-propagation",
			Usage:                  "business",
			Tags:                   []string{"edge"},
			VPN:                    true,
			IpFiltered:             true,
			Readonly:               true,
			DataAssetsSent:         []string{"orders"},
			DataAssetsReceived:     []string{"pages"},
			DiagramTweakWeight:     3,
			DiagramTweakConstraint: true,
		},
	}
	loadBalancer := asset("load-balancer")
	loadBalancer.CommunicationLinks = map[string]input.CommunicationLink{
		"Customer Traffic": {
			Target:         "web-server",
			Protocol:       "http",
			Authentication: "none",
			Authorization:  "none",
			Usage:          "devops",
		},
	}
	outOfScopeProxy := asset("cdn")
	outOfScopeProxy.OutOfScope = true

	data := func(id string) input.DataAsset {
		asset := createDataAsset(types.Internal, types.Operational, types.Operational)
		asset.ID = id
		return asset
	}
	model := createInputModel(
		map[string]input.TechnicalAsset{
			"Client":        client,
			"Load Balancer": loadBalancer,
			"WAF":           asset("waf"),
			"Web Server":    asset("web-server"),
			"CDN":           outOfScopeProxy,
		},
		map[string]input.DataAsset{"Orders": data("orders"), "Pages": data("pages")},
	)
	model.TagsAvailable = []string{"edge"}
	return model
}

func TestViaExpandsLinkIntoHops(t *testing.T) {
	parsedModel, err := ParseModel(&mockConfig{}, viaModel("load-balancer", "waf"), make(types.RiskRules), make(types.RiskRules))
	require.NoError(t, err)

	assert.NotContains(t, parsedModel.CommunicationLinks, "client>customer-traffic")
	type hop struct{ id, title, source, target string }
	expected := []hop{
		{"client>customer-traffic>load-balancer", "Customer Traffic (hop 1 of 3)", "client", "load-balancer"},
		{"client>customer-traffic>waf", "Customer Traffic (hop 2 of 3)", "load-balancer", "waf"},
		{"client>customer-traffic>web-server", "Customer Traffic (hop 3 of 3)", "waf", "web-server"},
	}
	for _, want := range expected {
		link := parsedModel.CommunicationLinks[want.id]
		require.NotNil(t, link, want.id)
		assert.Equal(t, want, hop{link.Id, link.Title, link.SourceId, link.TargetId})

		// the source owns the hop, and the target sees it coming in
		assert.Contains(t, parsedModel.TechnicalAssets[want.source].CommunicationLinks, link)
		assert.Contains(t, parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[want.target], link)
		assert.Subset(t, parsedModel.TechnicalAssets[want.source].DataAssetsProcessed, []string{"orders", "pages"})
		assert.Subset(t, parsedModel.TechnicalAssets[want.target].DataAssetsProcessed, []string{"orders", "pages"})

		assert.Equal(t, "Customer requests", link.Description)
		assert.Equal(t, types.HTTPS, link.Protocol)
		assert.Equal(t, types.Token, link.Authentication)
		assert.Equal(t, types.EndUserIdentityPropagation, link.Authorization)
		assert.Equal(t, types.Business, link.Usage)
		assert.Equal(t, []string{"edge"}, link.Tags)
		assert.True(t, link.VPN)
		assert.True(t, link.IpFiltered)
		assert.True(t, link.Readonly)
		assert.Equal(t, []string{"orders"}, link.DataAssetsSent)
		assert.Equal(t, []string{"pages"}, link.DataAssetsReceived)
		assert.Equal(t, 3, link.DiagramTweakWeight)
		assert.False(t, link.DiagramTweakConstraint)
	}
	assert.Len(t, parsedModel.TechnicalAssets["client"].CommunicationLinks, 1)
	assert.Len(t, parsedModel.TechnicalAssets["waf"].CommunicationLinks, 1)

	// the modelled link of the load balancer keeps its id, and its links stay ordered by title
	loadBalancerLinks := parsedModel.TechnicalAssets["load-balancer"].CommunicationLinks
	titles := make([]string, 0, len(loadBalancerLinks))
	for _, link := range loadBalancerLinks {
		titles = append(titles, link.Title)
	}
	assert.Equal(t, []string{"Customer Traffic", "Customer Traffic (hop 2 of 3)"}, titles)
	assert.Equal(t, types.HTTP, parsedModel.CommunicationLinks["load-balancer>customer-traffic"].Protocol)

	// the hops do not share their lists
	parsedModel.CommunicationLinks["client>customer-traffic>waf"].Tags[0] = "changed"
	assert.Equal(t, []string{"edge"}, parsedModel.CommunicationLinks["client>customer-traffic>web-server"].Tags)
}

func TestViaAllowsOutOfScopeProxy(t *testing.T) {
	parsedModel, err := ParseModel(&mockConfig{}, viaModel("cdn"), make(types.RiskRules), make(types.RiskRules))
	require.NoError(t, err)

	assert.Equal(t, "cdn", parsedModel.CommunicationLinks["client>customer-traffic>web-server"].SourceId)
	assert.Equal(t, "cdn", parsedModel.CommunicationLinks["client>customer-traffic>cdn"].TargetId)
}

func TestViaRejectsInvalidProxies(t *testing.T) {
	tests := map[string]struct {
		via   []string
		error string
	}{
		"unknown asset": {[]string{"load-balancer", "proxy"}, `missing technical asset "proxy" in 'via'`},
		"source":        {[]string{"client"}, `lists its source "client"`},
		"target":        {[]string{"waf", "web-server"}, `lists its target "web-server"`},
		"repeated":      {[]string{"waf", "load-balancer", "waf"}, `lists "waf" more than once`},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseModel(&mockConfig{}, viaModel(test.via...), make(types.RiskRules), make(types.RiskRules))
			require.ErrorContains(t, err, test.error)
			assert.ErrorContains(t, err, `communication link "Customer Traffic" of technical asset "Client"`)
		})
	}
}
