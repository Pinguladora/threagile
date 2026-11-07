package model

import (
	"testing"

	"github.com/Pinguladora/threagile/pkg/input"
	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// accessModel has a link from a client to a server with each of the identities and authorizations.
func accessModel(links map[string]input.CommunicationLink) *input.Model {
	client, server := createTechnicalAsset(), createTechnicalAsset()
	client.ID, server.ID = "client", "server"
	client.CommunicationLinks = make(map[string]input.CommunicationLink)
	for title, link := range links {
		link.Target, link.Protocol, link.Authentication, link.Usage = "server", "https", "none", "business"
		client.CommunicationLinks[title] = link
	}
	return createInputModel(map[string]input.TechnicalAsset{"Client": client, "Server": server},
		make(map[string]input.DataAsset))
}

func TestConvertLegacyIdentitiesMovesIdentityOutOfAuthorization(t *testing.T) {
	model := accessModel(map[string]input.CommunicationLink{
		"Legacy Technical User": {Authorization: "technical-user"},
		"Legacy End User":       {Authorization: "enduser-identity-propagation"},
		"Legacy None":           {Authorization: "none"},
		"Current":               {Identity: "workload", Authorization: "none"},
		"Granularity Only":      {Authorization: "object-level"},
		"Nothing":               {},
	})

	assert.Equal(t, 3, ConvertLegacyIdentities(model))

	type access struct{ identity, authorization string }
	got := make(map[string]access)
	for title, link := range model.TechnicalAssets["Client"].CommunicationLinks {
		got[title] = access{link.Identity, link.Authorization}
	}
	assert.Equal(t, map[string]access{
		"Legacy Technical User": {"service-account", ""},
		"Legacy End User":       {"end-user", ""},
		"Legacy None":           {"none", ""},
		"Current":               {"workload", "none"},
		"Granularity Only":      {"", "object-level"},
		"Nothing":               {"", ""},
	}, got)
	assert.Zero(t, ConvertLegacyIdentities(model), "converting twice changes nothing")
}

func TestParseReadsIdentityAndAuthorization(t *testing.T) {
	model := accessModel(map[string]input.CommunicationLink{
		"Legacy":  {Authorization: "technical-user"},
		"Current": {Identity: "end-user", Authorization: "object-level"},
		"Nothing": {},
	})

	parsedModel, err := ParseModel(&mockConfig{}, model, make(types.RiskRules), make(types.RiskRules))
	require.NoError(t, err)

	type access struct {
		identity      types.Identity
		authorization types.Authorization
	}
	got := make(map[string]access)
	for _, link := range parsedModel.TechnicalAssets["client"].CommunicationLinks {
		got[link.Title] = access{link.Identity, link.Authorization}
	}
	assert.Equal(t, map[string]access{
		"Legacy":  {types.ServiceAccount, types.UnknownAuthorization},
		"Current": {types.EndUser, types.ObjectLevel},
		"Nothing": {types.NoneIdentity, types.UnknownAuthorization},
	}, got)
}

func TestParseRejectsIdentityInAuthorizationNextToIdentity(t *testing.T) {
	model := accessModel(map[string]input.CommunicationLink{
		"Mixed": {Identity: "end-user", Authorization: "technical-user"},
	})

	_, err := ParseModel(&mockConfig{}, model, make(types.RiskRules), make(types.RiskRules))

	require.Error(t, err)
	assert.Contains(t, err.Error(), `'authorization' value "technical-user" is an identity, move it into 'identity'`)
}

func TestParseReadsAccount(t *testing.T) {
	model := accessModel(map[string]input.CommunicationLink{
		"Service Account": {Identity: "service-account", Account: " erp-sync "},
		"Workload":        {Identity: "workload", Account: "orders-role"},
		"No Account":      {Identity: "service-account"},
	})

	parsedModel, err := ParseModel(&mockConfig{}, model, make(types.RiskRules), make(types.RiskRules))
	require.NoError(t, err)

	got := make(map[string]string)
	for _, link := range parsedModel.TechnicalAssets["client"].CommunicationLinks {
		got[link.Title] = link.Account
	}
	assert.Equal(t, map[string]string{
		"Service Account": "erp-sync",
		"Workload":        "orders-role",
		"No Account":      "",
	}, got)
}

func TestParseRejectsAccountOfOtherIdentities(t *testing.T) {
	for _, identity := range []string{"", "none", "end-user"} {
		model := accessModel(map[string]input.CommunicationLink{
			"Link": {Identity: identity, Account: "shared"},
		})

		_, err := ParseModel(&mockConfig{}, model, make(types.RiskRules), make(types.RiskRules))

		require.Error(t, err, identity)
		assert.Contains(t, err.Error(), `'account' "shared" needs the identity service-account or workload`, identity)
	}
}

func TestParseReadsNetworkPolicies(t *testing.T) {
	model := accessModel(map[string]input.CommunicationLink{"Link": {Identity: "workload"}})
	model.TrustBoundaries = map[string]input.TrustBoundary{
		"Orders": {
			ID: "orders", Type: "execution-environment", NetworkPolicy: " ingress ",
			TechnicalAssetsInside: []string{"server"},
		},
		"Legacy": {ID: "legacy", Type: "execution-environment", TechnicalAssetsInside: []string{"client"}},
	}

	parsedModel, err := ParseModel(&mockConfig{}, model, make(types.RiskRules), make(types.RiskRules))
	require.NoError(t, err)

	assert.Equal(t, types.IngressNetworkPolicy, parsedModel.TrustBoundaries["orders"].NetworkPolicy)
	assert.Equal(t, types.UnknownNetworkPolicy, parsedModel.TrustBoundaries["legacy"].NetworkPolicy, "not modelled")
}

func TestParseRejectsNetworkPolicyOutsideNamespaces(t *testing.T) {
	for boundaryType, message := range map[string]string{
		"network-on-prem":       "needs the type execution-environment, not network-on-prem",
		"execution-environment": "unknown 'network_policy'",
	} {
		model := accessModel(map[string]input.CommunicationLink{"Link": {Identity: "workload"}})
		policy := "none"
		if boundaryType == "execution-environment" {
			policy = "allow-all"
		}
		model.TrustBoundaries = map[string]input.TrustBoundary{
			"Boundary": {ID: "boundary", Type: boundaryType, NetworkPolicy: policy},
		}

		_, err := ParseModel(&mockConfig{}, model, make(types.RiskRules), make(types.RiskRules))

		require.Error(t, err, boundaryType)
		assert.Contains(t, err.Error(), message, boundaryType)
	}
}

func TestParseReadsPrivileged(t *testing.T) {
	model := accessModel(map[string]input.CommunicationLink{"Link": {Identity: "workload"}})
	server := model.TechnicalAssets["Server"]
	server.Privileged = true
	model.TechnicalAssets["Server"] = server

	parsedModel, err := ParseModel(&mockConfig{}, model, make(types.RiskRules), make(types.RiskRules))
	require.NoError(t, err)

	assert.True(t, parsedModel.TechnicalAssets["server"].Privileged)
	assert.False(t, parsedModel.TechnicalAssets["client"].Privileged)
}
