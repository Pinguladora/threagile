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
