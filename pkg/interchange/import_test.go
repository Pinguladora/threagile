package interchange_test

import (
	"strings"
	"testing"

	"github.com/Pinguladora/threagile/internal/threagile"
	"github.com/Pinguladora/threagile/pkg/input"
	"github.com/Pinguladora/threagile/pkg/interchange"
	"github.com/Pinguladora/threagile/pkg/model"
	"github.com/Pinguladora/threagile/pkg/risks"
	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// foreignModel is what a model from another tool looks like: no threagile properties, ids and
// types that threagile does not know, and elements that threagile cannot express.
func foreignModel() *interchange.Model {
	return &interchange.Model{
		Project: interchange.Project{ID: "shop", Name: "Shop", Owner: "Shop Team", Tags: []string{"shop"}},
		Zones: []interchange.Zone{
			{ID: "internet", Name: "Internet", Type: "internet"},
			{ID: "dmz", Name: "DMZ", Type: "network-virtual-lan", ParentID: "internet"},
			{ID: "in-app", Name: "Inside the app", ParentID: "web"},
		},
		Components: []interchange.Component{
			{ID: "web", Name: "Web", Type: "web-server", ParentID: "dmz", Tags: []string{"nginx", " "}, Processed: []string{"orders"}},
			{ID: "web/module", Name: "Web", Type: "CD-V2-WEB-MODULE", ParentID: "web"},
			{ID: "db", Name: "Database", Type: "database", ParentID: "unknown", Stored: []string{"orders", "missing"}},
		},
		Flows: []interchange.Flow{
			{ID: "f1", Name: "Queries", SourceID: "web", DestinationID: "db", Bidirectional: true, DataAssets: []string{"orders"}},
			{ID: "f2", Name: "queries", SourceID: "web", DestinationID: "db"},
			{ID: "f3", Name: "To a zone", SourceID: "web", DestinationID: "dmz"},
		},
		DataAssets: []interchange.DataAsset{
			{ID: "orders", Name: "Orders", Confidentiality: types.Confidential, Integrity: types.Critical, Availability: types.Important},
		},
		Threats: []interchange.Threat{{ID: "t1", Name: "Not imported"}},
	}
}

func TestToInputAppliesDefaults(t *testing.T) {
	result, notes := interchange.ToInput(foreignModel(), technologies(t))

	assert.Equal(t, "Shop", result.Title)
	assert.Equal(t, "Shop Team", result.Author.Name)
	assert.Equal(t, interchange.DefaultBusinessCriticality, result.BusinessCriticality)
	assert.Equal(t, []string{"nginx", "shop"}, result.TagsAvailable, "the model declares every tag it uses")

	internet := result.TrustBoundaries["Internet"]
	assert.Equal(t, interchange.DefaultTrustBoundaryType, internet.Type, "a zone type threagile does not know")
	assert.Equal(t, []string{"dmz"}, internet.TrustBoundariesNested)
	assert.Equal(t, "network-virtual-lan", result.TrustBoundaries["DMZ"].Type)
	assert.Equal(t, []string{"web", "web-module"}, result.TrustBoundaries["DMZ"].TechnicalAssetsInside,
		"a component nested in a component goes into the trust boundary of that one")
	assert.Empty(t, result.TrustBoundaries["Inside the app"].TrustBoundariesNested)

	web := result.TechnicalAssets["Web"]
	assert.Equal(t, "web-server", web.Technology)
	assert.Equal(t, []string{"nginx"}, web.Tags)
	assert.Equal(t, interchange.DefaultTechnicalAssetType, web.Type)
	assert.Equal(t, interchange.DefaultConfidentiality, web.Confidentiality)
	assert.Equal(t, interchange.DefaultCriticality, web.Availability)

	module := result.TechnicalAssets["Web (web/module)"]
	assert.Equal(t, "web-module", module.ID, "an id threagile does not accept")
	assert.Equal(t, interchange.DefaultTechnology, module.Technology)

	assert.Equal(t, []string{"orders"}, result.TechnicalAssets["Database"].DataAssetsStored)

	require.Len(t, web.CommunicationLinks, 2, "the flow to a zone is left out")
	queries := web.CommunicationLinks["Queries"]
	assert.Equal(t, "db", queries.Target)
	assert.Equal(t, []string{"orders"}, queries.DataAssetsSent)
	assert.Equal(t, []string{"orders"}, queries.DataAssetsReceived, "a bidirectional flow receives its data assets back")
	assert.Equal(t, interchange.DefaultProtocol, queries.Protocol)
	assert.Equal(t, interchange.DefaultAuthentication, queries.Authentication)
	assert.Equal(t, interchange.DefaultIdentity, queries.Identity)
	assert.Equal(t, interchange.DefaultAuthorization, queries.Authorization)
	assert.Contains(t, web.CommunicationLinks, "queries (f2)", "link names need to differ in more than case")

	orders := result.DataAssets["Orders"]
	assert.Equal(t, "confidential", orders.Confidentiality)
	assert.Equal(t, "important", orders.Availability)
	assert.Equal(t, interchange.DefaultQuantity, orders.Quantity)

	for _, want := range []string{
		`trust zone "in-app": its parent "web" is no trust zone, imported as a top-level trust boundary`,
		`component "web/module": threagile ids take letters, digits and hyphens only, imported as "web-module"`,
		`component "web/module": type "CD-V2-WEB-MODULE" is no threagile technology, imported as unknown-technology`,
		`component "web/module": is nested in component "web"`,
		`component "db": its parent "unknown" is unknown, imported outside of all trust boundaries`,
		`component "db": data asset "missing" is unknown, left out`,
		`dataflow "f3": leads from "web" to "dmz", but threagile only links components, left out`,
		`trust zone "internet": type "internet" is unknown to threagile, imported as network-on-prem`,
	} {
		assert.True(t, containsPrefix(notes, want), "want a note %q, got %q", want, notes)
	}

	analyzeInput(t, result)
}

func TestToInputKeepsTheProperties(t *testing.T) {
	parsedModel := analyze(t, exampleModelFile)
	result, notes := interchange.ToInput(interchange.FromModel(parsedModel), technologies(t))
	assert.Empty(t, notes, "a threagile model needs no defaults")

	reimported := analyzeInput(t, result)
	for id, asset := range parsedModel.TechnicalAssets {
		again := reimported.TechnicalAssets[id]
		require.NotNil(t, again, id)
		assert.Equal(t, asset.Title, again.Title, id)
		assert.Equal(t, asset.Type, again.Type, id)
		assert.Equal(t, asset.Machine, again.Machine, id)
		assert.Equal(t, asset.Technologies, again.Technologies, id)
		assert.Equal(t, asset.Confidentiality, again.Confidentiality, id)
		assert.Equal(t, asset.OutOfScope, again.OutOfScope, id)
		assert.Equal(t, asset.DataFormatsAccepted, again.DataFormatsAccepted, id)
	}

	for id, link := range parsedModel.CommunicationLinks {
		again := reimported.CommunicationLinks[id]
		require.NotNil(t, again, id)
		assert.Equal(t, link.Protocol, again.Protocol, id)
		assert.Equal(t, link.Authentication, again.Authentication, id)
		assert.ElementsMatch(t, link.DataAssetsSent, again.DataAssetsSent, id)
		assert.ElementsMatch(t, link.DataAssetsReceived, again.DataAssetsReceived, id)
	}
}

func TestDefaultsAreThreagileValues(t *testing.T) {
	for _, check := range []struct {
		value string
		parse func(string) error
	}{
		{interchange.DefaultBusinessCriticality, func(v string) error { _, err := types.ParseCriticality(v); return err }},
		{interchange.DefaultTrustBoundaryType, func(v string) error { _, err := types.ParseTrustBoundary(v); return err }},
		{interchange.DefaultTechnicalAssetType, func(v string) error { _, err := types.ParseTechnicalAssetType(v); return err }},
		{interchange.DefaultSize, func(v string) error { _, err := types.ParseTechnicalAssetSize(v); return err }},
		{interchange.DefaultMachine, func(v string) error { _, err := types.ParseTechnicalAssetMachine(v); return err }},
		{interchange.DefaultEncryption, func(v string) error { _, err := types.ParseEncryptionStyle(v); return err }},
		{interchange.DefaultUsage, func(v string) error { _, err := types.ParseUsage(v); return err }},
		{interchange.DefaultConfidentiality, func(v string) error { _, err := types.ParseConfidentiality(v); return err }},
		{interchange.DefaultCriticality, func(v string) error { _, err := types.ParseCriticality(v); return err }},
		{interchange.DefaultProtocol, func(v string) error { _, err := types.ParseProtocol(v); return err }},
		{interchange.DefaultAuthentication, func(v string) error { _, err := types.ParseAuthentication(v); return err }},
		{interchange.DefaultIdentity, func(v string) error { _, err := types.ParseIdentity(v); return err }},
		{interchange.DefaultAuthorization, func(v string) error { _, err := types.ParseAuthorization(v); return err }},
		{interchange.DefaultQuantity, func(v string) error { _, err := types.ParseQuantity(v); return err }},
	} {
		assert.NoError(t, check.parse(check.value), check.value)
	}

	assert.NotNil(t, technologies(t).Get(interchange.DefaultTechnology))
}

// TestToInputReadsIdentityFromLegacyAuthorization imports flows exported by earlier versions of threagile, whose
// authorization holds their identity, next to a flow with both.
func TestToInputReadsIdentityFromLegacyAuthorization(t *testing.T) {
	elements := foreignModel()
	elements.Flows = []interchange.Flow{
		{
			ID: "f1", Name: "Legacy", SourceID: "web", DestinationID: "db",
			Properties: interchange.Properties{"authorization": "technical-user"},
		},
		{
			ID: "f2", Name: "Current", SourceID: "web", DestinationID: "db",
			Properties: interchange.Properties{"identity": "end-user", "authorization": "object-level"},
		},
	}

	result, _ := interchange.ToInput(elements, technologies(t))

	links := result.TechnicalAssets["Web"].CommunicationLinks
	assert.Equal(t, "service-account", links["Legacy"].Identity)
	assert.Equal(t, interchange.DefaultAuthorization, links["Legacy"].Authorization)
	assert.Equal(t, "end-user", links["Current"].Identity)
	assert.Equal(t, "object-level", links["Current"].Authorization)
}

// TestToInputReadsAccount imports the account of flows, and drops the account of a flow whose identity has none.
func TestToInputReadsAccount(t *testing.T) {
	elements := foreignModel()
	elements.Flows = []interchange.Flow{
		{
			ID: "f1", Name: "Service Account", SourceID: "web", DestinationID: "db",
			Properties: interchange.Properties{"identity": "service-account", "account": "erp-sync"},
		},
		{
			ID: "f2", Name: "End User", SourceID: "web", DestinationID: "db",
			Properties: interchange.Properties{"identity": "end-user", "account": "user-42"},
		},
	}

	result, notes := interchange.ToInput(elements, technologies(t))

	links := result.TechnicalAssets["Web"].CommunicationLinks
	assert.Equal(t, "erp-sync", links["Service Account"].Account)
	assert.Empty(t, links["End User"].Account)
	assert.Contains(t, strings.Join(notes, "\n"), `account "user-42" of a flow with the identity end-user is dropped`)
}

func technologies(t *testing.T) types.TechnologyMap {
	t.Helper()
	result := make(types.TechnologyMap)
	require.NoError(t, result.LoadDefault())
	result.PropagateAttributes()
	return result
}

// analyzeInput analyzes the model the way analyze-model does after reading it.
func analyzeInput(t *testing.T, modelInput *input.Model) *types.Model {
	t.Helper()
	config := new(threagile.Config).Defaults("")
	config.SetAppFolder(t.TempDir())
	config.SetTempFolder(t.TempDir())

	result, err := model.AnalyzeModel(modelInput, config, risks.GetBuiltInRiskRules(), nil, testReporter{t})
	require.NoError(t, err)
	return result.ParsedModel
}

func containsPrefix(notes []string, prefix string) bool {
	for _, note := range notes {
		if len(note) >= len(prefix) && note[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
