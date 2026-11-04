package risks_test

import (
	"maps"
	"slices"
	"testing"

	"github.com/Pinguladora/threagile/internal/threagile"
	"github.com/Pinguladora/threagile/pkg/input"
	"github.com/Pinguladora/threagile/pkg/model"
	"github.com/Pinguladora/threagile/pkg/risks"
	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestViaLinksEndToEnd analyzes a shop whose customer traffic passes through a load balancer and a
// WAF, modelled with a via list (threagile#15), with all built-in rules, and checks that the rules
// see the hops as links of their own.
func TestViaLinksEndToEnd(t *testing.T) {
	parsedModel := analyzeViaModel(t, func(*input.Model) {})

	hops := map[string][2]string{
		"customer-browser>shop-traffic>load-balancer": {"customer-browser", "load-balancer"},
		"customer-browser>shop-traffic>waf":           {"load-balancer", "waf"},
		"customer-browser>shop-traffic>shop-server":   {"waf", "shop-server"},
	}
	for id, ends := range hops {
		link := parsedModel.CommunicationLinks[id]
		require.NotNil(t, link, id)
		assert.Equal(t, ends, [2]string{link.SourceId, link.TargetId}, id)
	}
	assert.NotContains(t, parsedModel.CommunicationLinks, "customer-browser>shop-traffic")

	expected := map[string][]string{
		// the shop is reached only from the WAF, while the status page is reached directly
		"missing-waf": {"missing-waf@status-page"},
		// the hop that leaves the WAF is a link of the WAF
		"server-side-request-forgery": {"server-side-request-forgery@waf@shop-server@customer-browser>shop-traffic>shop-server"},
		// the customers reach the load balancer across a network trust boundary
		"dos-risky-access-across-trust-boundary": {
			"dos-risky-access-across-trust-boundary@load-balancer@customer-browser@customer-browser>shop-traffic>load-balancer->",
		},
	}
	for category, expectedIds := range expected {
		t.Run(category, func(t *testing.T) {
			got := make(map[string]bool)
			for _, risk := range parsedModel.GeneratedRisksByCategory[category] {
				got[risk.SyntheticId] = true
			}
			assert.Equal(t, expectedIds, slices.Sorted(maps.Keys(got)))
		})
	}

	// risk tracking finds a risk of a hop by the id of the hop
	ssrf := parsedModel.GeneratedRisksBySyntheticId["server-side-request-forgery@waf@shop-server@customer-browser>shop-traffic>shop-server"]
	require.NotNil(t, ssrf)
	assert.Equal(t, types.Accepted, parsedModel.GetRiskTrackingWithDefault(ssrf).Status)

	// without the via list the customers reach the shop directly, and it misses a WAF too
	t.Run("without via", func(t *testing.T) {
		withoutVia := analyzeViaModel(t, func(modelInput *input.Model) {
			browser := modelInput.TechnicalAssets["Customer Browser"]
			link := browser.CommunicationLinks["Shop Traffic"]
			require.NotEmpty(t, link.Via)
			link.Via = nil
			browser.CommunicationLinks["Shop Traffic"] = link
			// the tracked risk of a hop is gone with the hops
			modelInput.RiskTracking = nil
		})

		missingWaf := withoutVia.GeneratedRisksByCategory["missing-waf"]
		got := make([]string, 0, len(missingWaf))
		for _, risk := range missingWaf {
			got = append(got, risk.SyntheticId)
		}
		assert.ElementsMatch(t, []string{"missing-waf@shop-server", "missing-waf@status-page"}, got)
	})
}

// analyzeViaModel analyzes the model with the via list, after edit changes it.
func analyzeViaModel(t *testing.T, edit func(*input.Model)) *types.Model {
	t.Helper()
	config := new(threagile.Config).Defaults("")
	config.SetAppFolder(t.TempDir())
	config.SetPluginFolder(t.TempDir())
	config.SetOutputFolder(t.TempDir())
	config.SetTempFolder(t.TempDir())

	modelInput := new(input.Model).Defaults()
	require.NoError(t, modelInput.Load("testdata/via-links/threagile.yaml"))
	edit(modelInput)

	result, err := model.AnalyzeModel(modelInput, config, risks.GetBuiltInRiskRules(), make(types.RiskRules), testReporter{t})
	require.NoError(t, err)
	return result.ParsedModel
}
