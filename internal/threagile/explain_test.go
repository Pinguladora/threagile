package threagile

import (
	"strings"
	"testing"

	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
)

// explainingRule is a risk rule that explains its risks.
type explainingRule struct {
	types.RiskRule
}

func (explainingRule) ExplainRisk(_ *types.Model, syntheticRiskId string) []string {
	return []string{"found at " + syntheticRiskId}
}

func TestExplainRiskLines(t *testing.T) {
	risk := &types.Risk{
		CategoryId:                      "some-rule",
		SyntheticId:                     "some-rule@web-server",
		Title:                           "<b>Some Risk</b> at <b>Web Server</b> &amp; more",
		Severity:                        types.HighSeverity,
		ExploitationLikelihood:          types.Likely,
		ExploitationImpact:              types.HighImpact,
		MostRelevantTechnicalAssetId:    "web-server",
		MostRelevantCommunicationLinkId: "web-server>database",
		DataBreachProbability:           types.Possible,
		DataBreachTechnicalAssetIDs:     []string{"web-server", "database"},
	}
	explainModel := &types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{"web-server": {Id: "web-server", Title: "Web Server"}},
		CommunicationLinks: map[string]*types.CommunicationLink{
			"web-server>database": {Id: "web-server>database", Title: "Database Access"},
		},
		CustomRiskCategories: types.RiskCategories{{
			ID: "some-rule", Title: "Some Rule", STRIDE: types.Tampering, CWE: 89,
			References:     []string{"Some Catalog 1"},
			DetectionLogic: "Assets with <i>something</i>.",
		}},
		RiskTracking: map[string]*types.RiskTracking{
			"some-rule@web-server": {Status: types.Accepted, Justification: "Tolerable"},
		},
	}

	lines := strings.Join(explainRiskLines(explainModel, types.RiskRules{"some-rule": explainingRule{}}, risk), "\n")

	for _, want := range []string{
		"Risk some-rule@web-server: Some Risk at Web Server & more",
		"Severity: high (exploitation likelihood likely, impact high)",
		"Status: accepted",
		"Justification: Tolerable",
		"Technical asset: Web Server (web-server)",
		"Communication link: Database Access (web-server>database)",
		"Data breach: possible, at web-server, database",
		"Category: Some Rule (some-rule), Tampering, CWE-89",
		"References: Some Catalog 1",
		"Detection logic: Assets with something.",
		"Explanation:\n    found at some-rule@web-server",
	} {
		assert.Contains(t, lines, want)
	}
}
