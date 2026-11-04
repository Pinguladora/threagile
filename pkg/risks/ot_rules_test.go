package risks_test

import (
	"testing"

	"github.com/Pinguladora/threagile/internal/threagile"
	"github.com/Pinguladora/threagile/pkg/model"
	"github.com/Pinguladora/threagile/pkg/risks"
	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOTRulesEndToEnd analyzes a small plant with all built-in rules and checks the risks of the OT rules. The
// model also holds what the rules must skip: an office reaching the plant through a historian and a jump server
// in the industrial DMZ, a write over a secure protocol, readonly links, and a dedicated safety engineering
// workstation. The authentication rules leave the links over insecure control protocols to the OT rules.
func TestOTRulesEndToEnd(t *testing.T) {
	config := new(threagile.Config).Defaults("")
	config.SetAppFolder(t.TempDir())
	config.SetPluginFolder(t.TempDir())
	config.SetInputFile("testdata/ot-rules/threagile.yaml")
	config.SetOutputFolder(t.TempDir())
	config.SetTempFolder(t.TempDir())

	result, err := model.ReadAndAnalyzeModel(config, risks.GetBuiltInRiskRules(), testReporter{t})
	require.NoError(t, err)

	type expectedRisk struct {
		likelihood types.RiskExploitationLikelihood
		impact     types.RiskExploitationImpact
		severity   types.RiskSeverity
	}
	expected := map[string]map[string]expectedRisk{
		"direct-it-ot-communication": {
			"direct-it-ot-communication@plc-a@vendor>vendor-write": {types.VeryLikely, types.HighImpact, types.HighSeverity},
		},
		"insecure-control-protocol": {
			"insecure-control-protocol@plc-a@vendor>vendor-write":  {types.VeryLikely, types.HighImpact, types.HighSeverity},
			"insecure-control-protocol@plc-a@shared-ews>program-a": {types.Unlikely, types.HighImpact, types.MediumSeverity},
			"insecure-control-protocol@plc-b@scada>write-b":        {types.Unlikely, types.HighImpact, types.MediumSeverity},
			// PLC A reaches IT, which makes its commands to the valve likely to be forged
			"insecure-control-protocol@valve@plc-a>actuate": {types.Likely, types.HighImpact, types.ElevatedSeverity},
			"insecure-control-protocol@sis@shared-ews>program-sis": {
				types.Unlikely, types.VeryHighImpact, types.ElevatedSeverity,
			},
			"insecure-control-protocol@sis@safety-ews>program-sis-dedicated": {
				types.Unlikely, types.VeryHighImpact, types.ElevatedSeverity,
			},
		},
		"missing-safety-system-independence": {
			"missing-safety-system-independence@sis@shared-ews>program-sis": {
				types.Unlikely, types.VeryHighImpact, types.ElevatedSeverity,
			},
		},
	}

	for category, expectedRisks := range expected {
		t.Run(category, func(t *testing.T) {
			got := make(map[string]expectedRisk)
			for _, risk := range result.ParsedModel.GeneratedRisksByCategory[category] {
				got[risk.SyntheticId] = expectedRisk{risk.ExploitationLikelihood, risk.ExploitationImpact, risk.Severity}
			}
			assert.Equal(t, expectedRisks, got)
		})
	}

	for _, category := range []string{"missing-authentication", "missing-authentication-second-factor"} {
		for _, risk := range result.ParsedModel.GeneratedRisksByCategory[category] {
			link := result.ParsedModel.CommunicationLinks[risk.MostRelevantCommunicationLinkId]
			assert.False(t, link.Protocol.IsInsecureIndustrialControlProtocol(), risk.SyntheticId)
		}
	}
}
