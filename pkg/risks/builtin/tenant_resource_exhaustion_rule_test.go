package builtin

import (
	"testing"

	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTenantResourceExhaustionRule(t *testing.T) {
	for name, test := range map[string]struct {
		callerOutOfScope bool
		callerBoundary   string
		multiTenant      bool
		readonly         bool
		devops           bool
		availability     types.Criticality
		dataIntegrity    types.Criticality
		risky            bool
		impact           types.RiskExploitationImpact
	}{
		"out-of-scope caller in the same boundary": {
			callerOutOfScope: true, callerBoundary: "host", multiTenant: true,
			availability: types.Important, dataIntegrity: types.MissionCritical, risky: true, impact: types.HighImpact,
		},
		"in-scope caller in another boundary": {
			callerBoundary: "guest", multiTenant: true,
			availability: types.Critical, dataIntegrity: types.Operational, risky: true, impact: types.MediumImpact,
		},
		"caller outside any boundary": {
			multiTenant: true, availability: types.Important, dataIntegrity: types.Important, risky: true, impact: types.LowImpact,
		},
		"in-scope caller in the same boundary": {callerBoundary: "host", multiTenant: true},
		"single tenant":                        {callerOutOfScope: true, callerBoundary: "guest"},
		"devops link":                          {callerOutOfScope: true, callerBoundary: "guest", multiTenant: true, devops: true},
		"read-only link": {
			callerOutOfScope: true, callerBoundary: "guest", multiTenant: true, readonly: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			link := &types.CommunicationLink{
				Id: "tenant>send", Title: "Send", SourceId: "tenant", TargetId: "collector", Readonly: test.readonly,
				DataAssetsSent: []string{"records"},
			}
			if test.devops {
				link.Usage = types.DevOps
			}
			model := &types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"collector": {
						Id: "collector", Title: "Collector", MultiTenant: test.multiTenant,
						Availability: test.availability,
					},
					"tenant": {Id: "tenant", Title: "Tenant", OutOfScope: test.callerOutOfScope},
				},
				DataAssets: map[string]*types.DataAsset{
					"records": {Id: "records", Integrity: test.dataIntegrity},
				},
				IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
					"collector": {link},
				},
				TrustBoundaries: map[string]*types.TrustBoundary{"host": {Id: "host"}, "guest": {Id: "guest"}},
			}
			model.DirectContainingTrustBoundaryMappedByTechnicalAssetId = map[string]*types.TrustBoundary{
				"collector": model.TrustBoundaries["host"],
			}
			if test.callerBoundary != "" {
				model.DirectContainingTrustBoundaryMappedByTechnicalAssetId["tenant"] = model.TrustBoundaries[test.callerBoundary]
			}

			risks, err := NewTenantResourceExhaustionRule().GenerateRisks(model)

			require.NoError(t, err)
			if !test.risky {
				assert.Empty(t, risks)
				return
			}
			require.Len(t, risks, 1)
			assert.Equal(t, "tenant-resource-exhaustion@collector@tenant>send", risks[0].SyntheticId)
			assert.Equal(t, types.Likely, risks[0].ExploitationLikelihood)
			assert.Equal(t, test.impact, risks[0].ExploitationImpact)
		})
	}
}
