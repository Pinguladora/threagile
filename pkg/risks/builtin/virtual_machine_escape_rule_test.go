package builtin

import (
	"testing"

	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// virtualMachineModel is a node with a hypervisor, a service and an agent of the platform, and a guest with a
// workload in a trust boundary nested in the node's.
func virtualMachineModel(hypervisorOutOfScope bool, guestData types.Confidentiality) *types.Model {
	hypervisorTechnology := &types.Technology{
		Name: types.Hypervisor, Attributes: map[string]bool{types.Hypervisor: true},
	}
	model := &types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"vmm": {
				Id: "vmm", Title: "VMM", OutOfScope: hypervisorOutOfScope,
				Technologies: types.TechnologyList{hypervisorTechnology},
			},
			"sink":     {Id: "sink", Title: "Sink"},
			"agent":    {Id: "agent", Title: "Agent", OutOfScope: true},
			"workload": {Id: "workload", Title: "Workload", DataAssetsProcessed: []string{"guest-data"}},
		},
		DataAssets: map[string]*types.DataAsset{
			"guest-data": {Id: "guest-data", Confidentiality: guestData},
		},
		TrustBoundaries: map[string]*types.TrustBoundary{
			"node":  {Id: "node", TechnicalAssetsInside: []string{"vmm", "sink", "agent"}, TrustBoundariesNested: []string{"guest"}},
			"guest": {Id: "guest", TechnicalAssetsInside: []string{"workload"}},
		},
	}
	model.DirectContainingTrustBoundaryMappedByTechnicalAssetId = map[string]*types.TrustBoundary{
		"vmm": model.TrustBoundaries["node"], "sink": model.TrustBoundaries["node"],
		"agent": model.TrustBoundaries["node"], "workload": model.TrustBoundaries["guest"],
	}
	return model
}

func TestVirtualMachineEscapeRuleInScopeHypervisor(t *testing.T) {
	risks, err := NewVirtualMachineEscapeRule().GenerateRisks(virtualMachineModel(false, types.Confidential))

	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, "virtual-machine-escape@vmm", risks[0].SyntheticId)
	assert.Equal(t, "vmm", risks[0].MostRelevantTechnicalAssetId)
	assert.Equal(t, types.Unlikely, risks[0].ExploitationLikelihood)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
	assert.Equal(t, []string{"agent", "sink", "vmm", "workload"}, risks[0].DataBreachTechnicalAssetIDs,
		"the host and its guests")
}

func TestVirtualMachineEscapeRuleOutOfScopeHypervisor(t *testing.T) {
	risks, err := NewVirtualMachineEscapeRule().GenerateRisks(virtualMachineModel(true, types.StrictlyConfidential))

	require.NoError(t, err)
	require.Len(t, risks, 1, "only the in-scope assets of the host, not its guests")
	assert.Equal(t, "virtual-machine-escape@vmm@sink", risks[0].SyntheticId)
	assert.Equal(t, "sink", risks[0].MostRelevantTechnicalAssetId)
	assert.Equal(t, "<b>Virtual Machine Escape</b> risk at <b>VMM</b> exposing <b>Sink</b>", risks[0].Title)
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact, "a guest processes strictly confidential data")
}

func TestVirtualMachineEscapeRuleWithoutHost(t *testing.T) {
	model := virtualMachineModel(false, types.Confidential)
	model.DirectContainingTrustBoundaryMappedByTechnicalAssetId = map[string]*types.TrustBoundary{}

	risks, err := NewVirtualMachineEscapeRule().GenerateRisks(model)
	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, []string{"vmm"}, risks[0].DataBreachTechnicalAssetIDs)

	model.TechnicalAssets["vmm"].OutOfScope = true
	risks, err = NewVirtualMachineEscapeRule().GenerateRisks(model)
	require.NoError(t, err)
	assert.Empty(t, risks, "an out-of-scope hypervisor without a host exposes nothing in scope")
}

func TestVirtualMachineEscapeRuleOnlyHypervisors(t *testing.T) {
	model := virtualMachineModel(false, types.Confidential)
	model.TechnicalAssets["vmm"].Technologies = types.TechnologyList{}

	risks, err := NewVirtualMachineEscapeRule().GenerateRisks(model)

	require.NoError(t, err)
	assert.Empty(t, risks)
}
