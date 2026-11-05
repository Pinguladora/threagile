package builtin

import (
	"testing"

	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestServerSideRequestForgeryRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewServerSideRequestForgeryRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestServerSideRequestForgeryRuleGenerateRisksOutOfScopeNoRisksCreated(t *testing.T) {
	rule := NewServerSideRequestForgeryRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: true,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsClient:     false,
							types.LoadBalancer: false,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestServerSideRequestForgeryRuleGenerateRisksLoadBalancerNoRisksCreated(t *testing.T) {
	rule := NewServerSideRequestForgeryRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsClient:     false,
							types.LoadBalancer: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestServerSideRequestForgeryRuleGenerateRisksIsClientNoRisksCreated(t *testing.T) {
	rule := NewServerSideRequestForgeryRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsClient:     true,
							types.LoadBalancer: false,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestServerSideRequestForgeryRuleGenerateRisksNotWebAccessCommunicationNoRisksCreated(t *testing.T) {
	rule := NewServerSideRequestForgeryRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsClient:     false,
							types.LoadBalancer: false,
						},
					},
				},
				CommunicationLinks: []*types.CommunicationLink{
					{
						Protocol: types.SqlAccessProtocol,
						TargetId: "ta2",
					},
				},
			},
			"ta2": {
				Title:      "Test Target Asset",
				OutOfScope: false,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestServerSideRequestForgeryRuleGenerateRisksLowImpactRisksCreated(t *testing.T) {
	rule := NewServerSideRequestForgeryRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsClient:     false,
							types.LoadBalancer: false,
						},
					},
				},
				CommunicationLinks: []*types.CommunicationLink{
					{
						Protocol: types.HTTP,
						TargetId: "ta2",
						Title:    "Test Communication Link",
					},
				},
			},
			"ta2": {
				Id:         "ta2",
				Title:      "Test Target Asset",
				OutOfScope: false,
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
	assert.Equal(t, types.Likely, risks[0].ExploitationLikelihood)
	assert.Equal(t, "<b>Server-Side Request Forgery (SSRF)</b> risk at <b>Test Technical Asset</b> server-side web-requesting the target <b>Test Target Asset</b> via <b>Test Communication Link</b>", risks[0].Title)
}

func TestServerSideRequestForgeryRuleGenerateRisksStrictlyConfidentialMediumImpactRisksCreated(t *testing.T) {
	rule := NewServerSideRequestForgeryRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsClient:     false,
							types.LoadBalancer: false,
						},
					},
				},
				CommunicationLinks: []*types.CommunicationLink{
					{
						Protocol: types.HTTP,
						TargetId: "ta2",
						Title:    "Test Communication Link",
					},
				},
			},
			"ta2": {
				Id:              "ta2",
				Title:           "Test Target Asset",
				OutOfScope:      false,
				Confidentiality: types.StrictlyConfidential,
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
	assert.Equal(t, types.Likely, risks[0].ExploitationLikelihood)
	assert.Equal(t, "<b>Server-Side Request Forgery (SSRF)</b> risk at <b>Test Technical Asset</b> server-side web-requesting the target <b>Test Target Asset</b> via <b>Test Communication Link</b>", risks[0].Title)
}

func TestServerSideRequestForgeryRuleGenerateRisksTrustBoundaryWithinCloudMediumImpactRisksCreated(t *testing.T) {
	rule := NewServerSideRequestForgeryRule()
	tb1 := &types.TrustBoundary{
		Id:                    "tb1",
		Type:                  types.NetworkCloudProvider,
		TechnicalAssetsInside: []string{"ta1", "ta2"},
	}
	comm := &types.CommunicationLink{
		Protocol: types.HTTP,
		TargetId: "ta2",
		Title:    "Test Communication Link",
	}
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsClient:     false,
							types.LoadBalancer: false,
						},
					},
				},
				CommunicationLinks: []*types.CommunicationLink{comm},
			},
			"ta2": {
				Id:         "ta2",
				Title:      "Test Target Asset",
				OutOfScope: false,
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta2": {comm},
		},
		TrustBoundaries: map[string]*types.TrustBoundary{
			"tb1": tb1,
		},
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"ta1": tb1,
			"ta2": tb1,
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
	assert.Equal(t, types.Likely, risks[0].ExploitationLikelihood)
	assert.Equal(t, "<b>Server-Side Request Forgery (SSRF)</b> risk at <b>Test Technical Asset</b> server-side web-requesting the target <b>Test Target Asset</b> via <b>Test Communication Link</b>", risks[0].Title)
}

func TestServerSideRequestForgeryRuleGenerateRisksStrictlyConfidentialTrustBoundaryNotCloudMediumImpactRisksCreated(t *testing.T) {
	rule := NewServerSideRequestForgeryRule()
	tb1 := &types.TrustBoundary{
		Id:                    "tb1",
		Type:                  types.NetworkVirtualLAN,
		TechnicalAssetsInside: []string{"ta1", "ta2"},
	}
	comm := &types.CommunicationLink{
		Protocol: types.HTTP,
		TargetId: "ta2",
		Title:    "Test Communication Link",
	}
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsClient:     false,
							types.LoadBalancer: false,
						},
					},
				},
				CommunicationLinks: []*types.CommunicationLink{comm},
			},
			"ta2": {
				Id:              "ta2",
				Title:           "Test Target Asset",
				OutOfScope:      false,
				Confidentiality: types.StrictlyConfidential,
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta2": {comm},
		},
		TrustBoundaries: map[string]*types.TrustBoundary{
			"tb1": tb1,
		},
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"ta1": tb1,
			"ta2": tb1,
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
	assert.Equal(t, types.Likely, risks[0].ExploitationLikelihood)
	assert.Equal(t, "<b>Server-Side Request Forgery (SSRF)</b> risk at <b>Test Technical Asset</b> server-side web-requesting the target <b>Test Target Asset</b> via <b>Test Communication Link</b>", risks[0].Title)
}

func TestServerSideRequestForgeryRuleGenerateRisksStrictlyConfidentialDifferentTrustBoundaryNotCloudLowImpactRisksCreated(t *testing.T) {
	rule := NewServerSideRequestForgeryRule()
	tb1 := &types.TrustBoundary{
		Id:                    "tb1",
		Type:                  types.NetworkVirtualLAN,
		TechnicalAssetsInside: []string{"ta1"},
	}
	tb2 := &types.TrustBoundary{
		Id:                    "tb2",
		Type:                  types.NetworkVirtualLAN,
		TechnicalAssetsInside: []string{"ta2"},
	}
	comm := &types.CommunicationLink{
		Protocol: types.HTTP,
		TargetId: "ta2",
		Title:    "Test Communication Link",
	}
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsClient:     false,
							types.LoadBalancer: false,
						},
					},
				},
				CommunicationLinks: []*types.CommunicationLink{comm},
			},
			"ta2": {
				Id:              "ta2",
				Title:           "Test Target Asset",
				OutOfScope:      false,
				Confidentiality: types.Confidential,
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta2": {comm},
		},
		TrustBoundaries: map[string]*types.TrustBoundary{
			"tb1": tb1,
			"tb2": tb2,
		},
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"ta1": tb1,
			"ta2": tb2,
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
	assert.Equal(t, types.Likely, risks[0].ExploitationLikelihood)
	assert.Equal(t, "<b>Server-Side Request Forgery (SSRF)</b> risk at <b>Test Technical Asset</b> server-side web-requesting the target <b>Test Target Asset</b> via <b>Test Communication Link</b>", risks[0].Title)
}

func TestServerSideRequestForgeryRuleGenerateRisksWithinDevopsUnlikelyLikelihoodRisksCreated(t *testing.T) {
	rule := NewServerSideRequestForgeryRule()
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsClient:     false,
							types.LoadBalancer: false,
						},
					},
				},
				CommunicationLinks: []*types.CommunicationLink{
					{
						Protocol: types.HTTP,
						TargetId: "ta2",
						Title:    "Test Communication Link",
						Usage:    types.DevOps,
					},
				},
			},
			"ta2": {
				Id:         "ta2",
				Title:      "Test Target Asset",
				OutOfScope: false,
			},
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
	assert.Equal(t, types.Unlikely, risks[0].ExploitationLikelihood)
	assert.Equal(t, "<b>Server-Side Request Forgery (SSRF)</b> risk at <b>Test Technical Asset</b> server-side web-requesting the target <b>Test Target Asset</b> via <b>Test Communication Link</b>", risks[0].Title)
}

func TestServerSideRequestForgeryRuleGenerateRisksStrictlyConfidentialNotHttpAccessDifferentTrustBoundaryNotCloudLowImpactRisksCreated(t *testing.T) {
	rule := NewServerSideRequestForgeryRule()
	tb1 := &types.TrustBoundary{
		Id:                    "tb1",
		Type:                  types.NetworkVirtualLAN,
		TechnicalAssetsInside: []string{"ta1"},
	}
	tb2 := &types.TrustBoundary{
		Id:                    "tb2",
		Type:                  types.NetworkVirtualLAN,
		TechnicalAssetsInside: []string{"ta2", "ta3"},
	}
	comm := &types.CommunicationLink{
		Protocol: types.HTTP,
		TargetId: "ta2",
		Title:    "Test Communication Link",
	}
	comm2 := &types.CommunicationLink{
		Protocol: types.SqlAccessProtocol,
		TargetId: "ta1",
		Title:    "Test Communication Link 2",
	}
	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Id:         "ta1",
				Title:      "Test Technical Asset",
				OutOfScope: false,
				Technologies: types.TechnologyList{
					{
						Name: "service-registry",
						Attributes: map[string]bool{
							types.IsClient:     false,
							types.LoadBalancer: false,
						},
					},
				},
				CommunicationLinks: []*types.CommunicationLink{comm, comm2},
			},
			"ta2": {
				Id:              "ta2",
				Title:           "Test Target Asset",
				OutOfScope:      false,
				Confidentiality: types.Confidential,
			},
			"ta3": {
				Id:              "ta3",
				Title:           "Test Source Asset",
				OutOfScope:      false,
				Confidentiality: types.StrictlyConfidential,
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"ta2": {comm},
			"ta1": {comm2},
		},
		TrustBoundaries: map[string]*types.TrustBoundary{
			"tb1": tb1,
			"tb2": tb2,
		},
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"ta1": tb1,
			"ta2": tb2,
			"ta3": tb2,
		},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
	assert.Equal(t, types.Likely, risks[0].ExploitationLikelihood)
	assert.Equal(t, "<b>Server-Side Request Forgery (SSRF)</b> risk at <b>Test Technical Asset</b> server-side web-requesting the target <b>Test Target Asset</b> via <b>Test Communication Link</b>", risks[0].Title)
}

func TestServerSideRequestForgeryRuleGenerateRisksExecutionEnvironmentInCloudMediumImpact(t *testing.T) {
	rule := NewServerSideRequestForgeryRule()
	cloud := &types.TrustBoundary{Id: "cloud", Type: types.NetworkCloudProvider, TrustBoundariesNested: []string{"namespace"}}
	namespace := &types.TrustBoundary{Id: "namespace", Type: types.ExecutionEnvironment, TechnicalAssetsInside: []string{"ta1"}}
	link := &types.CommunicationLink{Id: "ta1>ta2", SourceId: "ta1", TargetId: "ta2", Protocol: types.HTTP}

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {Id: "ta1", Type: types.Process, CommunicationLinks: []*types.CommunicationLink{link}},
			"ta2": {Id: "ta2", Type: types.Process},
		},
		TrustBoundaries: map[string]*types.TrustBoundary{cloud.Id: cloud, namespace.Id: namespace},
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{"ta1": namespace},
		IncomingTechnicalCommunicationLinksMappedByTargetId:   map[string][]*types.CommunicationLink{"ta2": {link}},
	})

	assert.Nil(t, err)
	assert.Len(t, risks, 1)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact, "the namespace is in the cloud")
}
