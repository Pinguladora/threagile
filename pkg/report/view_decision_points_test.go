package report

import (
	"testing"

	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestViewDecisionPoints(t *testing.T) {
	decisionPointTechnology := &types.Technology{
		Name: types.PolicyDecisionPoint, Attributes: map[string]bool{types.PolicyDecisionPoint: true},
	}
	asks := &types.CommunicationLink{
		Id: "service>asks", Title: "Asks", SourceId: "service", TargetId: "pdp", Authentication: types.ClientCertificate,
	}
	request := &types.CommunicationLink{
		Id: "client>request", Title: "Request", SourceId: "client", TargetId: "service",
		Authorization: types.ObjectLevel,
	}
	parsedModel := &types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"pdp": {Id: "pdp", Title: "PDP", Technologies: types.TechnologyList{decisionPointTechnology}},
			"spare-pdp": {
				Id: "spare-pdp", Title: "Spare PDP", Redundant: true, OutOfScope: true,
				Technologies: types.TechnologyList{decisionPointTechnology},
			},
			"service": {Id: "service", Title: "Service", CommunicationLinks: []*types.CommunicationLink{asks}},
			"client":  {Id: "client", Title: "Client", CommunicationLinks: []*types.CommunicationLink{request}},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"pdp":     {asks},
			"service": {request},
		},
	}

	decisionPoints := viewDecisionPoints(parsedModel)

	require.Len(t, decisionPoints, 2, "only the policy decision points, by title")
	assert.Equal(t, "PDP", decisionPoints[0].Asset.Title)
	assert.Equal(t, []viewEnforcementPoint{{
		Asset:          viewRef{Anchor: viewAnchor("asset", "service"), Title: "Service"},
		Link:           viewRef{Anchor: viewAnchor("link", "service>asks"), Title: "Asks"},
		Authentication: types.ClientCertificate.String(),
		Requests: []viewAuthorizedRequest{{
			Link:          viewRef{Anchor: viewAnchor("link", "client>request"), Title: "Request"},
			Source:        viewRef{Anchor: viewAnchor("asset", "client"), Title: "Client"},
			Authorization: types.ObjectLevel.String(),
		}},
	}}, decisionPoints[0].Enforcement)
	assert.Equal(t, "not redundant", decisionPointState(decisionPoints[0]))

	assert.Equal(t, "Spare PDP", decisionPoints[1].Asset.Title)
	assert.Empty(t, decisionPoints[1].Enforcement, "nothing asks it")
	assert.Equal(t, "out of scope, redundant", decisionPointState(decisionPoints[1]))
}
