package report

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

// textPolicyDecisionPoints is the title of the chapter of the policy decision points.
const textPolicyDecisionPoints = "Policy Decision Points"

// decisionPointsIntro introduces the chapter of the policy decision points.
const decisionPointsIntro = "Policy decision points decide the authorization of other services, their enforcement " +
	"points, which ask them before granting a request. A decision point that is unavailable, tampered with or wrong " +
	"affects every request that its enforcement points authorize."

// viewDecisionPoint is a policy decision point with the enforcement points that ask it.
type viewDecisionPoint struct {
	Asset       viewRef
	Redundant   bool
	OutOfScope  bool
	Summary     string // of its risks
	Enforcement []viewEnforcementPoint
}

// viewEnforcementPoint is a technical asset that asks a policy decision point, with the requests it authorizes.
type viewEnforcementPoint struct {
	Asset          viewRef
	Link           viewRef // to the decision point
	Authentication string  // of the link to the decision point
	Requests       []viewAuthorizedRequest
}

// viewAuthorizedRequest is a communication link to an enforcement point, whose requests it authorizes.
type viewAuthorizedRequest struct {
	Link          viewRef
	Source        viewRef
	Authorization string
}

func viewDecisionPoints(parsedModel *types.Model) []viewDecisionPoint {
	decisionPoints := make([]viewDecisionPoint, 0)
	for _, asset := range sortedTechnicalAssetsByTitle(parsedModel) {
		if !asset.Technologies.GetAttribute(types.PolicyDecisionPoint) {
			continue
		}
		generatedRisks := parsedModel.GeneratedRisks(asset)
		view := viewDecisionPoint{
			Asset:      refTechnicalAsset(parsedModel, asset.Id),
			Redundant:  asset.Redundant,
			OutOfScope: asset.OutOfScope,
			Summary:    riskSuffix(len(types.ReduceToOnlyStillAtRisk(generatedRisks)), len(generatedRisks)),
		}
		for _, link := range incomingLinks(parsedModel, asset) {
			view.Enforcement = append(view.Enforcement, newViewEnforcementPoint(parsedModel, link))
		}
		decisionPoints = append(decisionPoints, view)
	}
	return decisionPoints
}

func newViewEnforcementPoint(parsedModel *types.Model, link *types.CommunicationLink) viewEnforcementPoint {
	view := viewEnforcementPoint{
		Asset:          refTechnicalAsset(parsedModel, link.SourceId),
		Link:           refCommunicationLink(link),
		Authentication: link.Authentication.String(),
	}
	if enforcer, ok := parsedModel.TechnicalAssets[link.SourceId]; ok {
		for _, request := range incomingLinks(parsedModel, enforcer) {
			view.Requests = append(view.Requests, viewAuthorizedRequest{
				Link:          refCommunicationLink(request),
				Source:        refTechnicalAsset(parsedModel, request.SourceId),
				Authorization: request.Authorization.String(),
			})
		}
	}
	return view
}
