package report

import "github.com/Pinguladora/threagile/pkg/types"

// riskDetails is what the risk outputs (risks.xlsx and risks.json) show about a risk beyond the
// risk itself, looked up once so that both draw on the same values.
type riskDetails struct {
	category          *types.RiskCategory
	technicalAsset    *types.TechnicalAsset    // nil when the risk has no most relevant technical asset
	communicationLink *types.CommunicationLink // nil when the risk has no most relevant communication link
	tracking          types.RiskTracking       // the zero value when the risk is not tracked
}

// newRiskDetails looks up the details of a risk of the given category; a nil category (a risk
// whose category the model does not know) yields empty category details.
func newRiskDetails(parsedModel *types.Model, category *types.RiskCategory, risk *types.Risk) riskDetails {
	if category == nil {
		category = &types.RiskCategory{ID: risk.CategoryId}
	}
	return riskDetails{
		category:          category,
		technicalAsset:    parsedModel.TechnicalAssets[risk.MostRelevantTechnicalAssetId],
		communicationLink: parsedModel.CommunicationLinks[risk.MostRelevantCommunicationLinkId],
		tracking:          parsedModel.GetRiskTrackingWithDefault(risk),
	}
}

func (what riskDetails) technicalAssetTitle() string {
	if what.technicalAsset == nil {
		return ""
	}
	return what.technicalAsset.Title
}

// technicalAssetRAA is the relative attacker attractiveness of the most relevant technical asset,
// or 0 when there is none.
func (what riskDetails) technicalAssetRAA() float64 {
	if what.technicalAsset == nil {
		return 0
	}
	return what.technicalAsset.RAA
}

func (what riskDetails) communicationLinkTitle() string {
	if what.communicationLink == nil {
		return ""
	}
	return what.communicationLink.Title
}

// trackingDate is the date of the risk tracking as YYYY-MM-DD, or empty when it has none.
func (what riskDetails) trackingDate() string {
	if what.tracking.Date.IsZero() {
		return ""
	}
	return what.tracking.Date.Format("2006-01-02")
}
