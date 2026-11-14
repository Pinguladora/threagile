package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

// TenantResourceExhaustionRule reports multi-tenant assets that take data from callers they cannot trust: one tenant
// can use up what the asset shares among all of them, and starve or blind the others.
type TenantResourceExhaustionRule struct{}

func NewTenantResourceExhaustionRule() *TenantResourceExhaustionRule {
	return &TenantResourceExhaustionRule{}
}

func (*TenantResourceExhaustionRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "tenant-resource-exhaustion",
		Title: "Tenant Resource Exhaustion",
		Description: "A multi-tenant asset shares its connections, queues, memory and processing time among its " +
			"tenants. A tenant that sends more than its share, by mistake or on purpose, takes them from the others. " +
			"For a collector of logs, events or audit records this does more than slow it down: the records of the " +
			"other tenants are dropped, and whoever reads them can no longer tell a quiet tenant from one that was " +
			"not heard.",
		Impact: "If this risk is unmitigated, one tenant might deny the service to the others, or make the asset " +
			"lose their data, such as the audit records that would show what that tenant did.",
		ASVS:       asvsArchitecture,
		CheatSheet: cheatSheetDenialOfService,
		Action:     "Per-Tenant Limits",
		Mitigation: "Give every tenant its own bounded share: limits on its connections, rate and queue length, and " +
			"fair scheduling among tenants, so that one that floods only loses its own data. Count and report what " +
			"is dropped per tenant, so that a gap can be told from silence, and alert on it.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Architecture,
		STRIDE:   types.DenialOfService,
		DetectionLogic: "In-scope multi-tenant technical assets that receive data over a communication link from a " +
			"caller that is out of scope or in another trust boundary, of any type. Read-only links, which send no " +
			"data, and links of " + types.DevOps.String() + " usage are left out.",
		RiskAssessment: "Likely. The impact follows the higher of the availability of the asset and the integrity of " +
			"the data it receives over the link: low below " + types.Critical.String() + ", medium for " +
			types.Critical.String() + " and high for " + types.MissionCritical.String() + ".",
		FalsePositives: "Assets that already give every tenant its own bounded share can be considered as false " +
			"positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweUncontrolledResourceConsumption,
		References:                 []string{owaspAPIUnrestrictedResourceConsumption},
	}
}

func (*TenantResourceExhaustionRule) SupportedTags() []string {
	return []string{}
}

func (r *TenantResourceExhaustionRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		target := input.TechnicalAssets[id]
		if target.OutOfScope || !target.MultiTenant {
			continue
		}
		for _, link := range sortedIncomingLinks(input, target) {
			if link.Readonly || len(link.DataAssetsSent) == 0 || link.Usage == types.DevOps ||
				!isUntrustedTenant(input, link) {
				continue
			}
			risks = append(risks, r.createRisk(input, target, link))
		}
	}
	return risks, nil
}

// isUntrustedTenant reports whether the caller of the link is out of scope or in another trust boundary than the
// target.
func isUntrustedTenant(input *types.Model, link *types.CommunicationLink) bool {
	if input.TechnicalAssets[link.SourceId].OutOfScope {
		return true
	}
	boundaryOf := input.DirectContainingTrustBoundaryMappedByTechnicalAssetId
	return boundaryId(boundaryOf[link.SourceId]) != boundaryId(boundaryOf[link.TargetId])
}

func boundaryId(boundary *types.TrustBoundary) string {
	if boundary == nil {
		return ""
	}
	return boundary.Id
}

func (r *TenantResourceExhaustionRule) createRisk(input *types.Model, target *types.TechnicalAsset,
	link *types.CommunicationLink,
) *types.Risk {
	at := max(target.Availability, input.HighestCommunicationLinkIntegrity(link))
	impact := types.LowImpact
	switch {
	case at >= types.MissionCritical:
		impact = types.HighImpact
	case at >= types.Critical:
		impact = types.MediumImpact
	}
	caller := input.TechnicalAssets[link.SourceId]
	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(types.Likely, impact),
		ExploitationLikelihood: types.Likely,
		ExploitationImpact:     impact,
		Title: "<b>Tenant Resource Exhaustion</b> of <b>" + target.Title + "</b> by tenants behind <b>" +
			caller.Title + "</b> via <b>" + link.Title + "</b>",
		MostRelevantTechnicalAssetId:    target.Id,
		MostRelevantCommunicationLinkId: link.Id,
		DataBreachProbability:           types.Improbable,
		DataBreachTechnicalAssetIDs:     []string{},
	}
	risk.SyntheticId = risk.CategoryId + "@" + target.Id + "@" + link.Id
	return risk
}
