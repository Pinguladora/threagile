package builtin

import (
	"strconv"

	"github.com/Pinguladora/threagile/pkg/types"
)

// The RAA values (in %) from which technical assets should be hardened; the reduced limit applies to high-value
// targets.
const (
	hardeningRAALimit        = 55
	hardeningRAALimitReduced = 40
)

type MissingHardeningRule struct {
	raaLimit        int
	raaLimitReduced int
}

func NewMissingHardeningRule() *MissingHardeningRule {
	return &MissingHardeningRule{raaLimit: hardeningRAALimit, raaLimitReduced: hardeningRAALimitReduced}
}

func (r *MissingHardeningRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-hardening",
		Title: "Missing Hardening",
		Description: "Technical assets with a Relative Attacker Attractiveness (RAA) value of " + strconv.Itoa(r.raaLimit) +
			" % or higher should be explicitly hardened taking best practices and vendor hardening guides into account.",
		Impact:     "If this risk remains unmitigated, attackers might be able to easier attack high-value targets.",
		ASVS:       asvsConfiguration,
		CheatSheet: cheatSheetAttackSurfaceAnalysis,
		Action:     "System Hardening",
		Mitigation: "Try to apply all hardening best practices (like CIS benchmarks, OWASP recommendations, vendor " +
			"recommendations, DevSec Hardening Framework, DBSAT for Oracle databases, and others).",
		Check:    checkCheatSheetAndASVS,
		Function: types.Operations,
		STRIDE:   types.Tampering,
		DetectionLogic: "In-scope technical assets with RAA values of " + strconv.Itoa(r.raaLimit) + " % or higher. " +
			"Generally for high-value targets like data stores, application servers, identity providers and ERP systems this " +
			"limit is reduced to " + strconv.Itoa(r.raaLimitReduced) + " %",
		RiskAssessment: "The risk rating depends on the sensitivity of the data processed in the technical " +
			"asset.",
		FalsePositives:             "Usually no false positives.",
		ModelFailurePossibleReason: false,
		CWE:                        cweConfiguration,
		References:                 []string{owaspSecurityMisconfiguration, owaspAPISecurityMisconfiguration},
	}
}

func (*MissingHardeningRule) SupportedTags() []string {
	return []string{"tomcat"}
}

func (r *MissingHardeningRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if r.skipAsset(technicalAsset) {
			continue
		}
		if technicalAsset.RAA >= float64(r.raaLimit) ||
			(technicalAsset.RAA >= float64(r.raaLimitReduced) &&
				(technicalAsset.Type == types.Datastore || technicalAsset.Technologies.GetAttribute(types.IsHighValueTarget))) {
			risks = append(risks, r.createRisk(input, technicalAsset))
		}
	}
	return risks, nil
}

func (r *MissingHardeningRule) skipAsset(technicalAsset *types.TechnicalAsset) bool {
	return technicalAsset.OutOfScope
}

func (r *MissingHardeningRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	title := "<b>Missing Hardening</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := types.LowImpact
	if input.HighestProcessedConfidentiality(technicalAsset) == types.StrictlyConfidential ||
		input.HighestProcessedIntegrity(technicalAsset) == types.MissionCritical {
		impact = types.MediumImpact
	}
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, impact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
