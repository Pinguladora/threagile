package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

type DirectITOTCommunicationRule struct{}

func NewDirectITOTCommunicationRule() *DirectITOTCommunicationRule {
	return &DirectITOTCommunicationRule{}
}

func (*DirectITOTCommunicationRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "direct-it-ot-communication",
		Title: "Direct IT/OT Communication",
		Description: "Controllers, field devices, HMIs, SCADA servers and engineering workstations of an industrial " +
			"control system belong into control zones that IT assets reach only through an industrial DMZ. A direct " +
			"communication link between an IT asset and an asset of a control zone lets attackers who compromise the " +
			"IT side, which is far more exposed, move straight into the control of the physical process.",
		Impact: "If this risk is unmitigated, attackers who compromise an IT asset might reach the industrial control " +
			"system and change, stop or damage the physical process it controls.",
		ASVS:       asvsArchitecture,
		CheatSheet: nistOTSecurityURL,
		Action:     "Industrial DMZ",
		Mitigation: "Separate IT and OT with an industrial DMZ, so that no communication link crosses from IT into a " +
			"control zone directly: replicate the historian into the DMZ for IT users, give remote and vendor access " +
			"only through a jump host there, and filter what passes with firewalls on both sides. Tag the assets in " +
			"the DMZ with <i>" + industrialDMZTag + "</i>.",
		Check:    checkOTGuidance,
		Function: types.Architecture,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "In-scope OT technical assets (" + types.PLC + ", " + types.RTU + ", " + types.SafetyController +
			", " + types.FieldDevice + ", " + types.HMI + ", " + types.SCADAServer + ", " + types.EngineeringWorkstation +
			") with a communication link, in either direction, with a technical asset that is neither an OT asset nor " +
			"in the industrial DMZ (a " + types.Historian + " or an asset tagged with <i>" + industrialDMZTag + "</i>).",
		RiskAssessment: "The risk rating depends on the integrity and availability of the OT asset, and is the highest " +
			"for safety controllers. The attack is very likely when the other asset is on the internet, and likely " +
			"otherwise.",
		FalsePositives: "Links that pass through a firewall allowing only them, and that are documented exceptions " +
			"of the zone model, can be considered as false positives after individual review.",
		ModelFailurePossibleReason: true,
		CWE:                        cweArchitecturalConcepts,
		References: []string{
			iec62443NetworkSegmentation, iec62443ZoneBoundaryProtection, mitreICSInternetAccessibleDevice,
			mitreICSRemoteServices, nistOTSecurity,
		},
	}
}

func (*DirectITOTCommunicationRule) SupportedTags() []string {
	return []string{industrialDMZTag}
}

func (r *DirectITOTCommunicationRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, otAsset := range input.InScopeTechnicalAssets() {
		if !isControlZoneAsset(otAsset) {
			continue
		}
		for _, link := range otAsset.CommunicationLinksSorted() {
			if itAsset, ok := input.TechnicalAssets[link.TargetId]; ok && r.crossesIntoIT(link, itAsset) {
				risks = append(risks, r.createRisk(input, otAsset, itAsset, link))
			}
		}
		for _, link := range sortedIncomingLinks(input, otAsset) {
			if itAsset, ok := input.TechnicalAssets[link.SourceId]; ok && r.crossesIntoIT(link, itAsset) {
				risks = append(risks, r.createRisk(input, otAsset, itAsset, link))
			}
		}
	}
	return risks, nil
}

// crossesIntoIT reports whether the link connects to the IT asset over the network.
func (r *DirectITOTCommunicationRule) crossesIntoIT(link *types.CommunicationLink, other *types.TechnicalAsset) bool {
	return isITAsset(other) && !link.Protocol.IsProcessLocal()
}

func (r *DirectITOTCommunicationRule) createRisk(
	input *types.Model, otAsset, itAsset *types.TechnicalAsset, link *types.CommunicationLink,
) *types.Risk {
	likelihood := types.Likely
	if itAsset.Internet {
		likelihood = types.VeryLikely
	}
	impact := otRiskImpact(input, otAsset)

	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: assetRiskTitle("Direct IT/OT Communication", otAsset,
			"with <b>"+itAsset.Title+"</b>"),
		MostRelevantTechnicalAssetId:    otAsset.Id,
		MostRelevantCommunicationLinkId: link.Id,
		DataBreachProbability:           types.Possible,
		DataBreachTechnicalAssetIDs:     []string{otAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + otAsset.Id + "@" + link.Id
	return risk
}
