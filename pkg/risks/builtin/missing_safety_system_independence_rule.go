package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

type MissingSafetySystemIndependenceRule struct{}

func NewMissingSafetySystemIndependenceRule() *MissingSafetySystemIndependenceRule {
	return &MissingSafetySystemIndependenceRule{}
}

func (*MissingSafetySystemIndependenceRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-safety-system-independence",
		Title: "Missing Safety System Independence",
		Description: "A safety instrumented system brings the process into a safe state when the basic process " +
			"control fails or is attacked. It only does so when it is independent of that control: when assets " +
			"other than a dedicated safety engineering workstation can change its program, setpoints or outputs, " +
			"one compromise can disable the control and the safety function together, as the TRITON attack did.",
		Impact: "If this risk is unmitigated, attackers might disable or trip the safety function and so cause " +
			"explosions, releases of hazardous material or injuries.",
		ASVS:       asvsArchitecture,
		CheatSheet: nistOTSecurityURL,
		Action:     "Safety System Independence",
		Mitigation: "Let only a dedicated safety engineering workstation, which programs no other controllers, change " +
			"the safety controller, and give the basic process control and the HMIs readonly access to its status. " +
			"Keep the key switch of the safety controller in RUN mode outside of maintenance, and alert on every " +
			"program change.",
		Check:    checkOTGuidance,
		Function: types.Architecture,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "In-scope " + types.SafetyController + " technical assets with an incoming non-readonly " +
			"communication link that is not process-local, from a technical asset other than an " +
			types.EngineeringWorkstation + " that has no non-readonly communication links to other controllers.",
		RiskAssessment: "The impact is very high, as the safety function protects people. The attack is very likely " +
			"when the sender is on the internet, likely when it is an IT asset, reaches IT or calls across a network " +
			"trust boundary, and unlikely otherwise.",
		FalsePositives: "Links whose writes the safety controller itself restricts to values that cannot impair " +
			"the safety function can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweImproperAccessControl,
		References: []string{
			iec61511SafetyIndependence, mitreICSLossOfSafety, mitreICSProgramDownload,
			iec62443NetworkSegmentation, nistOTSecurity,
		},
	}
}

func (*MissingSafetySystemIndependenceRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingSafetySystemIndependenceRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, safetyController := range input.InScopeTechnicalAssets() {
		if !isSafetyController(safetyController) {
			continue
		}
		for _, link := range sortedIncomingLinks(input, safetyController) {
			if link.Readonly || link.Protocol.IsProcessLocal() {
				continue
			}
			sender, ok := input.TechnicalAssets[link.SourceId]
			if ok && !isDedicatedSafetyEngineering(input, sender) {
				risks = append(risks, r.createRisk(input, safetyController, sender, link))
			}
		}
	}
	return risks, nil
}

// isDedicatedSafetyEngineering reports whether the technical asset is an engineering workstation that changes
// safety controllers only.
func isDedicatedSafetyEngineering(input *types.Model, technicalAsset *types.TechnicalAsset) bool {
	if !isEngineeringWorkstation(technicalAsset) {
		return false
	}
	for _, link := range technicalAsset.CommunicationLinks {
		target, ok := input.TechnicalAssets[link.TargetId]
		if ok && !link.Readonly && isIndustrialController(target) && !isSafetyController(target) {
			return false
		}
	}
	return true
}

func (r *MissingSafetySystemIndependenceRule) createRisk(
	input *types.Model, safetyController, sender *types.TechnicalAsset, link *types.CommunicationLink,
) *types.Risk {
	likelihood := otSenderLikelihood(input, sender, link)
	impact := otRiskImpact(input, safetyController)

	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: assetRiskTitle("Missing Safety System Independence", safetyController,
			"changed by <b>"+sender.Title+"</b>"),
		MostRelevantTechnicalAssetId:    safetyController.Id,
		MostRelevantCommunicationLinkId: link.Id,
		DataBreachProbability:           types.Improbable,
		DataBreachTechnicalAssetIDs:     []string{safetyController.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + safetyController.Id + "@" + link.Id
	return risk
}
