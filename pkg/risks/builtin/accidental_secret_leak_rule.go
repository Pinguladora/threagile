package builtin

import (
	"fmt"
	"strings"

	"github.com/Pinguladora/threagile/pkg/types"
)

type AccidentalSecretLeakRule struct{}

func NewAccidentalSecretLeakRule() *AccidentalSecretLeakRule {
	return &AccidentalSecretLeakRule{}
}

func (*AccidentalSecretLeakRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "accidental-secret-leak",
		Title: "Accidental Secret Leak",
		Description: "Sourcecode repositories (including their histories) as well as artifact registries can accidentally " +
			"contain secrets like checked-in or packaged-in passwords, API tokens, certificates, crypto keys, etc.",
		Impact: "If this risk is unmitigated, attackers which have access to affected sourcecode repositories or artifact " +
			"registries might find secrets accidentally checked-in.",
		ASVS:       asvsConfiguration,
		CheatSheet: cheatSheetAttackSurfaceAnalysis,
		Action:     actionBuildPipelineHardening,
		Mitigation: "Establish measures preventing accidental check-in or package-in of secrets into sourcecode " +
			"repositories and artifact registries. This starts by using good .gitignore and .dockerignore files, but does not " +
			"stop there. See for example tools like <i>\"git-secrets\" or \"Talisman\"</i> to have check-in preventive " +
			"measures for secrets. Consider also to regularly scan your repositories for secrets accidentally checked-in " +
			"using scanning tools like <i>\"gitleaks\" or \"gitrob\"</i>.",
		Check:                      checkCheatSheetAndASVS,
		Function:                   types.Operations,
		STRIDE:                     types.InformationDisclosure,
		DetectionLogic:             "In-scope sourcecode repositories and artifact registries.",
		RiskAssessment:             ratingByAssetAndProcessedDataSensitivity,
		FalsePositives:             "Usually no false positives.",
		ModelFailurePossibleReason: false,
		CWE:                        cweSensitiveInformationExposure,
	}
}

func (*AccidentalSecretLeakRule) SupportedTags() []string {
	// 'nexus' is accepted as a tag, but unlike 'git' it does not change the risk yet: how it should be used is open.
	return []string{"git", "nexus"}
}

func (r *AccidentalSecretLeakRule) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		techAsset := parsedModel.TechnicalAssets[id]
		if r.skipAsset(techAsset) {
			continue
		}

		var risk *types.Risk
		if techAsset.IsTaggedWithAny("git") {
			risk = r.createRisk(parsedModel, techAsset, "Git", "Git Leak Prevention")
		} else {
			risk = r.createRisk(parsedModel, techAsset, "", "")
		}
		risks = append(risks, risk)
	}
	return risks, nil
}

func (asl *AccidentalSecretLeakRule) skipAsset(techAsset *types.TechnicalAsset) bool {
	return techAsset.OutOfScope || !techAsset.Technologies.GetAttribute(types.MayContainSecrets)
}

func (r *AccidentalSecretLeakRule) createRisk(
	parsedModel *types.Model, technicalAsset *types.TechnicalAsset, prefix, details string,
) *types.Risk {
	if len(prefix) > 0 {
		prefix = " (" + prefix + ")"
	}
	title := "<b>Accidental Secret Leak" + prefix + "</b> risk at <b>" + technicalAsset.Title + "</b>"
	if len(details) > 0 {
		title += ": <u>" + details + "</u>"
	}
	impact := types.LowImpact
	highestProcessedConfidentiality := parsedModel.HighestProcessedConfidentiality(technicalAsset)
	highestProcessedIntegrity := parsedModel.HighestProcessedIntegrity(technicalAsset)
	highestProcessedAvailability := parsedModel.HighestProcessedAvailability(technicalAsset)
	if highestProcessedConfidentiality >= types.Confidential ||
		highestProcessedIntegrity >= types.Critical ||
		highestProcessedAvailability >= types.Critical {
		impact = types.MediumImpact
	}
	if highestProcessedConfidentiality == types.StrictlyConfidential ||
		highestProcessedIntegrity == types.MissionCritical ||
		highestProcessedAvailability == types.MissionCritical {
		impact = types.HighImpact
	}
	// create risk
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood:       types.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

func (r *AccidentalSecretLeakRule) MatchRisk(parsedModel *types.Model, risk string) bool {
	categoryId := r.Category().ID
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		techAsset := parsedModel.TechnicalAssets[id]
		if strings.EqualFold(risk, categoryId+"@"+techAsset.Id) || strings.EqualFold(risk, categoryId+"@*") {
			return true
		}
	}

	return false
}

func (r *AccidentalSecretLeakRule) ExplainRisk(parsedModel *types.Model, risk string) []string {
	categoryId := r.Category().ID
	explanation := make([]string, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		techAsset := parsedModel.TechnicalAssets[id]
		if strings.EqualFold(risk, categoryId+"@"+techAsset.Id) || strings.EqualFold(risk, categoryId+"@*") {
			if !techAsset.OutOfScope && (techAsset.Technologies.GetAttribute(types.SourcecodeRepository) ||
				techAsset.Technologies.GetAttribute(types.ArtifactRegistry)) {
				riskExplanation := r.explainRisk(parsedModel, techAsset)
				if riskExplanation != nil {
					if len(explanation) > 0 {
						explanation = append(explanation, "")
					}

					explanation = append(explanation, []string{
						fmt.Sprintf("technical asset %q", techAsset.Id),
						fmt.Sprintf("  - out of scope: %v (=false)", techAsset.OutOfScope),
						fmt.Sprintf(
							"  - technology: %v (has either [%q, %q])", techAsset.Technologies.String(), types.SourcecodeRepository,
							types.ArtifactRegistry,
						),
					}...)

					if techAsset.IsTaggedWithAny("git") {
						explanation = append(explanation, "  is tagged with 'git'")
					}

					explanation = append(explanation, riskExplanation...)
				}
			}
		}
	}

	return explanation
}

func (r *AccidentalSecretLeakRule) explainRisk(
	parsedModel *types.Model, technicalAsset *types.TechnicalAsset,
) []string {
	confidentiality := parsedModel.HighestProcessedConfidentiality(technicalAsset)
	integrity := parsedModel.HighestProcessedIntegrity(technicalAsset)
	availability := parsedModel.HighestProcessedAvailability(technicalAsset)
	switch {
	case confidentiality == types.StrictlyConfidential || integrity == types.MissionCritical ||
		availability == types.MissionCritical:
		return explainHighSecretLeakImpact(confidentiality, integrity, availability)
	case confidentiality >= types.Confidential || integrity >= types.Critical || availability >= types.Critical:
		return explainMediumSecretLeakImpact(confidentiality, integrity, availability)
	default:
		return []string{fmt.Sprintf("     - impact is %v (default)", types.LowImpact)}
	}
}

func explainHighSecretLeakImpact(
	confidentiality types.Confidentiality, integrity types.Criticality, availability types.Criticality,
) []string {
	explanation := []string{fmt.Sprintf("    - impact is %v because", types.HighImpact)}
	if confidentiality == types.StrictlyConfidential {
		explanation = append(explanation,
			fmt.Sprintf("      => highest confidentiality: %v (==%v)", confidentiality, types.StrictlyConfidential),
		)
	}
	if integrity == types.MissionCritical {
		explanation = append(explanation,
			fmt.Sprintf("      => highest integrity: %v (==%v)", integrity, types.MissionCritical),
		)
	}
	if availability == types.MissionCritical {
		explanation = append(explanation,
			fmt.Sprintf("      => highest availability: %v (==%v)", availability, types.MissionCritical),
		)
	}
	return explanation
}

func explainMediumSecretLeakImpact(
	confidentiality types.Confidentiality, integrity types.Criticality, availability types.Criticality,
) []string {
	explanation := []string{fmt.Sprintf("    - impact is %v because", types.MediumImpact)}
	if confidentiality == types.StrictlyConfidential {
		explanation = append(explanation,
			fmt.Sprintf("     =>  highest confidentiality: %v (>=%v)", confidentiality, types.Confidential),
		)
	}
	if integrity == types.MissionCritical {
		explanation = append(explanation,
			fmt.Sprintf("     =>  highest integrity: %v (==%v)", integrity, types.Critical),
		)
	}
	if availability == types.MissionCritical {
		explanation = append(explanation,
			fmt.Sprintf("     =>  highest availability: %v (==%v)", availability, types.Critical),
		)
	}
	return explanation
}
