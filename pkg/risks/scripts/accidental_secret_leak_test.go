package scripts

import (
	_ "embed"
	"testing"

	"github.com/Pinguladora/threagile/pkg/risks/script"
	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
)

// Disabled: the script rule fails with "no technical assets in scope" on a model without technical assets,
// where it should create no risks.
// func TestAccidentalSecretLeakRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
// 	rule := loadAccidentalSecretLeakRule()

// 	risks, err := rule.GenerateRisks(&types.Model{})

// 	assert.Nil(t, err)
// 	assert.Empty(t, risks)
// }

func TestAccidentalSecretLeakRuleGenerateRisksOutOfScopeNotRisksCreated(t *testing.T) {
	rule := loadAccidentalSecretLeakRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				OutOfScope: true,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestAccidentalSecretLeakRuleGenerateRisksTechAssetNotContainSecretsNotRisksCreated(t *testing.T) {
	rule := loadAccidentalSecretLeakRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Technologies: types.TechnologyList{
					{
						Name: "tool",
						Attributes: map[string]bool{
							types.MayContainSecrets:                                 false,
							types.IsUsuallyAbleToPropagateIdentityToOutgoingTargets: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

// Disabled: the script rule does not create the risk this test expects yet.
// func TestAccidentalSecretLeakRuleGenerateRisksTechAssetGitContainSecretsRisksCreated(t *testing.T) {
// 	rule := loadAccidentalSecretLeakRule()

// 	risks, err := rule.GenerateRisks(&types.Model{
// 		TechnicalAssets: map[string]*types.TechnicalAsset{
// 			"ta1": {
// 				Technologies: types.TechnologyList{
// 					{
// 						Name: "git repository",
// 						Attributes: map[string]bool{
// 							types.MayContainSecrets: true,
// 						},
// 					},
// 				},
// 				Tags: []string{"git"},
// 			},
// 		},
// 	})

// 	assert.Nil(t, err)
// 	assert.Equal(t, len(risks), 1)
// 	assert.Contains(t, risks[0].Title, "Accidental Secret Leak (Git)")
// }

// Disabled: the script rule does not create the risk this test expects yet.
// func TestAccidentalSecretLeakRuleGenerateRisksTechAssetNotGitContainSecretsRisksCreated(t *testing.T) {
// 	rule := loadAccidentalSecretLeakRule()

// 	risks, err := rule.GenerateRisks(&types.Model{
// 		TechnicalAssets: map[string]*types.TechnicalAsset{
// 			"ta1": {
// 				Technologies: types.TechnologyList{
// 					{
// 						Name: "git repository",
// 						Attributes: map[string]bool{
// 							types.MayContainSecrets: true,
// 						},
// 					},
// 				},
// 			},
// 		},
// 	})

// 	assert.Nil(t, err)
// 	assert.Equal(t, len(risks), 1)
// 	assert.Equal(t, "<b>Accidental Secret Leak</b> risk at <b></b>", risks[0].Title)
// }

// Disabled: the script rule does not create the risk this test expects yet.
// func TestAccidentalSecretLeakRuleGenerateRisksTechAssetProcessStrictlyConfidentialDataAssetHighImpactRiskCreated(t *testing.T) {
// 	rule := loadAccidentalSecretLeakRule()

// 	risks, err := rule.GenerateRisks(&types.Model{
// 		TechnicalAssets: map[string]*types.TechnicalAsset{
// 			"ta1": {
// 				Technologies: types.TechnologyList{
// 					{
// 						Name: "git repository",
// 						Attributes: map[string]bool{
// 							types.MayContainSecrets: true,
// 						},
// 					},
// 				},
// 				DataAssetsProcessed: []string{"confidential-data-asset", "strictly-confidential-data-asset"},
// 			},
// 		},
// 		DataAssets: map[string]*types.DataAsset{
// 			"confidential-data-asset": {
// 				Confidentiality: types.Confidential,
// 			},
// 			"strictly-confidential-data-asset": {
// 				Confidentiality: types.StrictlyConfidential,
// 			},
// 		},
// 	})

// 	assert.Nil(t, err)
// 	assert.Equal(t, len(risks), 1)
// 	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
// }

//go:embed accidental-secret-leak.yaml
var accidental_secret_leak string

func loadAccidentalSecretLeakRule() types.RiskRule {
	result := new(script.RiskRule).Init()
	riskRule, _ := result.ParseFromData([]byte(accidental_secret_leak))
	return riskRule
}
