package builtin

import (
	"testing"

	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptionKeyDeletionRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewEncryptionKeyDeletionRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type EncryptionKeyDeletionRuleTest struct {
	technology      string
	tags            []string
	boundaryTags    []string
	inCloud         bool
	keyStoreTags    []string
	keyStoreInCloud bool
	linkToKeyStore  bool
	encryption      types.EncryptionStyle
	outOfScope      bool
	stored          bool
	availability    types.Criticality
	confidentiality types.Confidentiality

	riskCreated      bool
	expectedTitle    string
	expectedImpact   types.RiskExploitationImpact
	expectedSeverity types.RiskSeverity
}

func TestEncryptionKeyDeletionRuleGenerateRisks(t *testing.T) {
	const (
		plainTitle    = "<b>Denial of Service by Encryption Key Deletion</b> risk at <b>Cloud Storage</b>"
		keyStoreTitle = plainTitle + " with keys from <b>Key Store</b>"
	)

	testCases := map[string]EncryptionKeyDeletionRuleTest{
		"storage tagged with a key management service": {
			tags:       []string{"aws:s3", "aws:kms"},
			encryption: types.Transparent,
			stored:     true,

			riskCreated:      true,
			expectedTitle:    plainTitle,
			expectedImpact:   types.MediumImpact,
			expectedSeverity: types.MediumSeverity,
		},
		"trust boundary tagged with a key management service": {
			boundaryTags: []string{"azure:keyvault"},
			encryption:   types.DataWithSymmetricSharedKey,
			stored:       true,

			riskCreated:      true,
			expectedTitle:    plainTitle,
			expectedImpact:   types.MediumImpact,
			expectedSeverity: types.MediumSeverity,
		},
		"storage using a vault in the cloud": {
			inCloud:         true,
			keyStoreInCloud: true,
			linkToKeyStore:  true,
			encryption:      types.Transparent,
			stored:          true,

			riskCreated:      true,
			expectedTitle:    keyStoreTitle,
			expectedImpact:   types.MediumImpact,
			expectedSeverity: types.MediumSeverity,
		},
		"storage using a tagged key store": {
			tags:           []string{"gcp"},
			keyStoreTags:   []string{"gcp:kms"},
			linkToKeyStore: true,
			encryption:     types.Transparent,
			stored:         true,

			riskCreated:      true,
			expectedTitle:    keyStoreTitle,
			expectedImpact:   types.MediumImpact,
			expectedSeverity: types.MediumSeverity,
		},
		"critical availability": {
			tags:         []string{"aws:kms"},
			encryption:   types.Transparent,
			stored:       true,
			availability: types.Critical,

			riskCreated:      true,
			expectedTitle:    plainTitle,
			expectedImpact:   types.HighImpact,
			expectedSeverity: types.MediumSeverity,
		},
		"mission-critical availability": {
			tags:         []string{"aws:kms"},
			encryption:   types.Transparent,
			stored:       true,
			availability: types.MissionCritical,

			riskCreated:      true,
			expectedTitle:    plainTitle,
			expectedImpact:   types.VeryHighImpact,
			expectedSeverity: types.ElevatedSeverity,
		},
		"confidentiality does not raise the impact": {
			tags:            []string{"aws:kms"},
			encryption:      types.Transparent,
			stored:          true,
			confidentiality: types.StrictlyConfidential,

			riskCreated:      true,
			expectedTitle:    plainTitle,
			expectedImpact:   types.MediumImpact,
			expectedSeverity: types.MediumSeverity,
		},
		"not encrypted": {
			tags:   []string{"aws:kms"},
			stored: true,
		},
		"no stored data": {
			tags:       []string{"aws:kms"},
			encryption: types.Transparent,
		},
		"out of scope": {
			tags:       []string{"aws:kms"},
			encryption: types.Transparent,
			stored:     true,
			outOfScope: true,
		},
		"encrypted cloud storage without a modelled key management service": {
			inCloud:    true,
			encryption: types.Transparent,
			stored:     true,
		},
		"cloud storage using an on-prem vault": {
			inCloud:        true,
			linkToKeyStore: true,
			encryption:     types.Transparent,
			stored:         true,
		},
		"on-prem storage using an on-prem vault": {
			linkToKeyStore: true,
			encryption:     types.Transparent,
			stored:         true,
		},
		"key store itself": {
			technology: types.Vault,
			tags:       []string{"aws:kms"},
			encryption: types.Transparent,
			stored:     true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			technology := testCase.technology
			if technology == "" {
				technology = types.FileServer
			}
			storage := &types.TechnicalAsset{
				Id:           "storage",
				Title:        "Cloud Storage",
				Technologies: cloudTestTechnology(technology),
				Tags:         testCase.tags,
				Encryption:   testCase.encryption,
				OutOfScope:   testCase.outOfScope,
			}
			if testCase.stored {
				storage.DataAssetsStored = []string{"da1"}
			}
			if testCase.linkToKeyStore {
				storage.CommunicationLinks = []*types.CommunicationLink{
					{Id: "storage>keys", Title: "Keys", SourceId: "storage", TargetId: "key-store"},
				}
			}

			model := &types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"storage": storage,
					"key-store": {
						Id: "key-store", Title: "Key Store", Technologies: cloudTestTechnology(types.Vault),
						Tags: testCase.keyStoreTags,
					},
				},
				TrustBoundaries: map[string]*types.TrustBoundary{
					"storage-boundary": {Id: "storage-boundary", Tags: testCase.boundaryTags, TechnicalAssetsInside: []string{"storage"}},
					"key-boundary":     {Id: "key-boundary", TechnicalAssetsInside: []string{"key-store"}},
				},
				DataAssets: map[string]*types.DataAsset{
					"da1": {Id: "da1", Availability: testCase.availability, Confidentiality: testCase.confidentiality},
				},
			}
			if testCase.inCloud {
				model.TrustBoundaries["storage-boundary"].Type = types.NetworkCloudProvider
			}
			if testCase.keyStoreInCloud {
				model.TrustBoundaries["key-boundary"].Type = types.NetworkCloudProvider
			}

			risks, err := NewEncryptionKeyDeletionRule().GenerateRisks(model)

			assert.Nil(t, err)
			if !testCase.riskCreated {
				assert.Empty(t, risks)
				return
			}
			require.Len(t, risks, 1)
			assert.Equal(t, testCase.expectedTitle, risks[0].Title)
			assert.Equal(t, types.Unlikely, risks[0].ExploitationLikelihood)
			assert.Equal(t, testCase.expectedImpact, risks[0].ExploitationImpact)
			assert.Equal(t, testCase.expectedSeverity, risks[0].Severity)
			assert.Equal(t, types.Improbable, risks[0].DataBreachProbability)
			assert.Equal(t, "encryption-key-deletion@storage", risks[0].SyntheticId)
		})
	}
}
