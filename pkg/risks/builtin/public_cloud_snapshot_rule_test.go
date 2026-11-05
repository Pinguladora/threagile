package builtin

import (
	"testing"

	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicCloudSnapshotRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewPublicCloudSnapshotRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type PublicCloudSnapshotRuleTest struct {
	technology        string
	tags              []string
	sharedRuntimeTags []string
	inCloud           bool
	outOfScope        bool
	stored            bool
	processedOnly     bool
	machine           types.TechnicalAssetMachine
	confidentiality   types.Confidentiality
	integrity         types.Criticality

	riskCreated      bool
	expectedTitle    string
	expectedImpact   types.RiskExploitationImpact
	expectedSeverity types.RiskSeverity
}

func TestPublicCloudSnapshotRuleGenerateRisks(t *testing.T) {
	testCases := map[string]PublicCloudSnapshotRuleTest{
		"rds database": {
			technology: types.Database,
			tags:       []string{"aws:rds"},
			stored:     true,

			riskCreated:      true,
			expectedTitle:    "<b>Publicly Shared Cloud Snapshot (RDS)</b> risk at <b>Cloud Asset</b>",
			expectedImpact:   types.MediumImpact,
			expectedSeverity: types.MediumSeverity,
		},
		"ebs volume": {
			technology: types.BlockStorage,
			tags:       []string{"aws:ebs"},
			stored:     true,

			riskCreated:      true,
			expectedTitle:    "<b>Publicly Shared Cloud Snapshot (EBS)</b> risk at <b>Cloud Asset</b>",
			expectedImpact:   types.MediumImpact,
			expectedSeverity: types.MediumSeverity,
		},
		"server on an ec2 shared runtime": {
			technology:        types.WebServer,
			sharedRuntimeTags: []string{"aws:ec2"},
			stored:            true,

			riskCreated:      true,
			expectedTitle:    "<b>Publicly Shared Cloud Snapshot (AMI)</b> risk at <b>Cloud Asset</b>",
			expectedImpact:   types.MediumImpact,
			expectedSeverity: types.MediumSeverity,
		},
		"untagged database in a cloud trust boundary": {
			technology: types.Database,
			inCloud:    true,
			stored:     true,

			riskCreated:      true,
			expectedTitle:    "<b>Publicly Shared Cloud Snapshot</b> risk at <b>Cloud Asset</b>",
			expectedImpact:   types.MediumImpact,
			expectedSeverity: types.MediumSeverity,
		},
		"confidential data": {
			technology:      types.Database,
			tags:            []string{"aws:rds"},
			stored:          true,
			confidentiality: types.Confidential,

			riskCreated:      true,
			expectedTitle:    "<b>Publicly Shared Cloud Snapshot (RDS)</b> risk at <b>Cloud Asset</b>",
			expectedImpact:   types.HighImpact,
			expectedSeverity: types.MediumSeverity,
		},
		"strictly confidential data": {
			technology:      types.BlockStorage,
			inCloud:         true,
			stored:          true,
			confidentiality: types.StrictlyConfidential,

			riskCreated:      true,
			expectedTitle:    "<b>Publicly Shared Cloud Snapshot</b> risk at <b>Cloud Asset</b>",
			expectedImpact:   types.VeryHighImpact,
			expectedSeverity: types.ElevatedSeverity,
		},
		"integrity does not raise the impact": {
			technology: types.Database,
			tags:       []string{"aws:rds"},
			stored:     true,
			integrity:  types.MissionCritical,

			riskCreated:      true,
			expectedTitle:    "<b>Publicly Shared Cloud Snapshot (RDS)</b> risk at <b>Cloud Asset</b>",
			expectedImpact:   types.MediumImpact,
			expectedSeverity: types.MediumSeverity,
		},
		"out of scope": {
			technology: types.Database,
			tags:       []string{"aws:rds"},
			stored:     true,
			outOfScope: true,
		},
		"no stored data": {
			technology:    types.Database,
			tags:          []string{"aws:rds"},
			processedOnly: true,
		},
		"database off-cloud": {
			technology: types.Database,
			stored:     true,
		},
		"untagged web server in the cloud": {
			technology: types.WebServer,
			inCloud:    true,
			stored:     true,
		},
		"untagged database in a container": {
			technology: types.Database,
			inCloud:    true,
			stored:     true,
			machine:    types.Container,
		},
		"tagged database in a container": {
			technology: types.Database,
			tags:       []string{"aws:rds"},
			stored:     true,
			machine:    types.Container,

			riskCreated:      true,
			expectedTitle:    "<b>Publicly Shared Cloud Snapshot (RDS)</b> risk at <b>Cloud Asset</b>",
			expectedImpact:   types.MediumImpact,
			expectedSeverity: types.MediumSeverity,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			model := &types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"ta1": {
						Id:           "ta1",
						Title:        "Cloud Asset",
						Technologies: cloudTestTechnology(testCase.technology),
						Tags:         testCase.tags,
						OutOfScope:   testCase.outOfScope,
						Machine:      testCase.machine,
					},
				},
				TrustBoundaries: map[string]*types.TrustBoundary{},
				SharedRuntimes: map[string]*types.SharedRuntime{
					"sr1": {Id: "sr1", Tags: testCase.sharedRuntimeTags, TechnicalAssetsRunning: []string{"ta1"}},
				},
				DataAssets: map[string]*types.DataAsset{
					"da1": {Id: "da1", Confidentiality: testCase.confidentiality, Integrity: testCase.integrity},
				},
			}
			if testCase.stored {
				model.TechnicalAssets["ta1"].DataAssetsStored = []string{"da1"}
			}
			if testCase.processedOnly {
				model.TechnicalAssets["ta1"].DataAssetsProcessed = []string{"da1"}
			}
			if testCase.inCloud {
				model.TrustBoundaries["tb1"] = &types.TrustBoundary{
					Id: "tb1", Type: types.NetworkCloudSecurityGroup, TechnicalAssetsInside: []string{"ta1"},
				}
			}

			risks, err := NewPublicCloudSnapshotRule().GenerateRisks(model)

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
			assert.Equal(t, "public-cloud-snapshot@ta1", risks[0].SyntheticId)
			assert.Equal(t, []string{"ta1"}, risks[0].DataBreachTechnicalAssetIDs)
		})
	}
}
