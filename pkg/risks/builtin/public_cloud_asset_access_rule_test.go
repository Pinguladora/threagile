package builtin

import (
	"testing"

	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cloudTestTechnology returns a technology with the attribute of its own name set, as in technologies.yaml.
func cloudTestTechnology(name string) types.TechnologyList {
	attributes := map[string]bool{name: true}
	if name == types.FileServer {
		attributes[types.IsFileStorage] = true
	}
	return types.TechnologyList{{Name: name, Attributes: attributes}}
}

func TestPublicCloudAssetAccessRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewPublicCloudAssetAccessRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type PublicCloudAssetAccessRuleTest struct {
	technology    string
	machine       types.TechnicalAssetMachine
	tags          []string
	inCloud       bool
	outOfScope    bool
	stored        bool
	processed     bool
	internet      bool
	internetLink  bool
	dataRating    types.Confidentiality
	dataIntegrity types.Criticality

	riskCreated        bool
	expectedTitle      string
	expectedLikelihood types.RiskExploitationLikelihood
	expectedImpact     types.RiskExploitationImpact
	expectedSeverity   types.RiskSeverity
}

func TestPublicCloudAssetAccessRuleGenerateRisks(t *testing.T) {
	testCases := map[string]PublicCloudAssetAccessRuleTest{
		"s3 bucket storing data": {
			technology: types.FileServer,
			tags:       []string{"aws:s3"},
			stored:     true,

			riskCreated:        true,
			expectedTitle:      "<b>Public Cloud Asset Access (S3)</b> risk at <b>Cloud Asset</b>",
			expectedLikelihood: types.Unlikely,
			expectedImpact:     types.MediumImpact,
			expectedSeverity:   types.MediumSeverity,
		},
		"sqs queue processing data": {
			technology: types.MessageQueue,
			tags:       []string{"aws:sqs"},
			processed:  true,

			riskCreated:        true,
			expectedTitle:      "<b>Public Cloud Asset Access (SQS)</b> risk at <b>Cloud Asset</b>",
			expectedLikelihood: types.Unlikely,
			expectedImpact:     types.MediumImpact,
			expectedSeverity:   types.MediumSeverity,
		},
		"untagged serverless storage in a cloud trust boundary": {
			technology: types.FileServer,
			machine:    types.Serverless,
			inCloud:    true,
			stored:     true,

			riskCreated:        true,
			expectedTitle:      "<b>Public Cloud Asset Access</b> risk at <b>Cloud Asset</b>",
			expectedLikelihood: types.Unlikely,
			expectedImpact:     types.MediumImpact,
			expectedSeverity:   types.MediumSeverity,
		},
		"serverless data lake tagged with a cloud provider": {
			technology: types.DataLake,
			machine:    types.Serverless,
			tags:       []string{"gcp"},
			stored:     true,

			riskCreated:        true,
			expectedTitle:      "<b>Public Cloud Asset Access</b> risk at <b>Cloud Asset</b>",
			expectedLikelihood: types.Unlikely,
			expectedImpact:     types.MediumImpact,
			expectedSeverity:   types.MediumSeverity,
		},
		"confidential data at internet-facing bucket": {
			technology: types.FileServer,
			tags:       []string{"aws:s3"},
			stored:     true,
			internet:   true,
			dataRating: types.Confidential,

			riskCreated:        true,
			expectedTitle:      "<b>Public Cloud Asset Access (S3)</b> risk at <b>Cloud Asset</b>",
			expectedLikelihood: types.Likely,
			expectedImpact:     types.HighImpact,
			expectedSeverity:   types.ElevatedSeverity,
		},
		"mission-critical data at bucket used from the internet": {
			technology:    types.FileServer,
			tags:          []string{"aws:s3"},
			stored:        true,
			internetLink:  true,
			dataIntegrity: types.MissionCritical,

			riskCreated:        true,
			expectedTitle:      "<b>Public Cloud Asset Access (S3)</b> risk at <b>Cloud Asset</b>",
			expectedLikelihood: types.Likely,
			expectedImpact:     types.VeryHighImpact,
			expectedSeverity:   types.ElevatedSeverity,
		},
		"strictly confidential data at bucket": {
			technology: types.FileServer,
			tags:       []string{"aws:s3"},
			stored:     true,
			dataRating: types.StrictlyConfidential,

			riskCreated:        true,
			expectedTitle:      "<b>Public Cloud Asset Access (S3)</b> risk at <b>Cloud Asset</b>",
			expectedLikelihood: types.Unlikely,
			expectedImpact:     types.VeryHighImpact,
			expectedSeverity:   types.ElevatedSeverity,
		},
		"out of scope": {
			technology: types.FileServer,
			tags:       []string{"aws:s3"},
			stored:     true,
			outOfScope: true,
		},
		"no data": {
			technology: types.FileServer,
			tags:       []string{"aws:s3"},
		},
		"virtual file server in the cloud without service tag": {
			technology: types.FileServer,
			machine:    types.Virtual,
			inCloud:    true,
			stored:     true,
		},
		"serverless storage off-cloud": {
			technology: types.FileServer,
			machine:    types.Serverless,
			stored:     true,
		},
		"serverless database in the cloud": {
			technology: types.Database,
			machine:    types.Serverless,
			inCloud:    true,
			stored:     true,
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
						Machine:      testCase.machine,
						Tags:         testCase.tags,
						OutOfScope:   testCase.outOfScope,
						Internet:     testCase.internet,
					},
					"client": {Id: "client", Title: "Client", Internet: testCase.internetLink},
				},
				TrustBoundaries: map[string]*types.TrustBoundary{},
				DataAssets: map[string]*types.DataAsset{
					"da1": {Id: "da1", Confidentiality: testCase.dataRating, Integrity: testCase.dataIntegrity},
				},
				IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
					"ta1": {{Id: "client>ta1", SourceId: "client", TargetId: "ta1"}},
				},
			}
			if testCase.stored {
				model.TechnicalAssets["ta1"].DataAssetsStored = []string{"da1"}
			}
			if testCase.processed {
				model.TechnicalAssets["ta1"].DataAssetsProcessed = []string{"da1"}
			}
			if testCase.inCloud {
				model.TrustBoundaries["tb1"] = &types.TrustBoundary{
					Id: "tb1", Type: types.NetworkCloudProvider, TechnicalAssetsInside: []string{"ta1"},
				}
			}

			risks, err := NewPublicCloudAssetAccessRule().GenerateRisks(model)

			assert.Nil(t, err)
			if !testCase.riskCreated {
				assert.Empty(t, risks)
				return
			}
			require.Len(t, risks, 1)
			assert.Equal(t, testCase.expectedTitle, risks[0].Title)
			assert.Equal(t, testCase.expectedLikelihood, risks[0].ExploitationLikelihood)
			assert.Equal(t, testCase.expectedImpact, risks[0].ExploitationImpact)
			assert.Equal(t, testCase.expectedSeverity, risks[0].Severity)
			assert.Equal(t, "public-cloud-asset-access@ta1", risks[0].SyntheticId)
			assert.Equal(t, "ta1", risks[0].MostRelevantTechnicalAssetId)
			assert.Equal(t, []string{"ta1"}, risks[0].DataBreachTechnicalAssetIDs)
		})
	}
}
