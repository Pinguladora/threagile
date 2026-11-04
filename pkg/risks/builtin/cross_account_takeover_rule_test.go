package builtin

import (
	"testing"

	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCrossAccountTakeoverRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewCrossAccountTakeoverRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type CrossAccountTakeoverRuleTest struct {
	sourceBoundary    string
	targetBoundary    string
	sourceOutOfScope  bool
	targetOutOfScope  bool
	sourceMultiTenant bool
	targetMultiTenant bool
	confidentiality   types.Confidentiality

	riskCreated        bool
	expectedTitle      string
	expectedLikelihood types.RiskExploitationLikelihood
	expectedImpact     types.RiskExploitationImpact
	expectedSeverity   types.RiskSeverity
}

func TestCrossAccountTakeoverRuleGenerateRisks(t *testing.T) {
	testCases := map[string]CrossAccountTakeoverRuleTest{
		"access from another account": {
			sourceBoundary: "account-a",
			targetBoundary: "account-b",

			riskCreated: true,
			expectedTitle: "<b>Cross-Account Takeover</b> risk at <b>Target</b> in <b>Account B</b> from " +
				"<b>Source</b> in <b>Account A</b> via <b>Access</b>",
			expectedLikelihood: types.Unlikely,
			expectedImpact:     types.MediumImpact,
			expectedSeverity:   types.MediumSeverity,
		},
		"access from a security group of another account": {
			sourceBoundary: "account-a-security-group",
			targetBoundary: "account-b",

			riskCreated: true,
			expectedTitle: "<b>Cross-Account Takeover</b> risk at <b>Target</b> in <b>Account B</b> from " +
				"<b>Source</b> in <b>Account A</b> via <b>Access</b>",
			expectedLikelihood: types.Unlikely,
			expectedImpact:     types.MediumImpact,
			expectedSeverity:   types.MediumSeverity,
		},
		"access from an out-of-scope partner account": {
			sourceBoundary:   "account-a",
			targetBoundary:   "account-b",
			sourceOutOfScope: true,

			riskCreated: true,
			expectedTitle: "<b>Cross-Account Takeover</b> risk at <b>Target</b> in <b>Account B</b> from " +
				"<b>Source</b> in <b>Account A</b> via <b>Access</b>",
			expectedLikelihood: types.Unlikely,
			expectedImpact:     types.MediumImpact,
			expectedSeverity:   types.MediumSeverity,
		},
		"multi-tenant source": {
			sourceBoundary:    "account-a",
			targetBoundary:    "account-b",
			sourceMultiTenant: true,

			riskCreated: true,
			expectedTitle: "<b>Cross-Account Takeover</b> risk at <b>Target</b> in <b>Account B</b> from " +
				"<b>Source</b> in <b>Account A</b> via <b>Access</b>",
			expectedLikelihood: types.Likely,
			expectedImpact:     types.MediumImpact,
			expectedSeverity:   types.ElevatedSeverity,
		},
		"multi-tenant target with strictly confidential data": {
			sourceBoundary:    "account-a",
			targetBoundary:    "account-b",
			targetMultiTenant: true,
			confidentiality:   types.StrictlyConfidential,

			riskCreated: true,
			expectedTitle: "<b>Cross-Account Takeover</b> risk at <b>Target</b> in <b>Account B</b> from " +
				"<b>Source</b> in <b>Account A</b> via <b>Access</b>",
			expectedLikelihood: types.Likely,
			expectedImpact:     types.VeryHighImpact,
			expectedSeverity:   types.ElevatedSeverity,
		},
		"same account": {
			sourceBoundary: "account-a-security-group",
			targetBoundary: "account-a",
		},
		"source on-prem": {
			sourceBoundary: "datacenter",
			targetBoundary: "account-b",
		},
		"source outside any trust boundary": {
			targetBoundary: "account-b",
		},
		"target on-prem": {
			sourceBoundary: "account-a",
			targetBoundary: "datacenter",
		},
		"target out of scope": {
			sourceBoundary:   "account-a",
			targetBoundary:   "account-b",
			targetOutOfScope: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			link := &types.CommunicationLink{Id: "source>access", Title: "Access", SourceId: "source", TargetId: "target"}
			model := &types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"source": {
						Id: "source", Title: "Source", OutOfScope: testCase.sourceOutOfScope,
						MultiTenant: testCase.sourceMultiTenant, CommunicationLinks: []*types.CommunicationLink{link},
					},
					"target": {
						Id: "target", Title: "Target", OutOfScope: testCase.targetOutOfScope,
						MultiTenant: testCase.targetMultiTenant, DataAssetsProcessed: []string{"da1"},
					},
				},
				TrustBoundaries: map[string]*types.TrustBoundary{
					"organization": {
						Id: "organization", Title: "Organization", Type: types.NetworkCloudProvider,
						TrustBoundariesNested: []string{"account-a", "account-b"},
					},
					"account-a": {
						Id: "account-a", Title: "Account A", Type: types.NetworkCloudProvider,
						TrustBoundariesNested: []string{"account-a-security-group"},
					},
					"account-a-security-group": {
						Id: "account-a-security-group", Title: "Account A Security Group", Type: types.NetworkCloudSecurityGroup,
					},
					"account-b":  {Id: "account-b", Title: "Account B", Type: types.NetworkCloudProvider},
					"datacenter": {Id: "datacenter", Title: "Datacenter", Type: types.NetworkOnPrem},
				},
				DataAssets: map[string]*types.DataAsset{
					"da1": {Id: "da1", Confidentiality: testCase.confidentiality},
				},
			}
			for asset, boundary := range map[string]string{"source": testCase.sourceBoundary, "target": testCase.targetBoundary} {
				if boundary != "" {
					tb := model.TrustBoundaries[boundary]
					tb.TechnicalAssetsInside = append(tb.TechnicalAssetsInside, asset)
				}
			}

			risks, err := NewCrossAccountTakeoverRule().GenerateRisks(model)

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
			assert.Equal(t, "cross-account-takeover@target@source@source>access", risks[0].SyntheticId)
			assert.Equal(t, "target", risks[0].MostRelevantTechnicalAssetId)
			assert.Equal(t, "account-b", risks[0].MostRelevantTrustBoundaryId)
			assert.Equal(t, "source>access", risks[0].MostRelevantCommunicationLinkId)
		})
	}
}
