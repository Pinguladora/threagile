package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

// cweIncorrectPermissionAssignment is CWE-732: Incorrect Permission Assignment for Critical Resource.
const cweIncorrectPermissionAssignment = 732

const awsS3BlockPublicAccess = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/" +
	"access-control-block-public-access.html"

type PublicCloudAssetAccessRule struct{}

func NewPublicCloudAssetAccessRule() *PublicCloudAssetAccessRule {
	return &PublicCloudAssetAccessRule{}
}

func (*PublicCloudAssetAccessRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "public-cloud-asset-access",
		Title: "Public Cloud Asset Access",
		Description: "Cloud storage and messaging services like object storage buckets or message queues are " +
			"governed by resource policies and access control lists. A policy with wildcards (like a principal " +
			"of <i>\"*\"</i>) or an ACL granting access to all users makes the asset public.",
		Impact: "If this risk is unmitigated, anyone on the internet might read (data leakage), alter or delete " +
			"(tampering) the data held by the cloud asset.",
		ASVS:       asvsAccessControl,
		CheatSheet: cheatSheetSecureCloudArchitecture,
		Action:     "Cloud Access Policies",
		Mitigation: "Audit the resource policies and ACLs of the cloud asset regularly and reduce the granted " +
			"rights to the bare minimum: no wildcard principals or actions, and conditions that pin access to " +
			"the expected accounts, VPCs or endpoints. Label the assets that have to be public and isolate them " +
			"from the non-public ones. " +
			"<br><br>For <b>Amazon Web Services (AWS)</b>: Turn on <i>S3 Block Public Access</i> at the account " +
			"level (see " + htmlLink(awsS3BlockPublicAccess) + ") " +
			"and review the public and cross-account findings of <i>IAM Access Analyzer</i>, which covers S3 " +
			"buckets, SQS queues and further resource types (see " + htmlLink(awsIAMAccessAnalyzer) + ").",
		Check:    checkCheatSheetAndASVS,
		Function: types.Operations,
		STRIDE:   types.InformationDisclosure,
		DetectionLogic: "In-scope cloud technical assets (residing in cloud trust boundaries or tagged with cloud " +
			"provider tags) processing or storing data assets, that are either tagged as resource-policy governed " +
			"services (aws:s3, aws:sqs) or are serverless file storage (like " + types.FileServer + "), " +
			types.DataLake + " or " + types.MessageQueue + " assets, which is how managed cloud storage and " +
			"queue services are modelled.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data " +
			"assets processed and stored. The likelihood rises when the asset is reachable from the internet " +
			"(the internet flag of the asset or a communication link from an internet asset).",
		FalsePositives: "Cloud assets whose resource policies and ACLs grant access only to fixed principals " +
			"(and that block public access at the account level) can be considered as false positives after " +
			"individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweIncorrectPermissionAssignment,
	}
}

// publicAccessTags are the tags of cloud services whose access is governed by resource policies or ACLs.
var publicAccessTags = []string{"aws:s3", "aws:sqs"}

func (*PublicCloudAssetAccessRule) SupportedTags() []string {
	return publicAccessTags
}

func (r *PublicCloudAssetAccessRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, technicalAsset := range input.InScopeTechnicalAssets() {
		if len(technicalAsset.DataAssetsStored) == 0 && len(technicalAsset.DataAssetsProcessed) == 0 {
			continue
		}
		if !isCloudTechnicalAsset(input, technicalAsset) {
			continue
		}
		if !isTechnicalAssetTaggedWithAnyTraversingUp(input, technicalAsset, publicAccessTags...) &&
			!isServerlessCloudStorage(technicalAsset) {
			continue
		}
		risks = append(risks, r.createRisk(input, technicalAsset))
	}
	return risks, nil
}

// isServerlessCloudStorage reports whether the asset is modelled like a managed cloud storage or queue service.
func isServerlessCloudStorage(technicalAsset *types.TechnicalAsset) bool {
	return technicalAsset.Machine == types.Serverless &&
		technicalAsset.Technologies.GetAttribute(types.IsFileStorage, types.DataLake, types.MessageQueue)
}

// isReachableFromInternet reports whether the asset is flagged as internet-facing or an internet asset
// communicates with it.
func isReachableFromInternet(input *types.Model, technicalAsset *types.TechnicalAsset) bool {
	if technicalAsset.Internet {
		return true
	}
	for _, incomingLink := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
		if source, ok := input.TechnicalAssets[incomingLink.SourceId]; ok && source.Internet {
			return true
		}
	}
	return false
}

func (r *PublicCloudAssetAccessRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	service := ""
	switch {
	case isTechnicalAssetTaggedWithAnyTraversingUp(input, technicalAsset, "aws:s3"):
		service = " (S3)"
	case isTechnicalAssetTaggedWithAnyTraversingUp(input, technicalAsset, "aws:sqs"):
		service = " (SQS)"
	}

	likelihood := types.Unlikely
	if isReachableFromInternet(input, technicalAsset) {
		likelihood = types.Likely
	}
	impact := cloudRiskImpact(
		input.HighestTechnicalAssetConfidentiality(technicalAsset),
		input.HighestIntegrity(technicalAsset),
		input.HighestAvailability(technicalAsset),
	)

	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: "<b>Public Cloud Asset Access" + service + "</b> risk at <b>" +
			technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
