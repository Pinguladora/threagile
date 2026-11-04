package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

// cweExposureToWrongSphere is CWE-668: Exposure of Resource to Wrong Sphere.
const cweExposureToWrongSphere = 668

const (
	awsEBSBlockPublicAccess = "https://docs.aws.amazon.com/ebs/latest/userguide/block-public-access-snapshots.html"
	awsAMIBlockPublicAccess = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/block-public-access-to-amis.html"
	awsConfigEBSSnapshots   = "https://docs.aws.amazon.com/config/latest/developerguide/" +
		"ebs-snapshot-public-restorable-check.html"
	awsConfigRDSSnapshots = "https://docs.aws.amazon.com/config/latest/developerguide/" +
		"rds-snapshots-public-prohibited.html"
	cheatSheetSecretsManagement = "https://cheatsheetseries.owasp.org/cheatsheets/" +
		"Secrets_Management_Cheat_Sheet.html"
)

type PublicCloudSnapshotRule struct{}

func NewPublicCloudSnapshotRule() *PublicCloudSnapshotRule {
	return &PublicCloudSnapshotRule{}
}

func (*PublicCloudSnapshotRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "public-cloud-snapshot",
		Title: "Publicly Shared Cloud Snapshot",
		Description: "Snapshots and images of cloud disks, databases and virtual machines (like EBS or RDS " +
			"snapshots and EC2 AMIs) can be shared with all accounts of the cloud provider. A snapshot shared " +
			"publicly by mistake hands everything stored on the asset to anyone.",
		Impact: "If this risk is unmitigated, attackers might restore a publicly shared snapshot or image and read " +
			"the data stored on it, including credentials baked into an image.",
		ASVS:       asvsConfiguration,
		CheatSheet: cheatSheetSecureCloudArchitecture,
		Action:     "Snapshot Sharing Restrictions",
		Mitigation: "Prevent the public sharing of snapshots and images with a cloud configuration rule that " +
			"revokes it, and audit the sharing settings regularly. Do not bake credentials into images; see " +
			"the secrets management cheat sheet at " + htmlLink(cheatSheetSecretsManagement) + ". " +
			"<br><br>For <b>Amazon Web Services (AWS)</b>: Turn on <i>block public access</i> for EBS " +
			"snapshots (" + htmlLink(awsEBSBlockPublicAccess) + ") and for AMIs (" +
			htmlLink(awsAMIBlockPublicAccess) + ") in every region, use the AWS Config managed rules " +
			"<i>ebs-snapshot-public-restorable-check</i> (" + htmlLink(awsConfigEBSSnapshots) + ") and " +
			"<i>rds-snapshots-public-prohibited</i> (" + htmlLink(awsConfigRDSSnapshots) + ") with an " +
			"automatic remediation, and review the snapshot findings of <i>IAM Access Analyzer</i> (" +
			htmlLink(awsIAMAccessAnalyzer) + ").",
		Check:    checkCheatSheetAndASVS,
		Function: types.Operations,
		STRIDE:   types.InformationDisclosure,
		DetectionLogic: "In-scope cloud technical assets (residing in cloud trust boundaries or tagged with cloud " +
			"provider tags) storing data assets, that are either tagged as snapshot-capable services (aws:ebs, " +
			"aws:rds, aws:ec2 for AMIs) or are " + types.Database + " or " + types.BlockStorage + " assets.",
		RiskAssessment: "The risk rating depends on the confidentiality of the technical asset itself and of the " +
			"data assets stored, as a snapshot discloses the stored data but does not alter it.",
		FalsePositives: "Cloud assets whose snapshots and images are not shared at all, or are shared only with " +
			"fixed accounts while public sharing is blocked at the account level, can be considered as false " +
			"positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweExposureToWrongSphere,
	}
}

// snapshotTags map the tags of snapshot-capable services to the kind of snapshot they share.
var snapshotTags = []struct {
	Tag  string
	Kind string
}{
	{"aws:rds", "RDS"},
	{"aws:ebs", "EBS"},
	{"aws:ec2", "AMI"},
}

func (*PublicCloudSnapshotRule) SupportedTags() []string {
	tags := make([]string, 0, len(snapshotTags))
	for _, snapshotTag := range snapshotTags {
		tags = append(tags, snapshotTag.Tag)
	}
	return tags
}

func (r *PublicCloudSnapshotRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, technicalAsset := range input.InScopeTechnicalAssets() {
		if len(technicalAsset.DataAssetsStored) == 0 || !isCloudTechnicalAsset(input, technicalAsset) {
			continue
		}

		kind, tagged := snapshotKind(input, technicalAsset)
		if !tagged && !technicalAsset.Technologies.GetAttribute(types.Database, types.BlockStorage) {
			continue
		}
		risks = append(risks, r.createRisk(input, technicalAsset, kind))
	}
	return risks, nil
}

// snapshotKind returns the kind of snapshot of the first snapshot-capable service tag found on the asset, a
// trust boundary around it or its shared runtime.
func snapshotKind(input *types.Model, technicalAsset *types.TechnicalAsset) (string, bool) {
	for _, snapshotTag := range snapshotTags {
		if isTechnicalAssetTaggedWithAnyTraversingUp(input, technicalAsset, snapshotTag.Tag) {
			return snapshotTag.Kind, true
		}
	}
	return "", false
}

func (r *PublicCloudSnapshotRule) createRisk(
	input *types.Model, technicalAsset *types.TechnicalAsset, kind string,
) *types.Risk {
	if kind != "" {
		kind = " (" + kind + ")"
	}

	impact := cloudRiskImpact(input.HighestStoredConfidentiality(technicalAsset), types.Archive, types.Archive)
	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood: types.Unlikely,
		ExploitationImpact:     impact,
		Title: "<b>Publicly Shared Cloud Snapshot" + kind + "</b> risk at <b>" +
			technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
