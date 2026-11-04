package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

const (
	awsKMSKeyDeletion      = "https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html"
	awsKMSKeyDeletionAlarm = "https://docs.aws.amazon.com/kms/latest/developerguide/" +
		"deleting-keys-creating-cloudwatch-alarm.html"
	azureKeyVaultSoftDelete = "https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview"
	gcpKMSDestroyRestore    = "https://docs.cloud.google.com/kms/docs/destroy-restore"
	cheatSheetKeyManagement = "https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html"
)

type EncryptionKeyDeletionRule struct{}

func NewEncryptionKeyDeletionRule() *EncryptionKeyDeletionRule {
	return &EncryptionKeyDeletionRule{}
}

func (*EncryptionKeyDeletionRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "encryption-key-deletion",
		Title: "Denial of Service by Encryption Key Deletion",
		Description: "Data in cloud storage encrypted with a key from a cloud key management service (like AWS " +
			"KMS, Azure Key Vault or Google Cloud KMS) can only be decrypted as long as the key exists. Deleting " +
			"the key, by mistake or by an attacker with enough rights, makes the data permanently unusable.",
		Impact: "If this risk is unmitigated, attackers might schedule the deletion of the encryption key and so " +
			"destroy the encrypted data for good (crypto-shredding), much like ransomware without a ransom.",
		ASVS:       asvsStoredCryptography,
		CheatSheet: cheatSheetKeyManagement,
		Action:     "Encryption Key Deletion Protection",
		Mitigation: "Restrict the right to delete or schedule the deletion of keys to a few dedicated principals, " +
			"use the longest deletion window the key management service offers, monitor and alert on scheduled " +
			"key deletions and on any use of a key pending deletion, and use cloud configuration rules that " +
			"deny or revert key deletions. " +
			"<br><br>For <b>Amazon Web Services (AWS)</b>: Keep the default (and maximum) waiting period of " +
			"30 days for deleting KMS keys (see " + htmlLink(awsKMSKeyDeletion) + ") and alarm on the use of " +
			"keys pending deletion (see " + htmlLink(awsKMSKeyDeletionAlarm) + "). " +
			"<br>For <b>Microsoft Azure</b>: Turn on soft-delete and purge protection for the key vault (see " +
			htmlLink(azureKeyVaultSoftDelete) + "). " +
			"<br>For <b>Google Cloud Platform</b>: Keep a long scheduled-for-destruction duration for key versions " +
			"(see " + htmlLink(gcpKMSDestroyRestore) + ").",
		Check:    checkCheatSheetAndASVS,
		Function: types.Operations,
		STRIDE:   types.DenialOfService,
		DetectionLogic: "In-scope encrypted cloud technical assets (residing in cloud trust boundaries or tagged " +
			"with cloud provider tags) storing data assets, which are either tagged as encrypted with a key from " +
			"a cloud key management service (aws:kms, azure:keyvault, gcp:kms on the asset, a trust boundary " +
			"around it or its shared runtime) or communicate with a cloud " + types.Vault + " or " + types.HSM +
			" asset. Key stores themselves are excluded.",
		RiskAssessment: "The risk rating depends on the availability rating of the technical asset itself and " +
			"of the data assets stored, as the deletion destroys the data but does not disclose it.",
		FalsePositives: "Cloud assets encrypted with keys the cloud provider manages and does not let anyone " +
			"delete (like AWS managed keys), or whose key deletion is guarded as described in the mitigation, " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweIncorrectPermissionAssignment,
	}
}

// keyManagementTags are the tags of the key management services of the cloud providers.
var keyManagementTags = []string{"aws:kms", "azure:keyvault", "gcp:kms"}

func (*EncryptionKeyDeletionRule) SupportedTags() []string {
	return keyManagementTags
}

func (r *EncryptionKeyDeletionRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, technicalAsset := range input.InScopeTechnicalAssets() {
		if technicalAsset.Encryption == types.NoneEncryption || len(technicalAsset.DataAssetsStored) == 0 {
			continue
		}
		if isKeyStore(technicalAsset) || !isCloudTechnicalAsset(input, technicalAsset) {
			continue
		}

		keyStore := cloudKeyStoreUsedBy(input, technicalAsset)
		if keyStore == nil && !isTechnicalAssetTaggedWithAnyTraversingUp(input, technicalAsset, keyManagementTags...) {
			continue
		}
		risks = append(risks, r.createRisk(input, technicalAsset, keyStore))
	}
	return risks, nil
}

func isKeyStore(technicalAsset *types.TechnicalAsset) bool {
	return technicalAsset.Technologies.GetAttribute(types.Vault, types.HSM)
}

// cloudKeyStoreUsedBy returns the first cloud key store the technical asset communicates with: a vault or HSM
// in the cloud, or an asset tagged with a key management service tag.
func cloudKeyStoreUsedBy(input *types.Model, technicalAsset *types.TechnicalAsset) *types.TechnicalAsset {
	for _, link := range technicalAsset.CommunicationLinksSorted() {
		target, ok := input.TechnicalAssets[link.TargetId]
		if !ok {
			continue
		}
		if target.IsTaggedWithAny(keyManagementTags...) || (isKeyStore(target) && isCloudTechnicalAsset(input, target)) {
			return target
		}
	}
	return nil
}

func (r *EncryptionKeyDeletionRule) createRisk(
	input *types.Model, technicalAsset *types.TechnicalAsset, keyStore *types.TechnicalAsset,
) *types.Risk {
	title := "<b>Denial of Service by Encryption Key Deletion</b> risk at <b>" + technicalAsset.Title + "</b>"
	if keyStore != nil {
		title += " with keys from <b>" + keyStore.Title + "</b>"
	}

	impact := cloudRiskImpact(types.Public, types.Archive, input.HighestStoredAvailability(technicalAsset))
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood:       types.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
