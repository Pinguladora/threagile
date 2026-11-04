package builtin

// Category texts several risk rules share.
const (
	checkCheatSheetAndASVS = "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?"

	asvsArchitecture       = "V1 - Architecture, Design and Threat Modeling Requirements"
	asvsAuthentication     = "V2 - Authentication Verification Requirements"
	asvsAccessControl      = "V4 - Access Control Verification Requirements"
	asvsValidation         = "V5 - Validation, Sanitization and Encoding Verification Requirements"
	asvsStoredCryptography = "V6 - Stored Cryptography Verification Requirements"
	asvsMaliciousCode      = "V10 - Malicious Code Verification Requirements"
	asvsFilesAndResources  = "V12 - File and Resources Verification Requirements"
	asvsConfiguration      = "V14 - Configuration Verification Requirements"

	cheatSheetAttackSurfaceAnalysis = "https://cheatsheetseries.owasp.org/cheatsheets/" +
		"Attack_Surface_Analysis_Cheat_Sheet.html"
	cheatSheetThreatModeling = "https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html"

	actionAttackSurfaceReduction = "Attack Surface Reduction"
	actionBuildPipelineHardening = "Build Pipeline Hardening"
	actionNetworkSegmentation    = "Network Segmentation"

	ratingByAssetAndProcessedDataSensitivity = "The risk rating depends on the sensitivity of the technical asset " +
		"itself and of the data assets processed."
	falsePositivesIncompleteModel = "Usually no false positives as this looks like an incomplete model."
)
