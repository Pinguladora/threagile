package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

// The entries of the catalogs and standards that the rules on credentials and authorization reference.
const (
	owaspAPIBrokenObjectLevelAuthorization   = "OWASP API1:2023 Broken Object Level Authorization"
	owaspAPIBrokenFunctionLevelAuthorization = "OWASP API5:2023 Broken Function Level Authorization"
	owaspNHISecretLeakage                    = "OWASP NHI2:2025 Secret Leakage"     // #nosec G101 // a catalog entry
	owaspNHILongLivedSecrets                 = "OWASP NHI7:2025 Long-Lived Secrets" // #nosec G101 // a catalog entry
	owaspNHIReuse                            = "OWASP NHI9:2025 NHI Reuse"
	owaspNHIHumanUse                         = "OWASP NHI10:2025 Human Use of NHI"
	openIDAuthorizationAPI                   = "OpenID AuthZEN Authorization API 1.0"
	nistABAC                                 = "NIST SP 800-162 Guide to Attribute Based Access Control"

	cheatSheetAuthorization = "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"
)

// The CWEs of the rules on credentials and authorization.
const (
	cweUserControlledKey  = 639  // CWE-639: Authorization Bypass Through User-Controlled Key
	cweFailingOpen        = 636  // CWE-636: Not Failing Securely ('Failing Open')
	cweImproperIsolation  = 653  // CWE-653: Improper Isolation or Compartmentalization
	cweWeakAuthentication = 1390 // CWE-1390: Weak Authentication
)

// isPolicyDecisionPoint reports whether the technical asset decides the authorization of other services.
func isPolicyDecisionPoint(technicalAsset *types.TechnicalAsset) bool {
	return technicalAsset.Technologies.GetAttribute(types.PolicyDecisionPoint)
}

// assetImpact rates the impact of a risk at a technical asset by the ratings of the data it processes and stores.
func assetImpact(input *types.Model, technicalAsset *types.TechnicalAsset) types.RiskExploitationImpact {
	return impactOfRatings(input.HighestTechnicalAssetConfidentiality(technicalAsset),
		input.HighestIntegrity(technicalAsset), input.HighestAvailability(technicalAsset))
}

// isSensitive reports whether the technical asset processes or stores data rated at least as confidential or
// critical.
func isSensitive(input *types.Model, technicalAsset *types.TechnicalAsset) bool {
	return assetImpact(input, technicalAsset) >= types.MediumImpact
}

// isMachineIdentity reports whether the identity is the caller's own, a service account or a workload, rather than
// none or that of an end user.
func isMachineIdentity(identity types.Identity) bool {
	return identity == types.ServiceAccount || identity == types.Workload
}
