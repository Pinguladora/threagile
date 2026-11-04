package builtin

// The CWE ids (https://cwe.mitre.org) of the weaknesses the built-in rules detect.
const (
	cweConfiguration                      = 16   // CWE-16: Configuration
	cwePathTraversal                      = 22   // CWE-22: Path Traversal
	cweInjection                          = 74   // CWE-74: Injection
	cweCrossSiteScripting                 = 79   // CWE-79: Cross-site Scripting
	cweSQLInjection                       = 89   // CWE-89: SQL Injection
	cweLDAPInjection                      = 90   // CWE-90: LDAP Injection
	cweSensitiveInformationExposure       = 200  // CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
	cweImproperAccessControl              = 284  // CWE-284: Improper Access Control
	cweImproperAuthentication             = 287  // CWE-287: Improper Authentication
	cweMissingAuthentication              = 306  // CWE-306: Missing Authentication for Critical Function
	cweSingleFactorAuthentication         = 308  // CWE-308: Use of Single-factor Authentication
	cweMissingEncryption                  = 311  // CWE-311: Missing Encryption of Sensitive Data
	cweCleartextTransmission              = 319  // CWE-319: Cleartext Transmission of Sensitive Information
	cweCrossSiteRequestForgery            = 352  // CWE-352: Cross-Site Request Forgery (CSRF)
	cweUncontrolledResourceConsumption    = 400  // CWE-400: Uncontrolled Resource Consumption
	cweUnrestrictedFileUpload             = 434  // CWE-434: Unrestricted Upload of File with Dangerous Type
	cweTrustBoundaryViolation             = 501  // CWE-501: Trust Boundary Violation
	cweUntrustedDeserialization           = 502  // CWE-502: Deserialization of Untrusted Data
	cweInsufficientlyProtectedCredentials = 522  // CWE-522: Insufficiently Protected Credentials
	cweXMLExternalEntity                  = 611  // CWE-611: Improper Restriction of XML External Entity Reference
	cweProtectionMechanismFailure         = 693  // CWE-693: Protection Mechanism Failure
	cweHiddenFunctionality                = 912  // CWE-912: Hidden Functionality
	cweServerSideRequestForgery           = 918  // CWE-918: Server-Side Request Forgery (SSRF)
	cweArchitecturalConcepts              = 1008 // CWE-1008: Architectural Concepts
	cweInsufficientCompilationWarnings    = 1127 // CWE-1127: Compilation with Insufficient Warnings or Errors
)
