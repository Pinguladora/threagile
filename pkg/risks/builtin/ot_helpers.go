package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

// The entries of the OT security standards and catalogs that the OT risk rules reference: the system requirements
// of IEC 62443-3-3, the techniques of MITRE ATT&CK for ICS, IEC 61511 on safety instrumented systems and NIST
// SP 800-82.
const (
	iec62443NetworkSegmentation      = "IEC 62443-3-3 SR 5.1 Network Segmentation"
	iec62443ZoneBoundaryProtection   = "IEC 62443-3-3 SR 5.2 Zone Boundary Protection"
	iec62443DeviceAuthentication     = "IEC 62443-3-3 SR 1.2 Software Process and Device Identification and Authentication"
	iec62443CommunicationIntegrity   = "IEC 62443-3-3 SR 3.1 Communication Integrity"
	iec61511SafetyIndependence       = "IEC 61511 Independence of the Safety Instrumented System"
	mitreICSInternetAccessibleDevice = "MITRE ATT&CK for ICS T0883 Internet Accessible Device"
	mitreICSRemoteServices           = "MITRE ATT&CK for ICS T0886 Remote Services"
	mitreICSUnauthorizedCommand      = "MITRE ATT&CK for ICS T0855 Unauthorized Command Message"
	mitreICSAdversaryInTheMiddle     = "MITRE ATT&CK for ICS T0830 Adversary-in-the-Middle"
	mitreICSProgramDownload          = "MITRE ATT&CK for ICS T0843 Program Download"
	mitreICSLossOfSafety             = "MITRE ATT&CK for ICS T0880 Loss of Safety"
	nistOTSecurity                   = "NIST SP 800-82r3 Guide to Operational Technology (OT) Security"

	nistOTSecurityURL = "https://csrc.nist.gov/pubs/sp/800/82/r3/final"
	checkOTGuidance   = "Are the recommendations of NIST SP 800-82 and the referenced IEC 62443 requirements applied?"
)

// industrialDMZTag marks a technical asset in the industrial DMZ, like a jump host or a replicated historian, that
// IT and OT assets may both talk to.
const industrialDMZTag = "industrial-dmz"

// isOTAsset reports whether the technical asset is part of an industrial control system.
func isOTAsset(technicalAsset *types.TechnicalAsset) bool {
	return technicalAsset.Technologies.GetAttribute(types.IsOperationalTechnology)
}

// isIndustrialController reports whether the technical asset is a controller of an industrial process: a PLC, an
// RTU or a safety controller.
func isIndustrialController(technicalAsset *types.TechnicalAsset) bool {
	return technicalAsset.Technologies.GetAttribute(types.IsIndustrialController)
}

// isSafetyController reports whether the technical asset is the controller of a safety instrumented system.
func isSafetyController(technicalAsset *types.TechnicalAsset) bool {
	return technicalAsset.Technologies.GetAttribute(types.SafetyController)
}

// isEngineeringWorkstation reports whether the technical asset programs and configures controllers.
func isEngineeringWorkstation(technicalAsset *types.TechnicalAsset) bool {
	return technicalAsset.Technologies.GetAttribute(types.EngineeringWorkstation)
}

// isIndustrialDMZ reports whether the technical asset sits between IT and OT: a historian, or an asset tagged
// industrial-dmz.
func isIndustrialDMZ(technicalAsset *types.TechnicalAsset) bool {
	return technicalAsset.Technologies.GetAttribute(types.Historian) || technicalAsset.IsTaggedWithAny(industrialDMZTag)
}

// isControlZoneAsset reports whether the technical asset belongs into the control zones of an industrial control
// system, which IT assets should reach only through the industrial DMZ.
func isControlZoneAsset(technicalAsset *types.TechnicalAsset) bool {
	return isOTAsset(technicalAsset) && !isIndustrialDMZ(technicalAsset)
}

// isITAsset reports whether the technical asset is neither part of an industrial control system nor in the
// industrial DMZ.
func isITAsset(technicalAsset *types.TechnicalAsset) bool {
	return !isOTAsset(technicalAsset) && !isIndustrialDMZ(technicalAsset)
}

// reachesIT reports whether the technical asset is on the internet or has a communication link, in either
// direction, with an IT asset.
func reachesIT(input *types.Model, technicalAsset *types.TechnicalAsset) bool {
	if technicalAsset.Internet {
		return true
	}
	for _, link := range technicalAsset.CommunicationLinks {
		if target, ok := input.TechnicalAssets[link.TargetId]; ok && isITAsset(target) {
			return true
		}
	}
	for _, link := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
		if source, ok := input.TechnicalAssets[link.SourceId]; ok && isITAsset(source) {
			return true
		}
	}
	return false
}

// otSenderLikelihood rates how likely attackers send through the link from the sender: very likely from the
// internet, likely from IT, from an asset that reaches IT or across a network trust boundary, and unlikely
// otherwise.
func otSenderLikelihood(
	input *types.Model, sender *types.TechnicalAsset, link *types.CommunicationLink,
) types.RiskExploitationLikelihood {
	switch {
	case sender.Internet:
		return types.VeryLikely
	case isITAsset(sender), reachesIT(input, sender), isAcrossTrustBoundaryNetworkOnly(input, link):
		return types.Likely
	default:
		return types.Unlikely
	}
}

// otRiskImpact rates the impact of an OT risk at a technical asset: very high for safety controllers, whose
// failure endangers people, and otherwise by the integrity and availability of the process it controls.
func otRiskImpact(input *types.Model, technicalAsset *types.TechnicalAsset) types.RiskExploitationImpact {
	if isSafetyController(technicalAsset) {
		return types.VeryHighImpact
	}
	return impactOfRatings(types.Public, input.HighestIntegrity(technicalAsset), input.HighestAvailability(technicalAsset))
}
