package builtin

import (
	"github.com/Pinguladora/threagile/pkg/types"
)

type InsecureControlProtocolRule struct{}

func NewInsecureControlProtocolRule() *InsecureControlProtocolRule {
	return &InsecureControlProtocolRule{}
}

func (*InsecureControlProtocolRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "insecure-control-protocol",
		Title: "Insecure Control Protocol",
		Description: "Most industrial control protocols, like Modbus, DNP3, S7comm, EtherNet/IP or PROFINET, were " +
			"designed for closed networks: a controller or field device executes every command it receives, without " +
			"checking who sent it or whether it was changed on the way. Anyone who can send packets to it can write " +
			"setpoints and outputs, stop it or download a new program.",
		Impact: "If this risk is unmitigated, attackers in the network might send commands that change, stop or " +
			"damage the physical process, or alter the commands and readings exchanged with the controller.",
		ASVS:       asvsArchitecture,
		CheatSheet: nistOTSecurityURL,
		Action:     "Authenticated Control Protocols",
		Mitigation: "Use the secure variant of the protocol where the devices support it (Modbus/TCP Security, DNP3 " +
			"over TLS or with Secure Authentication, CIP Security, OPC UA with SignAndEncrypt, S7comm-plus with " +
			"access protection), and enable the access protection of the controllers. Where the protocol cannot be " +
			"secured, allow only the expected senders and function codes with an industrial firewall in front of " +
			"the controller, and keep controllers in RUN mode with the key switch.",
		Check:    checkOTGuidance,
		Function: types.Architecture,
		STRIDE:   types.Tampering,
		DetectionLogic: "In-scope controllers (" + types.PLC + ", " + types.RTU + ", " + types.SafetyController + ") and " +
			types.FieldDevice + " technical assets with an incoming non-readonly communication link over an " +
			"industrial control protocol without a secure variant in use (all of them except modbus-security, " +
			"dnp3-encrypted and opc-ua-encrypted).",
		RiskAssessment: "The risk rating depends on the integrity and availability of the controlled process, and is " +
			"the highest for safety controllers. The attack is very likely when the sender is on the internet, likely " +
			"when it is an IT asset, reaches IT or calls across a network trust boundary, and unlikely otherwise.",
		FalsePositives: "Links in an isolated network that only the sender and the receiver are part of can be " +
			"considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweMissingAuthentication,
		References: []string{
			iec62443DeviceAuthentication, iec62443CommunicationIntegrity, mitreICSUnauthorizedCommand,
			mitreICSAdversaryInTheMiddle, nistOTSecurity,
		},
	}
}

func (*InsecureControlProtocolRule) SupportedTags() []string {
	return []string{}
}

func (r *InsecureControlProtocolRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, device := range input.InScopeTechnicalAssets() {
		if !isIndustrialController(device) && !device.Technologies.GetAttribute(types.FieldDevice) {
			continue
		}
		for _, link := range sortedIncomingLinks(input, device) {
			if !link.Readonly && link.Protocol.IsInsecureIndustrialControlProtocol() {
				risks = append(risks, r.createRisk(input, device, link))
			}
		}
	}
	return risks, nil
}

func (r *InsecureControlProtocolRule) createRisk(
	input *types.Model, device *types.TechnicalAsset, link *types.CommunicationLink,
) *types.Risk {
	sender := input.TechnicalAssets[link.SourceId]
	likelihood, senderTitle := types.Likely, link.SourceId
	if sender != nil {
		likelihood, senderTitle = otSenderLikelihood(input, sender, link), sender.Title
	}
	impact := otRiskImpact(input, device)

	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: assetRiskTitle("Insecure Control Protocol", device,
			"over <b>"+link.Protocol.String()+"</b> from <b>"+senderTitle+"</b>"),
		MostRelevantTechnicalAssetId:    device.Id,
		MostRelevantCommunicationLinkId: link.Id,
		DataBreachProbability:           types.Improbable,
		DataBreachTechnicalAssetIDs:     []string{device.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + device.Id + "@" + link.Id
	return risk
}
