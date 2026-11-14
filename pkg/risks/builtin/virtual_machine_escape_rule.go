package builtin

import (
	"slices"

	"github.com/Pinguladora/threagile/pkg/types"
)

// VirtualMachineEscapeRule reports hypervisors: code that escapes a virtual machine runs on its host, next to every
// other guest of it. It is the container escape of virtual machines.
type VirtualMachineEscapeRule struct{}

func NewVirtualMachineEscapeRule() *VirtualMachineEscapeRule {
	return &VirtualMachineEscapeRule{}
}

func (*VirtualMachineEscapeRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "virtual-machine-escape",
		Title: "Virtual Machine Escape",
		Description: "A hypervisor isolates its guests from its host and from each other, and sandboxes like Kata " +
			"Containers or Firecracker rely on that to run untrusted code. Code that exploits a vulnerability of the " +
			"hypervisor or of the devices it emulates escapes its virtual machine and runs on the host, with the " +
			"privileges of the hypervisor, next to the host's own services and every other guest.",
		Impact: "If this risk is unmitigated, attackers who control a guest, or the code it runs, might take over the " +
			"host and from there every other virtual machine on it and the services the host runs.",
		ASVS:       asvsConfiguration,
		CheatSheet: "https://csrc.nist.gov/pubs/sp/800/125/a/r1/final",
		Action:     "Hypervisor Hardening",
		Mitigation: "Keep the hypervisor, its device emulation and the host kernel patched, and prefer a hypervisor " +
			"with a small device model, like <i>Firecracker</i> or <i>Cloud Hypervisor</i>. Run it as an unprivileged " +
			"user with a seccomp filter and in its own namespaces, like the <i>Firecracker jailer</i> does, and keep " +
			"host services that hold secrets away from hosts that run untrusted guests. Where the host itself is not " +
			"trusted, consider confidential virtual machines (<i>AMD SEV-SNP</i>, <i>Intel TDX</i>).",
		Check:    checkCheatSheetAndASVS,
		Function: types.Operations,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "Technical assets of the technology " + types.Hypervisor + ". Their host is the trust boundary " +
			"that holds them and their guests are the technical assets of the trust boundaries nested in it. An " +
			"in-scope hypervisor gets the risk. For an out-of-scope one, like the hypervisor of a cloud or a sandbox " +
			"runtime, each in-scope technical asset of its host gets it, since those are what an escape reaches.",
		RiskAssessment: "Escapes are unlikely. The impact is high when a technical asset of the host or of its guests " +
			"processes " + types.StrictlyConfidential.String() + " or " + types.MissionCritical.String() + " data, " +
			"and medium otherwise.",
		FalsePositives: "Hypervisors that only run trusted guests, on hosts that run nothing else, can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweArchitecturalConcepts,
		References:                 []string{owaspSecurityMisconfiguration},
	}
}

func (*VirtualMachineEscapeRule) SupportedTags() []string {
	return []string{}
}

func (r *VirtualMachineEscapeRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		hypervisor := input.TechnicalAssets[id]
		if !hypervisor.Technologies.GetAttribute(types.Hypervisor) {
			continue
		}
		host, exposed := hostOf(input, hypervisor)
		impact := r.impact(input, exposed)
		if !hypervisor.OutOfScope {
			risks = append(risks, r.createRisk(hypervisor, hypervisor, impact, exposed))
			continue
		}
		for _, assetId := range host {
			if asset := input.TechnicalAssets[assetId]; !asset.OutOfScope {
				risks = append(risks, r.createRisk(hypervisor, asset, impact, exposed))
			}
		}
	}
	return risks, nil
}

// hostOf returns the technical assets on the host of the hypervisor, itself left out, and all that an escape exposes:
// the hypervisor, its host and its guests. The host is the trust boundary that directly holds the hypervisor, and
// without one it is the hypervisor alone.
func hostOf(input *types.Model, hypervisor *types.TechnicalAsset) ([]string, []string) {
	boundary := input.DirectContainingTrustBoundaryMappedByTechnicalAssetId[hypervisor.Id]
	if boundary == nil {
		return nil, []string{hypervisor.Id}
	}
	host := slices.DeleteFunc(slices.Clone(boundary.TechnicalAssetsInside),
		func(id string) bool { return id == hypervisor.Id })
	slices.Sort(host)
	exposed := input.RecursivelyAllTechnicalAssetIDsInside(boundary)
	slices.Sort(exposed)
	return host, slices.Compact(exposed)
}

// impact is high when an exposed technical asset processes strictly confidential or mission-critical data.
func (*VirtualMachineEscapeRule) impact(input *types.Model, exposed []string) types.RiskExploitationImpact {
	for _, id := range exposed {
		asset := input.TechnicalAssets[id]
		if input.HighestProcessedConfidentiality(asset) == types.StrictlyConfidential ||
			input.HighestProcessedIntegrity(asset) == types.MissionCritical ||
			input.HighestProcessedAvailability(asset) == types.MissionCritical {
			return types.HighImpact
		}
	}
	return types.MediumImpact
}

func (r *VirtualMachineEscapeRule) createRisk(hypervisor *types.TechnicalAsset, asset *types.TechnicalAsset,
	impact types.RiskExploitationImpact, exposed []string,
) *types.Risk {
	title := "<b>Virtual Machine Escape</b> risk at <b>" + hypervisor.Title + "</b>"
	syntheticId := r.Category().ID + "@" + hypervisor.Id
	if asset != hypervisor {
		title += " exposing <b>" + asset.Title + "</b>"
		syntheticId += "@" + asset.Id
	}
	return &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood:       types.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		SyntheticId:                  syntheticId,
		MostRelevantTechnicalAssetId: asset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  exposed,
	}
}
