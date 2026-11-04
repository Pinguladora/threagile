package builtin

import (
	"maps"
	"slices"
	"strings"

	"github.com/Pinguladora/threagile/pkg/types"
)

type SharedMachineAccountRule struct{}

func NewSharedMachineAccountRule() *SharedMachineAccountRule {
	return &SharedMachineAccountRule{}
}

func (*SharedMachineAccountRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "shared-machine-account",
		Title: "Shared Machine Account",
		Description: "Several technical assets that call others with one service account, API key or workload " +
			"identity share all of its permissions: each can do what any of them needs, and the targets cannot " +
			"tell them apart.",
		Impact: "If this risk is unmitigated, attackers who compromise any one of the callers might use the shared " +
			"account to access everything the other callers can, and the logs would not show which caller acted.",
		ASVS:       asvsAccessControl,
		CheatSheet: cheatSheetSecretsManagement,
		Action:     "One Account per Workload",
		Mitigation: "Give each technical asset an account of its own, preferably a workload identity issued by the " +
			"platform, with only the permissions it needs, so that its compromise stays contained and its actions " +
			"can be told apart.",
		Check:    checkCheatSheetAndASVS,
		Function: types.Operations,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "In-scope technical assets with a communication link naming an <i>account</i> that " +
			"communication links of other technical assets name as well, with the identity <i>" +
			types.ServiceAccount.String() + "</i> or <i>" + types.Workload.String() + "</i>. Links that name no " +
			"account are skipped.",
		RiskAssessment: "The risk rating depends on the sensitivity of the data processed or stored by the targets " +
			"of all links of the account. The attack is likely when the callers are in different trust boundaries, " +
			"so that the compromise of one crosses into others, and unlikely otherwise.",
		FalsePositives: "Replicas of one service that share its account, modelled as separate technical assets, " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        cweImproperIsolation,
		References:                 []string{owaspNHIReuse, owaspAgenticPrivilegeAbuse},
	}
}

func (*SharedMachineAccountRule) SupportedTags() []string {
	return []string{}
}

func (r *SharedMachineAccountRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	linksByAccount := make(map[string][]*types.CommunicationLink)
	for _, id := range input.SortedTechnicalAssetIDs() {
		for _, link := range input.TechnicalAssets[id].CommunicationLinksSorted() {
			if link.Account != "" && isMachineIdentity(link.Identity) {
				linksByAccount[link.Account] = append(linksByAccount[link.Account], link)
			}
		}
	}

	risks := make([]*types.Risk, 0)
	for _, account := range slices.Sorted(maps.Keys(linksByAccount)) {
		links := linksByAccount[account]
		callers := linkSources(links)
		if len(callers) == 1 { // the account of a single caller is not shared
			continue
		}
		for _, callerId := range callers {
			if caller := input.TechnicalAssets[callerId]; !caller.OutOfScope {
				risks = append(risks, r.createRisk(input, account, caller, links, callers))
			}
		}
	}
	return risks, nil
}

// linkSources returns the ids of the sources of the links, sorted and once each.
func linkSources(links []*types.CommunicationLink) []string {
	sources := make([]string, 0, len(links))
	for _, link := range links {
		sources = append(sources, link.SourceId)
	}
	slices.Sort(sources)
	return slices.Compact(sources)
}

// inDifferentTrustBoundaries reports whether the technical assets are not all directly inside the same trust
// boundary, or all outside of any.
func inDifferentTrustBoundaries(input *types.Model, ids []string) bool {
	boundaries := make(map[string]bool)
	for _, id := range ids {
		boundaryId := ""
		if boundary, ok := input.DirectContainingTrustBoundaryMappedByTechnicalAssetId[id]; ok && boundary != nil {
			boundaryId = boundary.Id
		}
		boundaries[boundaryId] = true
	}
	return len(boundaries) > 1
}

func (r *SharedMachineAccountRule) createRisk(
	input *types.Model, account string, caller *types.TechnicalAsset, links []*types.CommunicationLink,
	callers []string,
) *types.Risk {
	likelihood := types.Unlikely
	if inDifferentTrustBoundaries(input, callers) {
		likelihood = types.Likely
	}

	impact := types.LowImpact
	targets := make([]string, 0, len(links))
	var callerLink *types.CommunicationLink
	for _, link := range links {
		if target, ok := input.TechnicalAssets[link.TargetId]; ok {
			impact = max(impact, assetImpact(input, target))
			targets = append(targets, target.Id)
		}
		if callerLink == nil && link.SourceId == caller.Id {
			callerLink = link
		}
	}
	slices.Sort(targets)

	others := make([]string, 0, len(callers)-1)
	for _, otherId := range callers {
		if otherId != caller.Id {
			others = append(others, "<b>"+input.TechnicalAssets[otherId].Title+"</b>")
		}
	}

	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: assetRiskTitle("Shared Machine Account", caller,
			"sharing <b>"+account+"</b> with "+strings.Join(others, ", ")),
		MostRelevantTechnicalAssetId:    caller.Id,
		MostRelevantCommunicationLinkId: callerLink.Id,
		DataBreachProbability:           types.Possible,
		DataBreachTechnicalAssetIDs:     slices.Compact(targets),
	}
	risk.SyntheticId = risk.CategoryId + "@" + caller.Id + "@" + account
	return risk
}
