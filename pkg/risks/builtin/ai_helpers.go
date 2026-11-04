package builtin

import (
	"sort"

	"github.com/Pinguladora/threagile/pkg/types"
)

// The entries of the AI threat catalogs that the AI risk rules reference: the OWASP Top 10 for LLM
// Applications 2025, the OWASP Top 10 for Agentic Applications 2026 and the layers of the CSA MAESTRO
// framework for threat modeling agentic AI.
const (
	owaspLLMPromptInjection           = "OWASP LLM01:2025 Prompt Injection"
	owaspLLMSensitiveInformation      = "OWASP LLM02:2025 Sensitive Information Disclosure"
	owaspLLMSupplyChain               = "OWASP LLM03:2025 Supply Chain"
	owaspLLMDataAndModelPoisoning     = "OWASP LLM04:2025 Data and Model Poisoning"
	owaspLLMExcessiveAgency           = "OWASP LLM06:2025 Excessive Agency"
	owaspLLMVectorAndEmbedding        = "OWASP LLM08:2025 Vector and Embedding Weaknesses"
	owaspAgenticGoalHijack            = "OWASP ASI01:2026 Agent Goal Hijack"
	owaspAgenticToolMisuse            = "OWASP ASI02:2026 Tool Misuse and Exploitation"
	owaspAgenticPrivilegeAbuse        = "OWASP ASI03:2026 Identity and Privilege Abuse"
	owaspAgenticSupplyChain           = "OWASP ASI04:2026 Agentic Supply Chain Vulnerabilities"
	owaspAgenticMemoryPoisoning       = "OWASP ASI06:2026 Memory and Context Poisoning"
	owaspAgenticInterAgent            = "OWASP ASI07:2026 Insecure Inter-Agent Communication"
	owaspAgenticCascadingFailures     = "OWASP ASI08:2026 Cascading Failures"
	owaspAgenticRogueAgents           = "OWASP ASI10:2026 Rogue Agents"
	maestroFoundationModels           = "MAESTRO Layer 1: Foundation Models"
	maestroDataOperations             = "MAESTRO Layer 2: Data Operations"
	maestroAgentFrameworks            = "MAESTRO Layer 3: Agent Frameworks"
	maestroDeploymentAndInfrastucture = "MAESTRO Layer 4: Deployment and Infrastructure"
	maestroEvaluationAndObservability = "MAESTRO Layer 5: Evaluation and Observability"
	maestroSecurityAndCompliance      = "MAESTRO Layer 6: Security and Compliance"
	maestroAgentEcosystem             = "MAESTRO Layer 7: Agent Ecosystem"

	cheatSheetLLMPromptInjection = "https://cheatsheetseries.owasp.org/cheatsheets/" +
		"LLM_Prompt_Injection_Prevention_Cheat_Sheet.html"
	owaspGenAIProject = "https://genai.owasp.org/"
)

// The CWEs of the AI risk rules.
const (
	cweUnnecessaryPrivileges       = 250  // CWE-250: Execution with Unnecessary Privileges
	cweInsufficientAuthenticity    = 345  // CWE-345: Insufficient Verification of Data Authenticity
	cweDownloadWithoutIntegrity    = 494  // CWE-494: Download of Code Without Integrity Check
	cweInsufficientLogging         = 778  // CWE-778: Insufficient Logging
	cweImproperLLMPromptNeutralize = 1427 // CWE-1427: Improper Neutralization of Input Used for LLM Prompting
)

// humanInTheLoopTag marks an agent, or a link of an agent, whose actions a human approves before they run.
const humanInTheLoopTag = "human-in-the-loop"

// isLanguageModel reports whether the technical asset is a large language model.
func isLanguageModel(technicalAsset *types.TechnicalAsset) bool {
	return technicalAsset.Technologies.GetAttribute(types.LLM)
}

// isAIAgent reports whether the technical asset is an AI agent.
func isAIAgent(technicalAsset *types.TechnicalAsset) bool {
	return technicalAsset.Technologies.GetAttribute(types.AIAgent)
}

// isAIGuardrail reports whether the technical asset screens the input and output of language models and agents.
func isAIGuardrail(technicalAsset *types.TechnicalAsset) bool {
	return technicalAsset.Technologies.GetAttribute(types.AIGuardrail)
}

// isPromptedAsset reports whether the technical asset takes prompts: a language model or an AI agent.
func isPromptedAsset(technicalAsset *types.TechnicalAsset) bool {
	return isLanguageModel(technicalAsset) || isAIAgent(technicalAsset)
}

// untrustedAssets returns the ids of the technical assets that content no one vetted reaches: internet assets,
// clients used by humans and assets that read from the internet (directly, or through a tool that does), and
// every asset that such an asset sends requests to, transitively.
func untrustedAssets(input *types.Model) map[string]bool {
	untrusted := make(map[string]bool)
	for id, technicalAsset := range input.TechnicalAssets {
		if technicalAsset.Internet || technicalAsset.UsedAsClientByHuman || readsFromInternet(input, technicalAsset) {
			untrusted[id] = true
		}
	}
	for spreadUntrusted(input, untrusted) { // until it marks no more
	}
	return untrusted
}

// spreadUntrusted marks the targets of the links of untrusted assets as untrusted, and reports whether it marked
// any.
func spreadUntrusted(input *types.Model, untrusted map[string]bool) bool {
	changed := false
	for _, id := range input.SortedTechnicalAssetIDs() {
		if !untrusted[id] {
			continue
		}
		for _, link := range input.TechnicalAssets[id].CommunicationLinks {
			if _, ok := input.TechnicalAssets[link.TargetId]; ok && !untrusted[link.TargetId] {
				untrusted[link.TargetId] = true
				changed = true
			}
		}
	}
	return changed
}

// readsFromInternet reports whether the technical asset calls an internet asset, or a tool that calls one, and so
// reads content from the internet in the responses.
func readsFromInternet(input *types.Model, technicalAsset *types.TechnicalAsset) bool {
	for _, link := range technicalAsset.CommunicationLinks {
		target, ok := input.TechnicalAssets[link.TargetId]
		if !ok {
			continue
		}
		if servesInternetContent(target) || callsInternet(input, target) {
			return true
		}
	}
	return false
}

// servesInternetContent reports whether the technical asset is an internet asset whose responses are content of
// the internet. A language model on the internet, like a hosted model API, is not: its responses come from the
// model.
func servesInternetContent(technicalAsset *types.TechnicalAsset) bool {
	return technicalAsset.Internet && !isLanguageModel(technicalAsset)
}

// callsInternet reports whether the technical asset has a communication link to an internet asset serving
// internet content.
func callsInternet(input *types.Model, technicalAsset *types.TechnicalAsset) bool {
	for _, link := range technicalAsset.CommunicationLinks {
		if target, ok := input.TechnicalAssets[link.TargetId]; ok && servesInternetContent(target) {
			return true
		}
	}
	return false
}

// untrustedInputLinks returns, sorted by id, the links that bring untrusted content into the technical asset:
// incoming links from untrusted assets or from across a network trust boundary, and outgoing links to internet
// assets or to tools that call them.
func untrustedInputLinks(
	input *types.Model, untrusted map[string]bool, technicalAsset *types.TechnicalAsset,
) []*types.CommunicationLink {
	links := make([]*types.CommunicationLink, 0)
	for _, incomingLink := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
		if untrusted[incomingLink.SourceId] || isAcrossTrustBoundaryNetworkOnly(input, incomingLink) {
			links = append(links, incomingLink)
		}
	}
	for _, outgoingLink := range technicalAsset.CommunicationLinks {
		target, ok := input.TechnicalAssets[outgoingLink.TargetId]
		if ok && (servesInternetContent(target) || callsInternet(input, target)) {
			links = append(links, outgoingLink)
		}
	}
	sort.Slice(links, func(i, j int) bool { return links[i].Id < links[j].Id })
	return links
}

// takesUntrustedInput reports whether untrusted content reaches the technical asset: it is untrusted itself, or it
// is called across a network trust boundary.
func takesUntrustedInput(input *types.Model, untrusted map[string]bool, technicalAsset *types.TechnicalAsset) bool {
	return untrusted[technicalAsset.Id] || len(untrustedInputLinks(input, untrusted, technicalAsset)) > 0
}

// isInternetAdjacent reports whether the technical asset is on the internet or talks to an internet asset
// directly, which makes attacks through its input very likely.
func isInternetAdjacent(input *types.Model, technicalAsset *types.TechnicalAsset) bool {
	if technicalAsset.Internet || callsInternet(input, technicalAsset) {
		return true
	}
	for _, incomingLink := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
		if source, ok := input.TechnicalAssets[incomingLink.SourceId]; ok && source.Internet {
			return true
		}
	}
	return false
}

// impactOfRatings rates the impact of a risk by the ratings at stake: high for strictly confidential or
// mission-critical, medium for confidential or critical, and low otherwise.
func impactOfRatings(
	confidentiality types.Confidentiality, integrity, availability types.Criticality,
) types.RiskExploitationImpact {
	if confidentiality == types.StrictlyConfidential ||
		integrity == types.MissionCritical || availability == types.MissionCritical {
		return types.HighImpact
	}
	if confidentiality >= types.Confidential || integrity >= types.Critical || availability >= types.Critical {
		return types.MediumImpact
	}
	return types.LowImpact
}

// processedImpact rates the impact of an AI risk at a technical asset by what it processes.
func processedImpact(input *types.Model, technicalAsset *types.TechnicalAsset) types.RiskExploitationImpact {
	return impactOfRatings(input.HighestProcessedConfidentiality(technicalAsset),
		input.HighestProcessedIntegrity(technicalAsset), input.HighestProcessedAvailability(technicalAsset))
}

// raiseImpact returns the next higher impact, up to very high.
func raiseImpact(impact types.RiskExploitationImpact) types.RiskExploitationImpact {
	return min(impact+1, types.VeryHighImpact)
}

// assetRiskTitle is the title of a risk: its name in bold, at the technical asset, with a detail if any.
func assetRiskTitle(name string, technicalAsset *types.TechnicalAsset, detail string) string {
	title := "<b>" + name + "</b> risk at <b>" + technicalAsset.Title + "</b>"
	if detail != "" {
		title += " " + detail
	}
	return title
}
