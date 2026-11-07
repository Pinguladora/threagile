// Package catalog lists the threat catalogs that risk rules reference, like the OWASP Top 10 and the OWASP Top 10
// for LLM Applications, with all their entries, so that a report can show which entries the rules of a model cover
// and which they do not.
//
// A rule references an entry by its reference text, like "OWASP LLM01:2025 Prompt Injection", in the references
// of its risk category.
package catalog

import "fmt"

// Catalog is a threat catalog and its entries, in their order.
type Catalog struct {
	ID      string
	Title   string
	Link    string
	Entries []Entry
}

// Entry is an entry of a threat catalog.
type Entry struct {
	ID        string // like LLM01
	Title     string // like Prompt Injection
	Reference string // what the references of a risk category name it by
}

// All returns the threat catalogs, in the order the reports show them.
func All() []Catalog {
	return []Catalog{
		owaspCatalog("owasp-top-10-2025", "OWASP Top 10:2025", "https://top10.owasp.org/2025/", "A", "2025",
			[]string{
				"Broken Access Control", "Security Misconfiguration", "Software Supply Chain Failures",
				"Cryptographic Failures", "Injection", "Insecure Design", "Authentication Failures",
				"Software or Data Integrity Failures", "Security Logging and Alerting Failures",
				"Mishandling of Exceptional Conditions",
			}),
		owaspCatalog("owasp-api-2023", "OWASP API Security Top 10 2023",
			"https://owasp.org/API-Security/editions/2023/en/0x11-t10/", "API", "2023", []string{
				"Broken Object Level Authorization", "Broken Authentication",
				"Broken Object Property Level Authorization", "Unrestricted Resource Consumption",
				"Broken Function Level Authorization", "Unrestricted Access to Sensitive Business Flows",
				"Server Side Request Forgery", "Security Misconfiguration", "Improper Inventory Management",
				"Unsafe Consumption of APIs",
			}),
		owaspCatalog("owasp-llm-2025", "OWASP Top 10 for LLM Applications 2025", "https://genai.owasp.org/llm-top-10/",
			"LLM", "2025", []string{
				"Prompt Injection", "Sensitive Information Disclosure", "Supply Chain", "Data and Model Poisoning",
				"Improper Output Handling", "Excessive Agency", "System Prompt Leakage",
				"Vector and Embedding Weaknesses", "Misinformation", "Unbounded Consumption",
			}),
		owaspCatalog("owasp-agentic-2026", "OWASP Top 10 for Agentic Applications 2026",
			"https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/", "ASI", "2026", []string{
				"Agent Goal Hijack", "Tool Misuse and Exploitation", "Identity and Privilege Abuse",
				"Agentic Supply Chain Vulnerabilities", "Unexpected Code Execution", "Memory and Context Poisoning",
				"Insecure Inter-Agent Communication", "Cascading Failures", "Human-Agent Trust Exploitation",
				"Rogue Agents",
			}),
		maestro(),
		owaspCatalog("owasp-nhi-2025", "OWASP Non-Human Identities Top 10 2025",
			"https://owasp.org/www-project-non-human-identities-top-10/2025/", "NHI", "2025", []string{
				"Improper Offboarding", "Secret Leakage", "Vulnerable Third-Party NHI", "Insecure Authentication",
				"Overprivileged NHI", "Insecure Cloud Deployment Configurations", "Long-Lived Secrets",
				"Environment Isolation", "NHI Reuse", "Human Use of NHI",
			}),
		owaspCatalog("owasp-kubernetes-2025", "OWASP Kubernetes Top 10 2025", "https://kubernetes-top10.owasp.org/",
			"K", "2025", []string{
				"Insecure Workload Configurations", "Overly Permissive Authorization Configurations",
				"Secrets Management Failures", "Lack Of Cluster Level Policy Enforcement",
				"Missing Network Segmentation Controls", "Overly Exposed Kubernetes Components",
				"Misconfigured And Vulnerable Cluster Components", "Cluster To Cloud Lateral Movement",
				"Broken Authentication Mechanisms", "Inadequate Logging And Monitoring",
			}),
	}
}

// owaspCatalog is an OWASP top 10 whose entries are numbered with the prefix and referenced like
// "OWASP LLM01:2025 Prompt Injection", with two digits for the web, LLM, agentic and Kubernetes lists, as OWASP
// writes them.
func owaspCatalog(id, title, link, prefix, year string, titles []string) Catalog {
	format := "%s%d"
	if prefix == "A" || prefix == "LLM" || prefix == "ASI" || prefix == "K" {
		format = "%s%02d"
	}
	entries := make([]Entry, 0, len(titles))
	for index, entryTitle := range titles {
		entryID := fmt.Sprintf(format, prefix, index+1)
		entries = append(entries, Entry{
			ID: entryID, Title: entryTitle, Reference: fmt.Sprintf("OWASP %s:%s %s", entryID, year, entryTitle),
		})
	}
	return Catalog{ID: id, Title: title, Link: link, Entries: entries}
}

// maestro is the CSA MAESTRO framework for threat modeling agentic AI, whose layers are its entries.
func maestro() Catalog {
	layers := []string{
		"Foundation Models", "Data Operations", "Agent Frameworks", "Deployment and Infrastructure",
		"Evaluation and Observability", "Security and Compliance", "Agent Ecosystem",
	}
	entries := make([]Entry, 0, len(layers))
	for index, layer := range layers {
		entries = append(entries, Entry{
			ID: fmt.Sprintf("L%d", index+1), Title: layer, Reference: fmt.Sprintf("MAESTRO Layer %d: %s", index+1, layer),
		})
	}
	return Catalog{
		ID: "maestro", Title: "CSA MAESTRO", Link: "https://cloudsecurityalliance.org/blog/2025/02/06/" +
			"agentic-ai-threat-modeling-framework-maestro", Entries: entries,
	}
}
