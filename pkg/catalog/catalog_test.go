package catalog

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAllHasUniqueReferences(t *testing.T) {
	seen := make(map[string]bool)
	for _, catalog := range All() {
		assert.NotEmpty(t, catalog.Entries, catalog.ID)
		for _, entry := range catalog.Entries {
			assert.False(t, seen[entry.Reference], entry.Reference)
			seen[entry.Reference] = true
		}
	}
}

func TestReferencesReadAsOWASPAndMAESTROWriteThem(t *testing.T) {
	references := make(map[string]bool)
	for _, catalog := range All() {
		for _, entry := range catalog.Entries {
			references[entry.Reference] = true
		}
	}
	for _, reference := range []string{
		"OWASP A01:2025 Broken Access Control",
		"OWASP A10:2025 Mishandling of Exceptional Conditions",
		"OWASP LLM01:2025 Prompt Injection",
		"OWASP ASI10:2026 Rogue Agents",
		"MAESTRO Layer 7: Agent Ecosystem",
		"OWASP NHI10:2025 Human Use of NHI",
		"OWASP API1:2023 Broken Object Level Authorization",
	} {
		assert.True(t, references[reference], reference)
	}
}
