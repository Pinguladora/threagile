package risks_test

import (
	"strings"
	"testing"

	"github.com/Pinguladora/threagile/pkg/catalog"
	"github.com/Pinguladora/threagile/pkg/risks"
	"github.com/stretchr/testify/assert"
)

// TestReferencesNameCatalogEntries keeps the references of the built-in rules to OWASP and MAESTRO to the entries
// of the threat catalogs, which the reports show the coverage of. Other references, like those to IEC 62443 or to
// MITRE ATT&CK for ICS, name standards that the reports list but whose coverage they do not show.
func TestReferencesNameCatalogEntries(t *testing.T) {
	entries := make(map[string]bool)
	for _, threatCatalog := range catalog.All() {
		for _, entry := range threatCatalog.Entries {
			entries[entry.Reference] = true
		}
	}
	for _, rule := range risks.GetBuiltInRiskRules() {
		category := rule.Category()
		for _, reference := range category.References {
			if strings.HasPrefix(reference, "OWASP ") || strings.HasPrefix(reference, "MAESTRO ") {
				assert.True(t, entries[reference], "%s: %s", category.ID, reference)
			}
		}
	}
}
