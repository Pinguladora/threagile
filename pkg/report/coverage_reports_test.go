package report_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAsciiDocReportShowsCatalogCoverage checks the coverage chapter of the AsciiDoc report of the AI demo: it is
// included before the risk rules checked, links the rules that found risks to their category and marks the entries
// that no rule checks.
func TestAsciiDocReportShowsCatalogCoverage(t *testing.T) {
	outputs := generateOutputs(t, aiAgentModel)

	var main, coverage string
	for name, content := range outputs {
		switch {
		case strings.HasSuffix(name, "000_main.adoc"):
			main = string(content)
		case strings.HasSuffix(name, "215_CatalogCoverage.adoc"):
			coverage = string(content)
		}
	}
	require.NotEmpty(t, coverage, "the coverage chapter is written")
	assert.Less(t, strings.Index(main, "include::215_CatalogCoverage.adoc"),
		strings.Index(main, "include::220_RiskRulesChecked.adoc"))
	assert.Contains(t, coverage, "= Threat Catalog Coverage\n")
	assert.Contains(t, coverage, "== OWASP Top 10 for LLM Applications 2025\n")
	assert.Contains(t, coverage, "| `LLM01` Prompt Injection | Missing AI Guardrail, <<prompt-injection,Prompt Injection>> | "+
		"2/2 unmitigated Risks\n")
	assert.Contains(t, coverage, "| `LLM07` System Prompt Leakage |  | [SmallGrey]#not checked by any risk rule#\n")
}
