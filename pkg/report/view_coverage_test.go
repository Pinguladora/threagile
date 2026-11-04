package report

import (
	"testing"

	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestViewCatalogsShowsTheCatalogsOfTheRisks(t *testing.T) {
	const injection, excessiveAgency = "OWASP LLM01:2025 Prompt Injection", "OWASP LLM06:2025 Excessive Agency"
	injectionRule := &types.RiskCategory{ID: "prompt-injection", Title: "Prompt Injection", References: []string{injection}}
	guardrailRule := &types.RiskCategory{ID: "guardrail", Title: "Guardrail", References: []string{injection}}
	skippedRule := &types.RiskCategory{ID: "skipped", Title: "Skipped", References: []string{excessiveAgency}}
	apiRule := &types.RiskCategory{
		ID: "api", Title: "API", References: []string{"OWASP API1:2023 Broken Object Level Authorization"},
	}
	rules := []viewRiskRule{
		{Category: injectionRule}, {Category: injectionRule}, // a script rule shadowing a built-in one
		{Category: guardrailRule}, {Category: skippedRule, Skipped: true}, {Category: apiRule},
	}
	categories := []viewCategory{{
		Anchor: "category-prompt-injection", Category: injectionRule,
		Risks: []*viewRisk{{StillAtRisk: true}, {StillAtRisk: false}},
	}}

	catalogs := viewCatalogs(rules, categories)

	require.Len(t, catalogs, 1, "the API catalog holds no risks")
	llm := catalogs[0]
	assert.Equal(t, "OWASP Top 10 for LLM Applications 2025", llm.Title)
	assert.Equal(t, 1, llm.Checked, "a skipped rule checks nothing")
	assert.Equal(t, viewCatalogEntry{
		ID: "LLM01", Title: "Prompt Injection", Risks: 2, StillAtRisk: true, Summary: "1/2 unmitigated Risks",
		Rules: []viewRef{{Title: "Guardrail"}, {Anchor: "category-prompt-injection", Title: "Prompt Injection"}},
	}, llm.Entries[0])
	assert.Equal(t, textNotChecked, llm.Entries[5].Summary)
}
