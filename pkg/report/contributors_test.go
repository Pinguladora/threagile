package report

import (
	"testing"

	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestContributorsLine(t *testing.T) {
	assert.Empty(t, contributorsLine(&types.Model{}), "no line without contributors")
	assert.Empty(t, contributorsLine(&types.Model{Contributors: []*types.Author{nil, {Contact: "anonymous@example.com"}}}),
		"contributors without a name are skipped")

	model := &types.Model{Contributors: []*types.Author{
		{Name: "Jane Roe", Contact: "jane@example.com", Homepage: "https://example.com"},
		{Name: " Max Mustermann "},
	}}
	assert.Equal(t, "Contributors: Jane Roe (jane@example.com), Max Mustermann", contributorsLine(model))
}
