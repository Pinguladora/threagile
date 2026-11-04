package input

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorMergeListKeepsTheFieldsOfEachEntry(t *testing.T) {
	merged, err := new(Author).MergeList([]Author{
		{Name: "Alex", Contact: "alex@example.com"},
		{Name: "Sam"},
		{Name: "Alex", Homepage: "example.com/alex"},
	})
	require.NoError(t, err)

	assert.Equal(t, []Author{
		{Name: "Alex", Contact: "alex@example.com", Homepage: "example.com/alex"},
		{Name: "Sam"},
	}, merged)
}

func TestAuthorMergeRejectsConflictingFields(t *testing.T) {
	author := Author{Name: "Alex", Contact: "alex@example.com"}
	assert.ErrorContains(t, author.Merge(Author{Name: "Alex", Contact: "other@example.com"}), "contact mismatch")
	assert.NoError(t, author.Merge(Author{Name: "alex"}))
	assert.Equal(t, Author{Name: "Alex", Contact: "alex@example.com"}, author)
}
