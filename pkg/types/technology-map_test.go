package types

import (
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTechnologyMapGetResolvesAliases(t *testing.T) {
	technologies := make(TechnologyMap)
	require.NoError(t, technologies.LoadDefault())
	technologies.PropagateAttributes()

	technology := technologies.Get("openfga")
	require.NotNil(t, technology)
	assert.Equal(t, "policy-decision-point", technology.Name, "an alias stands for its technology")
	assert.True(t, technology.GetAttribute(PolicyDecisionPoint))
	assert.Nil(t, technologies.Get("no-such-technology"))

	owners := make(map[string]string)
	for _, name := range slices.Sorted(maps.Keys(technologies)) {
		for _, alias := range technologies[name].Aliases {
			assert.NotContains(t, technologies, alias, "the alias %q of %q is a technology itself", alias, name)
			if owner, taken := owners[alias]; taken {
				t.Errorf("the alias %q is one of both %q and %q", alias, owner, name)
			}
			owners[alias] = name
			if resolved := technologies.Get(alias); assert.NotNil(t, resolved, alias) {
				assert.Equal(t, name, resolved.Name, alias)
			}
		}
	}
}
