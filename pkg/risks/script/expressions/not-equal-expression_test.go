package expressions

import (
	"testing"

	"github.com/Pinguladora/threagile/pkg/risks/script/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNotEqualExpression_EvalBool_DifferentStrings_ReturnsTrue(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	script := map[string]any{
		"first":  "hello",
		"second": "world",
	}
	expr := new(NotEqualExpression)
	_, _, parseErr := expr.ParseBool(script)
	require.NoError(t, parseErr)

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.True(t, result.BoolValue())
}

func TestNotEqualExpression_EvalBool_EqualStrings_ReturnsFalse(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	script := map[string]any{
		"first":  "hello",
		"second": "hello",
	}
	expr := new(NotEqualExpression)
	_, _, parseErr := expr.ParseBool(script)
	require.NoError(t, parseErr)

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.False(t, result.BoolValue())
}
