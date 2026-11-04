package expressions

import (
	"testing"

	"github.com/Pinguladora/threagile/pkg/risks/script/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAndExpression_ParseBool_ArrayOfBoolExpressions(t *testing.T) {
	// Parse with an array of bool-valued expressions (strings that will become ValueExpressions)
	script := []any{"true", "true"}
	expr := new(AndExpression)
	result, errorScript, err := expr.ParseBool(script)
	assert.NoError(t, err)
	assert.Nil(t, errorScript)
	assert.NotNil(t, result)
	assert.Len(t, expr.expressions, 2)
}

func TestAndExpression_EvalBool_AllTrue(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	// Build an AndExpression with two true ValueExpressions
	trueExpr1 := new(ValueExpression)
	_, _, parseErr := trueExpr1.ParseBool(true)
	require.NoError(t, parseErr)
	trueExpr2 := new(ValueExpression)
	_, _, parseErr = trueExpr2.ParseBool(true)
	require.NoError(t, parseErr)

	expr := &AndExpression{
		expressions: []common.BoolExpression{trueExpr1, trueExpr2},
	}

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.True(t, result.BoolValue())
}

func TestAndExpression_EvalBool_OneFalse_ShortCircuits(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	trueExpr := new(ValueExpression)
	_, _, parseErr := trueExpr.ParseBool(true)
	require.NoError(t, parseErr)
	falseExpr := new(ValueExpression)
	_, _, parseErr = falseExpr.ParseBool(false)
	require.NoError(t, parseErr)

	expr := &AndExpression{
		expressions: []common.BoolExpression{falseExpr, trueExpr},
	}

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.False(t, result.BoolValue())
}

func TestAndExpression_EvalBool_Empty_ReturnsTrue(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)

	expr := &AndExpression{
		expressions: []common.BoolExpression{},
	}

	result, errorLiteral, err := expr.EvalBool(scope)
	assert.NoError(t, err)
	assert.Empty(t, errorLiteral)
	assert.True(t, result.BoolValue())
}
