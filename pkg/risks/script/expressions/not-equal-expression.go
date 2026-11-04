package expressions

import (
	"github.com/Pinguladora/threagile/pkg/risks/script/common"
)

type NotEqualExpression struct {
	literal string
	first   common.ValueExpression
	second  common.ValueExpression
	as      string
}

func (what *NotEqualExpression) ParseBool(script any) (common.BoolExpression, any, error) {
	what.literal = common.ToLiteral(script)

	return parseComparison[common.BoolExpression](what, "equal-expression", script, common.First, &what.first,
		common.Second, &what.second, parseAsString("equal-expression", script, &what.as))
}

func (what *NotEqualExpression) ParseAny(script any) (common.Expression, any, error) {
	return what.ParseBool(script)
}

func (what *NotEqualExpression) EvalBool(scope *common.Scope) (*common.BoolValue, string, error) {
	compareValue, errorLiteral, compareError := evalComparison(scope, what.first, what.second, what.as, what.Literal(),
		"not-equal-expression")
	if compareError != nil {
		return common.EmptyBoolValue(), errorLiteral, compareError
	}

	if !common.IsSame(compareValue.Property) {
		return common.SomeBoolValue(true, compareValue), "", nil
	}

	return common.SomeBoolValue(false, compareValue), "", nil
}

func (what *NotEqualExpression) EvalAny(scope *common.Scope) (common.Value, string, error) {
	return what.EvalBool(scope)
}

func (what *NotEqualExpression) Literal() string {
	return what.literal
}
