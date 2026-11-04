package expressions

import (
	"github.com/Pinguladora/threagile/pkg/risks/script/common"
)

type EqualOrLessExpression struct {
	literal string
	first   common.ValueExpression
	second  common.ValueExpression
	as      string
}

func (what *EqualOrLessExpression) ParseBool(script any) (common.BoolExpression, any, error) {
	what.literal = common.ToLiteral(script)

	return parseComparison[common.BoolExpression](what, "equal-expression", script, common.First, &what.first,
		common.Second, &what.second, parseAsString("equal-expression", script, &what.as))
}

func (what *EqualOrLessExpression) ParseAny(script any) (common.Expression, any, error) {
	return what.ParseBool(script)
}

func (what *EqualOrLessExpression) EvalBool(scope *common.Scope) (*common.BoolValue, string, error) {
	compareValue, errorLiteral, compareError := evalComparison(scope, what.first, what.second, what.as, what.Literal(),
		"equal-expression")
	if compareError != nil {
		return common.EmptyBoolValue(), errorLiteral, compareError
	}

	if common.IsSame(compareValue.Property) {
		return common.SomeBoolValue(true, compareValue), "", nil
	}

	if common.IsLess(compareValue.Property) {
		return common.SomeBoolValue(true, compareValue), "", nil
	}

	return common.SomeBoolValue(false, compareValue), "", nil
}

func (what *EqualOrLessExpression) EvalAny(scope *common.Scope) (common.Value, string, error) {
	return what.EvalBool(scope)
}

func (what *EqualOrLessExpression) Literal() string {
	return what.literal
}
