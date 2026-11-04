package expressions

import (
	"github.com/Pinguladora/threagile/pkg/risks/script/common"
)

type LessExpression struct {
	literal string
	first   common.ValueExpression
	second  common.ValueExpression
	as      string
}

func (what *LessExpression) ParseBool(script any) (common.BoolExpression, any, error) {
	what.literal = common.ToLiteral(script)

	return parseComparison[common.BoolExpression](what, "equal-expression", script, common.First, &what.first,
		common.Second, &what.second, parseAsString("equal-expression", script, &what.as))
}

func (what *LessExpression) ParseAny(script any) (common.Expression, any, error) {
	return what.ParseBool(script)
}

func (what *LessExpression) EvalBool(scope *common.Scope) (*common.BoolValue, string, error) {
	compareValue, errorLiteral, compareError := evalComparison(scope, what.first, what.second, what.as, what.Literal(),
		"equal-expression")
	if compareError != nil {
		return common.EmptyBoolValue(), errorLiteral, compareError
	}

	if common.IsLess(compareValue.Property) {
		return common.SomeBoolValue(true, compareValue), "", nil
	}

	return common.SomeBoolValue(false, compareValue), "", nil
}

func (what *LessExpression) EvalAny(scope *common.Scope) (common.Value, string, error) {
	return what.EvalBool(scope)
}

func (what *LessExpression) Literal() string {
	return what.literal
}
