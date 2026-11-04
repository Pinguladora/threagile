package expressions

import (
	"fmt"

	"github.com/Pinguladora/threagile/pkg/risks/script/common"
)

type ContainsExpression struct {
	literal string
	item    common.ValueExpression
	in      common.ValueExpression
	as      string
}

func (what *ContainsExpression) ParseBool(script any) (common.BoolExpression, any, error) {
	what.literal = common.ToLiteral(script)

	return parseComparison[common.BoolExpression](what, "contains-expression", script, common.Item, &what.item,
		common.In, &what.in, parseAsString("contains-expression", script, &what.as))
}

func (what *ContainsExpression) ParseAny(script any) (common.Expression, any, error) {
	return what.ParseBool(script)
}

func (what *ContainsExpression) EvalBool(scope *common.Scope) (*common.BoolValue, string, error) {
	item, errorItemLiteral, itemError := what.item.EvalAny(scope)
	if itemError != nil {
		return common.EmptyBoolValue(), errorItemLiteral, itemError
	}

	inValue, errorInLiteral, evalError := what.in.EvalAny(scope)
	if evalError != nil {
		return common.EmptyBoolValue(), errorInLiteral, evalError
	}

	return what.evalBool(item, inValue)
}

func (what *ContainsExpression) evalBool(item common.Value, inValue common.Value) (*common.BoolValue, string, error) {
	switch castValue := inValue.Value().(type) {
	case []any, []common.Value, map[string]any:
		var sameValue *common.Event
		errorLiteral, compareError := forEachItem(castValue, func(candidate iterationItem) (bool, string, error) {
			compareValue, compareError := common.Compare(item, common.SomeValue(candidate.value, candidate.event), what.as)
			if compareError != nil {
				return true, what.Literal(), fmt.Errorf(
					"failed to eval contains-expression: can't compare value to item %v: %w", candidate.label, compareError)
			}

			if common.IsSame(compareValue.Property) {
				sameValue = compareValue
				return true, "", nil
			}

			return false, "", nil
		})
		if compareError != nil {
			return common.EmptyBoolValue(), errorLiteral, compareError
		}

		if sameValue != nil {
			return common.SomeBoolValue(true, sameValue), "", nil
		}

		return common.SomeBoolValue(false, nil), "", nil

	case common.Value:
		return what.evalBool(item, common.SomeValue(castValue.Value(), inValue.Event()))

	case nil:
		return common.SomeBoolValue(false, nil), "", nil

	default:
		return common.EmptyBoolValue(), "", fmt.Errorf("failed to eval contains-expression: expected iterable type, got %T", inValue)
	}
}

func (what *ContainsExpression) EvalAny(scope *common.Scope) (common.Value, string, error) {
	return what.EvalBool(scope)
}

func (what *ContainsExpression) Literal() string {
	return what.literal
}
