package expressions

import (
	"fmt"

	"github.com/Pinguladora/threagile/pkg/risks/script/common"
)

type AllExpression struct {
	literal    string
	in         common.ValueExpression
	item       string
	index      string
	expression common.BoolExpression
}

func (what *AllExpression) ParseBool(script any) (common.BoolExpression, any, error) {
	what.literal = common.ToLiteral(script)

	return parseIteration[common.BoolExpression](what, "all-expression", script, &what.in, &what.item, &what.index,
		&what.expression)
}

func (what *AllExpression) ParseAny(script any) (common.Expression, any, error) {
	return what.ParseBool(script)
}

func (what *AllExpression) EvalBool(scope *common.Scope) (*common.BoolValue, string, error) {
	oldItem := scope.PopItem()
	defer scope.SetItem(oldItem)

	inValue, errorEvalLiteral, evalError := what.in.EvalAny(scope)
	if evalError != nil {
		return common.EmptyBoolValue(), errorEvalLiteral, evalError
	}

	return what.evalBool(scope, inValue)
}

func (what *AllExpression) evalBool(scope *common.Scope, inValue common.Value) (*common.BoolValue, string, error) {
	oldItem := scope.PopItem()
	defer scope.SetItem(oldItem)

	switch castValue := inValue.Value().(type) {
	case []any, []common.Value, map[string]any:
		if what.expression == nil {
			return common.SomeBoolValue(true, nil), "", nil
		}

		values := make([]common.Value, 0)
		var falseValue *common.BoolValue
		errorLiteral, evalError := evalForEachItem(scope, inValue, castValue, what.item, what.index, what.expression,
			"all-expression", func(value *common.BoolValue) bool {
				if !value.BoolValue() {
					falseValue = value
					return true
				}

				values = append(values, value)
				return false
			})
		if evalError != nil {
			return common.EmptyBoolValue(), errorLiteral, evalError
		}

		if falseValue != nil {
			return common.SomeBoolValue(false, falseValue.Event()), "", nil
		}

		trueEvent := common.NewEvent(common.NewTrueProperty(), inValue.Event().Origin).From(values...)
		return common.SomeBoolValue(true, trueEvent), "", nil

	case common.Value:
		return what.evalBool(scope, common.SomeValue(castValue.Value(), inValue.Event()))

	case nil:
		return common.SomeBoolValue(false, nil), "", nil

	default:
		return common.EmptyBoolValue(), what.Literal(), fmt.Errorf("failed to eval all-expression: expected iterable type, got %T", inValue)
	}
}

func (what *AllExpression) EvalAny(scope *common.Scope) (common.Value, string, error) {
	return what.EvalBool(scope)
}

func (what *AllExpression) Literal() string {
	return what.literal
}
