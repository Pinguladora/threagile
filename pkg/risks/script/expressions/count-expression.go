package expressions

import (
	"fmt"

	"github.com/Pinguladora/threagile/pkg/risks/script/common"
	"github.com/shopspring/decimal"
)

type CountExpression struct {
	literal    string
	in         common.ValueExpression
	item       string
	index      string
	expression common.BoolExpression
}

func (what *CountExpression) ParseDecimal(script any) (common.DecimalExpression, any, error) {
	what.literal = common.ToLiteral(script)

	return parseIteration[common.DecimalExpression](what, "count-expression", script, &what.in, &what.item,
		&what.index, &what.expression)
}

func (what *CountExpression) ParseAny(script any) (common.Expression, any, error) {
	return what.ParseDecimal(script)
}

func (what *CountExpression) EvalDecimal(scope *common.Scope) (*common.DecimalValue, string, error) {
	oldItem := scope.PopItem()
	defer scope.SetItem(oldItem)

	inValue, errorEvalLiteral, evalError := what.in.EvalAny(scope)
	if evalError != nil {
		return common.EmptyDecimalValue(), errorEvalLiteral, evalError
	}

	return what.evalDecimal(scope, inValue)
}

func (what *CountExpression) evalDecimal(scope *common.Scope, inValue common.Value) (*common.DecimalValue, string, error) {
	switch castValue := inValue.Value().(type) {
	case []any, []common.Value, map[string]any:
		if what.expression == nil {
			return common.SomeDecimalValue(decimal.NewFromInt(int64(iterableLen(castValue))), nil), "", nil
		}

		values := make([]common.Value, 0)
		var count int64 = 0
		errorLiteral, evalError := evalForEachItem(scope, inValue, castValue, what.item, what.index, what.expression,
			"all-expression", func(value *common.BoolValue) bool {
				if value.BoolValue() {
					values = append(values, value)
					count++
				}

				return false
			})
		if evalError != nil {
			return common.EmptyDecimalValue(), errorLiteral, evalError
		}

		return common.SomeDecimalValue(decimal.NewFromInt(count), inValue.Event().From(values...)), "", nil

	case common.Value:
		return what.evalDecimal(scope, common.SomeValue(castValue.Value(), inValue.Event()))

	case nil:
		return common.EmptyDecimalValue(), "", nil

	default:
		return common.EmptyDecimalValue(), what.Literal(), fmt.Errorf("failed to eval all-expression: expected iterable type, got %T", inValue)
	}
}

func (what *CountExpression) EvalAny(scope *common.Scope) (common.Value, string, error) {
	return what.EvalDecimal(scope)
}

func (what *CountExpression) Literal() string {
	return what.literal
}
