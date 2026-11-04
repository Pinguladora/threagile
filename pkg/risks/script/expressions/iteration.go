package expressions

import (
	"fmt"
	"maps"
	"slices"

	"github.com/Pinguladora/threagile/pkg/risks/script/common"
	"github.com/shopspring/decimal"
)

// parseIteration parses the script of an expression that iterates over values (all-, any- and count-expression)
// into its fields: the values to iterate over, the names to give the current item and its index, and the bool
// expression to evaluate for each item. It returns the expression itself; name is how error messages call it.
func parseIteration[T common.Expression](
	what T, name string, script any, in *common.ValueExpression, item *string, index *string,
	expression *common.BoolExpression,
) (T, any, error) {
	var none T
	castScript, ok := script.(map[string]any)
	if !ok {
		return none, script, fmt.Errorf("failed to parse %v: expected map[string]any, got %T", name, script)
	}

	for key, value := range castScript {
		switch key {
		case common.In:
			inValue, errorExpression, itemError := new(ValueExpression).ParseValue(value)
			if itemError != nil {
				return none, errorExpression, fmt.Errorf("failed to parse %q of %v: %w", key, name, itemError)
			}

			*in = inValue

		case common.Item, common.Index:
			text, ok := value.(string)
			if !ok {
				return none, value, fmt.Errorf("failed to parse %q of %v: expected string, got %T", key, name, value)
			}

			if key == common.Item {
				*item = text
			} else {
				*index = text
			}

		default:
			boolExpression, errorScript, expressionError := parseIterationExpression(name, script, key, value, *expression)
			if expressionError != nil {
				return none, errorScript, expressionError
			}

			*expression = boolExpression
		}
	}

	return what, nil, nil
}

// parseIterationExpression parses the bool expression of an iteration expression, which must not have one yet.
func parseIterationExpression(
	name string, script any, key string, value any, current common.BoolExpression,
) (common.BoolExpression, any, error) {
	if current != nil {
		return nil, script, fmt.Errorf("failed to parse %v: additional bool expression %q", name, key)
	}

	expression, errorScript, itemError := new(ExpressionList).ParseAny(map[string]any{key: value})
	if itemError != nil {
		return nil, errorScript, fmt.Errorf("failed to parse %v: %w", name, itemError)
	}

	boolExpression, ok := expression.(common.BoolExpression)
	if !ok {
		return nil, script, fmt.Errorf("%v contains non-bool expression: %w", name, itemError)
	}

	return boolExpression, nil, nil
}

// iterationItem is an item of an iterable value.
type iterationItem struct {
	index common.Value  // the index (a decimal) of the item in a slice, or its key (a string) in a map
	value any           // the value of the item
	event *common.Event // the event of the item if it is a value itself, otherwise nil
	label string        // how error messages refer to the item
}

// forEachItem calls visit for each item of an iterable value, a slice or a map (in the order of its sorted keys),
// until visit tells to stop. It returns what visit returned when it stopped.
func forEachItem(
	iterable any, visit func(item iterationItem) (stop bool, errorLiteral string, err error),
) (string, error) {
	switch castValue := iterable.(type) {
	case []any:
		for index, value := range castValue {
			stop, errorLiteral, err := visit(iterationItem{
				index: common.SomeDecimalValue(decimal.NewFromInt(int64(index)), nil),
				value: value,
				label: fmt.Sprintf("#%v", index+1),
			})
			if stop {
				return errorLiteral, err
			}
		}

	case []common.Value:
		for index, value := range castValue {
			stop, errorLiteral, err := visit(iterationItem{
				index: common.SomeDecimalValue(decimal.NewFromInt(int64(index)), nil),
				value: value.Value(),
				event: value.Event(),
				label: fmt.Sprintf("#%v", index+1),
			})
			if stop {
				return errorLiteral, err
			}
		}

	case map[string]any:
		for _, name := range slices.Sorted(maps.Keys(castValue)) {
			stop, errorLiteral, err := visit(iterationItem{
				index: common.SomeStringValue(name, nil),
				value: castValue[name],
				label: fmt.Sprintf("%q", name),
			})
			if stop {
				return errorLiteral, err
			}
		}
	}

	return "", nil
}

// iterableLen returns the number of items of an iterable value.
func iterableLen(iterable any) int {
	switch castValue := iterable.(type) {
	case []any:
		return len(castValue)
	case []common.Value:
		return len(castValue)
	case map[string]any:
		return len(castValue)
	default:
		return 0
	}
}

// evalForEachItem evaluates the bool expression of an iteration expression for each item of an iterable value, with
// the item and its index set in the scope under the given names, and passes the results to visit until it tells to
// stop. name is how error messages call the iteration expression.
func evalForEachItem(
	scope *common.Scope, inValue common.Value, iterable any, itemName string, indexName string,
	expression common.BoolExpression, name string, visit func(value *common.BoolValue) (stop bool),
) (string, error) {
	return forEachItem(iterable, func(item iterationItem) (bool, string, error) {
		if len(indexName) > 0 {
			scope.Set(indexName, item.index)
		}

		itemValue := scope.SetItem(common.SomeValue(item.value, inValue.Event()))
		if len(itemName) > 0 {
			scope.Set(itemName, itemValue)
		}

		value, errorLiteral, expressionError := expression.EvalBool(scope)
		if expressionError != nil {
			return true, errorLiteral, fmt.Errorf("error evaluating expression %v of %v: %w", item.label, name,
				expressionError)
		}

		return visit(value), "", nil
	})
}
