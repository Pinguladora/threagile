package expressions

import (
	"fmt"

	"github.com/Pinguladora/threagile/pkg/risks/script/common"
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

			setIterationName(key, text, item, index)

		default:
			boolExpression, errorScript, expressionError := parseIterationExpression(name, script, key, value, *expression)
			if expressionError != nil {
				return none, errorScript, expressionError
			}

			*expression = boolExpression
		}
	}

	if *in == nil {
		return none, script, fmt.Errorf("failed to parse %v: missing %q", name, common.In)
	}

	return what, nil, nil
}

// setIterationName sets the name of the current item or of its index, as the key tells.
func setIterationName(key string, text string, item *string, index *string) {
	if key == common.Item {
		*item = text
	} else {
		*index = text
	}
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
	var errorLiteral string
	var evalError error
	common.ForEachItem(iterable, func(item common.IterationItem) bool {
		if len(indexName) > 0 {
			scope.Set(indexName, item.Index)
		}

		itemValue := scope.SetItem(common.SomeValue(item.Value, inValue.Event()))
		if len(itemName) > 0 {
			scope.Set(itemName, itemValue)
		}

		value, expressionLiteral, expressionError := expression.EvalBool(scope)
		if expressionError != nil {
			errorLiteral = expressionLiteral
			evalError = fmt.Errorf("error evaluating expression %v of %v: %w", item.Label, name, expressionError)
			return true
		}

		return visit(value)
	})

	return errorLiteral, evalError
}
