package expressions

import (
	"fmt"

	"github.com/Pinguladora/threagile/pkg/risks/script/common"
)

// parseComparison parses the script of an expression that compares two values into its fields: the two values under
// their keys, and how to compare them ("as"), which parseAs parses. It returns the expression itself; name is how
// error messages call it.
func parseComparison[T common.Expression](
	what T, name string, script any, firstKey string, first *common.ValueExpression, secondKey string,
	second *common.ValueExpression, parseAs func(key string, value any) (any, error),
) (T, any, error) {
	var none T
	castScript, ok := script.(map[string]any)
	if !ok {
		return none, script, fmt.Errorf("failed to parse %v: expected map[string]any, got %T", name, script)
	}

	for key, value := range castScript {
		switch key {
		case firstKey, secondKey:
			item, errorScript, itemError := new(ValueExpression).ParseValue(value)
			if itemError != nil {
				return none, errorScript, fmt.Errorf("failed to parse %q of %v: %w", key, name, itemError)
			}

			if key == firstKey {
				*first = item
			} else {
				*second = item
			}

		case common.As:
			if errorScript, asError := parseAs(key, value); asError != nil {
				return none, errorScript, asError
			}

		default:
			return none, script, fmt.Errorf("failed to parse %v: unexpected keyword %q", name, key)
		}
	}

	return what, nil, nil
}

// parseAsString returns a parser for the "as" of a comparison expression that must be a string.
func parseAsString(name string, script any, as *string) func(key string, value any) (any, error) {
	return func(key string, value any) (any, error) {
		item, ok := value.(string)
		if !ok {
			return script, fmt.Errorf("failed to parse %v: %q is not a string but %T", name, key, value)
		}

		*as = item
		return nil, nil
	}
}

// parseAsExpression returns a parser for the "as" of a comparison expression that is an expression itself.
func parseAsExpression(name string, as *common.StringExpression) func(key string, value any) (any, error) {
	return func(key string, value any) (any, error) {
		item, errorScript, itemError := new(ValueExpression).ParseValue(value)
		if itemError != nil {
			return errorScript, fmt.Errorf("failed to parse %q of %v: %w", key, name, itemError)
		}

		*as = item
		return nil, nil
	}
}

// evalComparison evaluates the two values of a comparison expression and compares them as told. literal is the
// literal of the expression, and name is how error messages call it.
func evalComparison(
	scope *common.Scope, first common.ValueExpression, second common.ValueExpression, as string, literal string,
	name string,
) (*common.Event, string, error) {
	// the errors of the values pass on unwrapped, as in the other expressions: their literals tell where they failed
	firstValue, errorItemLiteral, itemError := first.EvalAny(scope)
	if itemError != nil {
		return nil, errorItemLiteral, itemError //nolint:wrapcheck // see above
	}

	secondValue, errorInLiteral, evalError := second.EvalAny(scope)
	if evalError != nil {
		return nil, errorInLiteral, evalError //nolint:wrapcheck // see above
	}

	compareValue, compareError := common.Compare(firstValue, secondValue, as)
	if compareError != nil {
		return nil, literal, fmt.Errorf("failed to compare %v: %w", name, compareError)
	}

	return compareValue, "", nil
}
