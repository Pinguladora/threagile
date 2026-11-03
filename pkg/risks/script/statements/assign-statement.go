package statements

import (
	"fmt"
	"maps"
	"slices"

	"github.com/Pinguladora/threagile/pkg/risks/script/common"
	"github.com/Pinguladora/threagile/pkg/risks/script/expressions"
)

type AssignStatement struct {
	literal string
	items   map[string]common.Expression
	names   []string // the assigned names in the order they are run
}

func (what *AssignStatement) Parse(script any) (common.Statement, any, error) {
	what.literal = common.ToLiteral(script)

	if what.items == nil {
		what.items = make(map[string]common.Expression)
	}

	switch castScript := script.(type) {
	case map[string]any:
		return what.parse(castScript)

	case []any:
		for _, statement := range castScript {
			_, errorScript, itemError := what.Parse(statement)
			if itemError != nil {
				return nil, errorScript, fmt.Errorf("failed to parse assign-statement: %w", itemError)
			}
		}

	default:
		return nil, script, fmt.Errorf("unexpected assign-statement format %T", script)
	}

	return what, nil, nil
}

func (what *AssignStatement) parse(script map[string]any) (common.Statement, any, error) {
	// a list of assignments runs in list order, the keys of a single map in key order
	for _, key := range slices.Sorted(maps.Keys(script)) {
		expression, errorScript, parseError := new(expressions.ExpressionList).ParseAny(script[key])
		if parseError != nil {
			return nil, errorScript, fmt.Errorf("failed to parse %q of assign-statement: %w", key, parseError)
		}

		if _, exists := what.items[key]; !exists {
			what.names = append(what.names, key)
		}
		what.items[key] = expression
	}

	return what, nil, nil
}

func (what *AssignStatement) Run(scope *common.Scope) (string, error) {
	if scope.HasReturned {
		return "", nil
	}

	for _, name := range what.names {
		value, errorLiteral, evalError := what.items[name].EvalAny(scope)
		if evalError != nil {
			return errorLiteral, fmt.Errorf("failed to eval %q of assign-statement: %w", name, evalError)
		}

		scope.Set(name, value)
	}

	return "", nil
}

func (what *AssignStatement) Literal() string {
	return what.literal
}
