package statements

import (
	"errors"
	"fmt"

	"github.com/Pinguladora/threagile/pkg/risks/script/common"
	"github.com/Pinguladora/threagile/pkg/risks/script/expressions"
)

type IfStatement struct {
	literal    string
	expression common.BoolExpression
	yesPath    common.Statement
	noPath     common.Statement
}

func (what *IfStatement) Parse(script any) (common.Statement, any, error) {
	what.literal = common.ToLiteral(script)

	switch castScript := script.(type) {
	case map[any]any:
		for key, value := range castScript {
			statement, errorScript, parseError := what.parse(key, value, script)
			if parseError != nil {
				return statement, errorScript, parseError
			}
		}

	case map[string]any:
		for key, value := range castScript {
			statement, errorScript, parseError := what.parse(key, value, script)
			if parseError != nil {
				return statement, errorScript, parseError
			}
		}

	default:
		return nil, script, fmt.Errorf("failed to parse if-statement: expected map[string]any, got %T", script)
	}

	return what, nil, nil
}

func (what *IfStatement) parse(key any, value any, script any) (common.Statement, any, error) {
	switch key {
	case common.Then:
		item, errorScript, itemError := new(StatementList).Parse(value)
		if itemError != nil {
			return nil, errorScript, fmt.Errorf("failed to parse %q of if-statement: %w", key, itemError)
		}

		what.yesPath = item

	case common.Else:
		item, errorScript, itemError := new(StatementList).Parse(value)
		if itemError != nil {
			return nil, errorScript, fmt.Errorf("failed to parse %q of if-statement: %w", key, itemError)
		}

		what.noPath = item

	default:
		if what.expression != nil {
			return nil, script, errors.New("if-statement has multiple expressions")
		}

		item, errorScript, itemError := new(expressions.ExpressionList).ParseExpression(
			map[string]any{fmt.Sprintf("%v", key): value},
		)
		if itemError != nil {
			return nil, errorScript, fmt.Errorf("failed to parse expression of if-statement: %w", itemError)
		}

		boolItem, ok := item.(common.BoolExpression)
		if !ok {
			return nil, script, fmt.Errorf("expression of if-statement is not a bool expression: %w", itemError)
		}

		what.expression = boolItem
	}

	return what, nil, nil
}

func (what *IfStatement) Run(scope *common.Scope) (string, error) {
	if scope.HasReturned {
		return "", nil
	}

	if what.expression == nil {
		return "", nil
	}

	value, errorLiteral, evalError := what.expression.EvalBool(scope)
	if evalError != nil {
		return errorLiteral, fmt.Errorf("failed to eval the condition of if-statement: %w", evalError)
	}

	if value.BoolValue() {
		if what.yesPath != nil {
			scope.PushCall(common.NewEventFrom(common.NewTrueProperty(), value))
			defer scope.PopCall()

			return runIfPath(scope, common.Then, what.yesPath)
		}
	} else {
		if what.noPath != nil {
			scope.PushCall(common.NewEventFrom(common.NewFalseProperty(), value))
			defer scope.PopCall()

			return runIfPath(scope, common.Else, what.noPath)
		}
	}

	return "", nil
}

func (what *IfStatement) Literal() string {
	return what.literal
}

// runIfPath runs the "then" or "else" path of an if-statement.
func runIfPath(scope *common.Scope, key string, path common.Statement) (string, error) {
	errorLiteral, runError := path.Run(scope)
	if runError != nil {
		return errorLiteral, fmt.Errorf("failed to run %q of if-statement: %w", key, runError)
	}

	return errorLiteral, nil
}
