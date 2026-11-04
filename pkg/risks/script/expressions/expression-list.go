package expressions

import (
	"fmt"

	"github.com/Pinguladora/threagile/pkg/risks/script/common"
)

type ExpressionList struct {
	literal     string
	expressions []common.Expression
}

// newExpressions create the expressions by their keywords; ParseAny parses their scripts.
var newExpressions = map[string]func() common.Expression{
	common.All:            func() common.Expression { return new(AllExpression) },
	common.Any:            func() common.Expression { return new(AnyExpression) },
	common.And:            func() common.Expression { return new(AndExpression) },
	common.Contains:       func() common.Expression { return new(ContainsExpression) },
	common.Count:          func() common.Expression { return new(CountExpression) },
	common.Equal:          func() common.Expression { return new(EqualExpression) },
	common.EqualOrGreater: func() common.Expression { return new(EqualOrGreaterExpression) },
	common.EqualOrLess:    func() common.Expression { return new(EqualOrLessExpression) },
	common.False:          func() common.Expression { return new(FalseExpression) },
	common.Greater:        func() common.Expression { return new(GreaterExpression) },
	common.Less:           func() common.Expression { return new(LessExpression) },
	common.NotEqual:       func() common.Expression { return new(NotEqualExpression) },
	common.Or:             func() common.Expression { return new(OrExpression) },
	common.True:           func() common.Expression { return new(TrueExpression) },
}

func (what *ExpressionList) ParseExpression(script map[string]any) (common.Expression, any, error) {
	for key, value := range script {
		newExpression, ok := newExpressions[key]
		if !ok {
			return nil, script, fmt.Errorf("failed to parse expression: unexpected keyword %q", key)
		}

		return newExpression().ParseAny(value) //nolint:wrapcheck // only dispatches to the expression of the keyword
	}

	return what, nil, nil
}

func (what *ExpressionList) ParseArray(script any) (common.ExpressionList, any, error) {
	what.literal = common.ToLiteral(script)

	switch castScript := script.(type) {
	case []any:
		for _, expression := range castScript {
			item, errorScript, itemError := what.ParseAny(expression)
			if itemError != nil {
				return nil, errorScript, fmt.Errorf("failed to parse expression list: %w", itemError)
			}

			what.expressions = append(what.expressions, item)
		}

	default:
		return nil, script, fmt.Errorf("unexpected expression list format %T", script)
	}

	return what, nil, nil
}

func (what *ExpressionList) ParseAny(script any) (common.Expression, any, error) {
	what.literal = common.ToLiteral(script)

	switch castScript := script.(type) {
	case map[any]any:
		newMap := make(map[string]any)
		for key, value := range castScript {
			newMap[fmt.Sprintf("%v", key)] = value
		}

		return what.ParseExpression(newMap)

	case map[string]any:
		return what.ParseExpression(castScript)

	case []any:
		for _, expression := range castScript {
			item, errorScript, itemError := what.ParseAny(expression)
			if itemError != nil {
				return nil, errorScript, fmt.Errorf("failed to parse expression list: %w", itemError)
			}

			what.expressions = append(what.expressions, item)
		}

		if len(what.expressions) == 1 {
			return what.expressions[0], nil, nil
		}

	default:
		return new(ValueExpression).ParseAny(script)
	}

	return what, nil, nil
}

func (what *ExpressionList) EvalAny(scope *common.Scope) (common.Value, string, error) {
	if what.expressions == nil {
		return nil, "", nil
	}

	switch len(what.expressions) {
	case 0:
		return nil, "", nil

	case 1:
		return what.expressions[0].EvalAny(scope)

	default:
		var values []common.Value
		for _, expression := range what.expressions {
			value, errorLiteral, statementError := expression.EvalAny(scope)
			if statementError != nil {
				return nil, errorLiteral, statementError
			}

			values = append(values, value)
		}

		return common.SomeArrayValue(values, common.NewEvent(common.NewValueProperty(values), common.NewPath("array value")).From(values...)), "", nil
	}
}

func (what *ExpressionList) Literal() string {
	return what.literal
}

func (what *ExpressionList) Expressions() []common.Expression {
	return what.expressions
}
