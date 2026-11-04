package statements

import (
	"fmt"

	"github.com/Pinguladora/threagile/pkg/risks/script/common"
	"github.com/Pinguladora/threagile/pkg/risks/script/expressions"
)

type LoopStatement struct {
	literal string
	in      common.ValueExpression
	item    string
	index   string
	body    common.Statement
}

func (what *LoopStatement) Parse(script any) (common.Statement, any, error) {
	what.literal = common.ToLiteral(script)

	castScript, ok := script.(map[string]any)
	if !ok {
		return nil, script, fmt.Errorf("failed to parse loop-statement: expected map[string]any, got %T", script)
	}

	for key, value := range castScript {
		switch key {
		case common.In:
			item, errorExpression, itemError := new(expressions.ValueExpression).ParseValue(value)
			if itemError != nil {
				return nil, errorExpression, fmt.Errorf("failed to parse %q of loop-statement: %w", key, itemError)
			}

			what.in = item

		case common.Item, common.Index:
			text, ok := value.(string)
			if !ok {
				return nil, value, fmt.Errorf("failed to parse %q of loop-statement: expected string, got %T", key, value)
			}

			what.setName(key, text)

		case common.Do:
			item, errorScript, itemError := new(StatementList).Parse(value)
			if itemError != nil {
				return nil, errorScript, fmt.Errorf("failed to parse %q of loop-statement: %w", key, itemError)
			}

			what.body = item

		default:
			return nil, script, fmt.Errorf("failed to parse loop-statement: unexpected keyword %q", key)
		}
	}

	return what, nil, nil
}

// setName sets the name of the current item or of its index, by the key it is given under.
func (what *LoopStatement) setName(key string, name string) {
	if key == common.Item {
		what.item = name
	} else {
		what.index = name
	}
}

func (what *LoopStatement) Run(scope *common.Scope) (string, error) {
	if scope.HasReturned {
		return "", nil
	}

	oldIterator := scope.PopItem()
	defer scope.SetItem(oldIterator)

	value, errorEvalLiteral, evalError := what.in.EvalAny(scope)
	if evalError != nil {
		return errorEvalLiteral, fmt.Errorf("failed to eval %q of loop-statement: %w", common.In, evalError)
	}

	return what.run(scope, value)
}

func (what *LoopStatement) run(scope *common.Scope, value common.Value) (string, error) {
	switch castValue := value.Value().(type) {
	case []any, []common.Value, map[string]any:
		var errorLiteral string
		var runError error
		common.ForEachItem(castValue, func(item common.IterationItem) bool {
			if scope.HasReturned {
				return true
			}

			if len(what.index) > 0 {
				scope.Set(what.index, item.Index)
			}

			itemValue := scope.SetItem(common.SomeValue(item.Value, value.Event()))
			if len(what.item) > 0 {
				scope.Set(what.item, itemValue)
			}

			bodyLiteral, bodyError := what.body.Run(scope)
			if bodyError != nil {
				errorLiteral = bodyLiteral
				runError = fmt.Errorf("failed to run loop-statement for item %v: %w", item.Label, bodyError)
				return true
			}

			return false
		})

		return errorLiteral, runError

	case common.Value:
		return what.run(scope, common.SomeValue(castValue.Value(), value.Event()))

	default:
		return what.Literal(), fmt.Errorf("failed to run loop-statement: expected iterable type, got %T", value)
	}
}

func (what *LoopStatement) Literal() string {
	return what.literal
}
