package statements

import (
	"fmt"

	"github.com/Pinguladora/threagile/pkg/risks/script/common"
)

type MethodStatement struct {
	literal    string
	parameters []string
	body       common.Statement
}

func (what *MethodStatement) Parse(script any) (common.Statement, any, error) {
	what.literal = common.ToLiteral(script)

	castScript, ok := script.(map[string]any)
	if !ok {
		return nil, script, fmt.Errorf("failed to parse method-statement: expected map[string]any, got %T", script)
	}

	for key, value := range castScript {
		switch key {
		case common.Parameter, common.Parameters:
			parameters, errorScript, parameterError := parseMethodParameters(key, value)
			if parameterError != nil {
				return nil, errorScript, parameterError
			}

			what.parameters = append(what.parameters, parameters...)

		case common.Do:
			item, errorScript, itemError := new(StatementList).Parse(value)
			if itemError != nil {
				return nil, errorScript, fmt.Errorf("failed to parse %q of method-statement: %w", key, itemError)
			}

			what.body = item

		default:
			return nil, script, fmt.Errorf("failed to parse method-statement: unexpected statement %q", key)
		}
	}

	return what, nil, nil
}

// parseMethodParameters parses the names of the parameters of a method: a list of names or a single one.
func parseMethodParameters(key string, value any) ([]string, any, error) {
	switch castValue := value.(type) {
	case []string:
		return castValue, nil, nil

	case []any:
		parameters := make([]string, 0, len(castValue))
		for _, generic := range castValue {
			text, ok := generic.(string)
			if !ok {
				return nil, generic, fmt.Errorf("failed to parse %q of method-statement: expected string, got %T", key, generic)
			}

			parameters = append(parameters, text)
		}

		return parameters, nil, nil

	case string:
		return []string{castValue}, nil, nil

	default:
		return nil, value, fmt.Errorf("failed to parse %q of method-statement: unexpected parameter type %T", key, value)
	}
}

func (what *MethodStatement) Run(scope *common.Scope) (string, error) {
	if scope.HasReturned {
		return "", nil
	}

	defer what.runDeferred(scope)

	if len(what.parameters) != len(scope.Args) {
		return what.Literal(),
			fmt.Errorf("failed to run method-statement: expected %d parameters, got %d", len(what.parameters), len(scope.Args))
	}

	for n, name := range what.parameters {
		scope.Set(name, scope.Args[n])
	}

	if what.body != nil {
		errorLiteral, runError := what.body.Run(scope)
		if runError != nil {
			return errorLiteral, fmt.Errorf("failed to run method-statement: %w", runError)
		}
	}

	return "", nil
}

func (what *MethodStatement) runDeferred(scope *common.Scope) {
	for _, statement := range scope.Deferred {
		scope.HasReturned = false
		_, _ = statement.Run(scope)
	}

	if scope.Explain != nil {
		scope.HasReturned = false
		scope.CallStack = make(common.History, 0)

		returnValue := scope.GetReturnValue()
		if returnValue != nil {
			returnValue = common.SomeValue(returnValue.PlainValue(), returnValue.Event())
			scope.SetReturnValue(returnValue)
		}
	}
}

func (what *MethodStatement) Literal() string {
	return what.literal
}
