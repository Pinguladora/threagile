package statements

import (
	"fmt"

	"github.com/Pinguladora/threagile/pkg/risks/script/common"
)

type Statement struct{}

func (what *Statement) Parse(name string, body any) (common.Statement, any, error) {
	var parse func(script any) (common.Statement, any, error)
	switch name {
	case common.Assign:
		parse = new(AssignStatement).Parse

	case common.Defer:
		parse = new(DeferStatement).Parse

	case common.Explain:
		parse = new(ExplainStatement).Parse

	case common.If:
		parse = new(IfStatement).Parse

	case common.Loop:
		parse = new(LoopStatement).Parse

	case common.Return:
		parse = new(ReturnStatement).Parse

	default:
		return nil, body, fmt.Errorf("failed to parse statement: unexpected keyword %q", name)
	}

	statement, errorScript, parseError := parse(body)
	if parseError != nil {
		return nil, errorScript, fmt.Errorf("failed to parse %q-statement: %w", name, parseError)
	}

	return statement, errorScript, parseError
}
