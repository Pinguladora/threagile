package expressions

import (
	"testing"

	"github.com/Pinguladora/threagile/pkg/risks/script/common"
	"github.com/stretchr/testify/assert"
)

func TestComparisonsRequireBothValues(t *testing.T) {
	for name, expression := range map[string]func() common.BoolExpression{
		"equal":            func() common.BoolExpression { return new(EqualExpression) },
		"not-equal":        func() common.BoolExpression { return new(NotEqualExpression) },
		"less":             func() common.BoolExpression { return new(LessExpression) },
		"equal-or-less":    func() common.BoolExpression { return new(EqualOrLessExpression) },
		"greater":          func() common.BoolExpression { return new(GreaterExpression) },
		"equal-or-greater": func() common.BoolExpression { return new(EqualOrGreaterExpression) },
	} {
		_, _, err := expression().ParseBool(map[string]any{"first": "1"})
		assert.ErrorContains(t, err, `missing "second"`, name)
		_, _, err = expression().ParseBool(map[string]any{"second": "1"})
		assert.ErrorContains(t, err, `missing "first"`, name)
	}

	_, _, err := new(ContainsExpression).ParseBool(map[string]any{"item": "1"})
	assert.ErrorContains(t, err, `missing "in"`)
}

func TestIterationsRequireIn(t *testing.T) {
	for name, parse := range map[string]func(any) (common.BoolExpression, any, error){
		"any": new(AnyExpression).ParseBool,
		"all": new(AllExpression).ParseBool,
	} {
		_, _, err := parse(map[string]any{"item": "x", "true": "{x}"})
		assert.ErrorContains(t, err, `missing "in"`, name)
	}
}
