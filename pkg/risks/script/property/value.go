package property

import (
	"fmt"
	"maps"
	"slices"
)

type Value struct {
	value   any
	negated bool
}

func NewValue(value any) *Value {
	return &Value{value: value}
}

func (what *Value) Negate() {
	what.negated = !what.negated
}

func (what *Value) Negated() bool {
	return what.negated
}

func (what *Value) Text() []string {
	lines, isList := listText(what.value)
	if !isList {
		if what.negated {
			return []string{fmt.Sprintf("not %v", what.value)}
		}

		return []string{fmt.Sprintf("%v", what.value)}
	}

	text := make([]string, 0, len(lines)+1)
	if what.negated {
		text = append(text, "not")
	}

	return append(text, lines...)
}

// listText returns the lines of a value that shows as a list: a texter, a slice or a map (sorted by its keys).
func listText(value any) ([]string, bool) {
	switch castValue := value.(type) {
	case Texter:
		lines := make([]string, 0)
		for _, line := range castValue.Text() {
			lines = append(lines, fmt.Sprintf("  %v", line))
		}

		return lines, true

	case []any:
		lines := make([]string, 0, len(castValue))
		for _, item := range castValue {
			lines = append(lines, fmt.Sprintf("  - %v", item))
		}

		return lines, true

	case map[string]any:
		lines := make([]string, 0, len(castValue))
		for _, name := range slices.Sorted(maps.Keys(castValue)) {
			item := castValue[name]
			lines = append(lines, fmt.Sprintf("  %v: %v", name, item))
		}

		return lines, true
	}

	return nil, false
}
