package common

import (
	"fmt"
	"maps"
	"slices"

	"github.com/shopspring/decimal"
)

// IterationItem is an item of an iterable value.
type IterationItem struct {
	Index Value  // the index (a decimal) of the item in a slice, or its key (a string) in a map
	Value any    // the value of the item
	Event *Event // the event of the item if it is a value itself, otherwise nil
	Label string // how error messages refer to the item
}

// ForEachItem calls visit for each item of an iterable value, a slice or a map (in the order of its sorted keys),
// until visit tells to stop.
func ForEachItem(iterable any, visit func(item IterationItem) (stop bool)) {
	switch castValue := iterable.(type) {
	case []any:
		for index, value := range castValue {
			stop := visit(IterationItem{
				Index: SomeDecimalValue(decimal.NewFromInt(int64(index)), nil),
				Value: value,
				Label: fmt.Sprintf("#%v", index+1),
			})
			if stop {
				return
			}
		}

	case []Value:
		for index, value := range castValue {
			stop := visit(IterationItem{
				Index: SomeDecimalValue(decimal.NewFromInt(int64(index)), nil),
				Value: value.Value(),
				Event: value.Event(),
				Label: fmt.Sprintf("#%v", index+1),
			})
			if stop {
				return
			}
		}

	case map[string]any:
		for _, name := range slices.Sorted(maps.Keys(castValue)) {
			stop := visit(IterationItem{
				Index: SomeStringValue(name, nil),
				Value: castValue[name],
				Label: fmt.Sprintf("%q", name),
			})
			if stop {
				return
			}
		}
	}
}
