package common

import (
	"fmt"
	"maps"
	"slices"

	"github.com/shopspring/decimal"
)

type AnyValue struct {
	value any
	name  Path
	event *Event
}

func (what AnyValue) Value() any {
	return what.value
}

func (what AnyValue) Name() Path {
	return what.name
}

func (what AnyValue) SetName(name ...string) {
	what.name.SetPath(name...)
}

func (what AnyValue) Event() *Event {
	return what.event
}

func (what AnyValue) PlainValue() any {
	if castValue, ok := what.value.(Value); ok {
		return castValue.PlainValue()
	}

	return what.value
}

func (what AnyValue) Text() []string {
	switch castValue := what.value.(type) {
	case []any:
		text := make([]string, 0)
		for _, item := range castValue {
			text = append(text, fmt.Sprintf("  - %v", item))
		}

		return text

	case map[string]any:
		text := make([]string, 0)
		for _, name := range slices.Sorted(maps.Keys(castValue)) {
			item := castValue[name]
			text = append(text, fmt.Sprintf("  %v: %v", name, item))
		}

		return text
	}

	return []string{fmt.Sprintf("%v", what.PlainValue())}
}

func NilValue() Value {
	return &AnyValue{}
}

func SomeValue(anyValue any, event *Event) Value {
	switch castValue := anyValue.(type) {
	case string:
		return SomeStringValue(castValue, event)

	case bool:
		return SomeBoolValue(castValue, event)

	case decimal.Decimal:
		return SomeDecimalValue(castValue, event)

	case []Value:
		return SomeArrayValue(castValue, event)

	case []any:
		return SomeArrayValue(toValues(castValue), event)

	case Value:
		return castValue
	}

	if number, isNumber := toDecimal(anyValue); isNumber {
		return SomeDecimalValue(number, event)
	}

	return &AnyValue{
		value: anyValue,
		event: event,
	}
}

// toValues converts the items to values, unless they are values already.
func toValues(items []any) []Value {
	array := make([]Value, 0)
	for _, item := range items {
		switch castItem := item.(type) {
		case Value:
			array = append(array, castItem)

		default:
			array = append(array, SomeValue(castItem, nil))
		}
	}

	return array
}

// toDecimal converts a number of one of the integer and floating point types to a decimal.
func toDecimal(anyValue any) (decimal.Decimal, bool) {
	switch castValue := anyValue.(type) {
	case int:
		return decimal.NewFromInt(int64(castValue)), true

	case int8:
		return decimal.NewFromInt(int64(castValue)), true

	case int16:
		return decimal.NewFromInt(int64(castValue)), true

	case int32:
		return decimal.NewFromInt(int64(castValue)), true

	case int64:
		return decimal.NewFromInt(castValue), true

	case float32:
		return decimal.NewFromFloat32(castValue), true

	case float64:
		return decimal.NewFromFloat(castValue), true

	default:
		return decimal.Decimal{}, false
	}
}

func AddValueHistory(anyValue Value, history []*Event) Value {
	if anyValue == nil {
		if len(history) == 0 {
			return nil
		}

		return SomeValue(nil, NewEvent(NewValueProperty(nil), EmptyPath()).AddHistory(history))
	}

	event := anyValue.Event()
	if event == nil {
		path := anyValue.Name()
		event = NewEvent(NewValueProperty(anyValue), &path).AddHistory(history)
	}

	return SomeValue(anyValue.PlainValue(), event)
}
