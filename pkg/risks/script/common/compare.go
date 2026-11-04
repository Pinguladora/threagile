package common

import (
	"fmt"

	"github.com/Pinguladora/threagile/pkg/risks/script/property"
)

func Compare(first Value, second Value, as string) (*Event, error) {
	firstValue := first
	secondValue := second
	if len(as) > 0 {
		var castError error
		firstValue, castError = CastValue(firstValue, as)
		if castError != nil {
			return nil, fmt.Errorf("failed to cast value to %q: %w", as, castError)
		}

		secondValue, castError = CastValue(secondValue, as)
		if castError != nil {
			return nil, fmt.Errorf("failed to cast value to %q: %w", as, castError)
		}
	}

	return compare(firstValue, secondValue)
}

func compare(firstValue Value, secondValue Value) (*Event, error) {
	switch first := firstValue.(type) {
	case *ArrayValue:
		second, conversionError := ToArrayValue(secondValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return compareArrays(first, second)

	case *BoolValue:
		second, conversionError := ToBoolValue(secondValue)
		if conversionError != nil {
			return nil, conversionError
		}

		if first.BoolValue() == second.BoolValue() {
			return NewEventFrom(NewEqualProperty(second), first, second), nil
		}

		return NewEventFrom(NewNotEqualProperty(second), first, second), nil

	case *DecimalValue:
		second, conversionError := ToDecimalValue(secondValue)
		if conversionError != nil {
			return nil, conversionError
		}

		value := first.DecimalValue().Cmp(second.DecimalValue())
		prop := NewEqualProperty(secondValue)
		if value < 0 {
			prop = NewLessProperty(secondValue)
		} else if value > 0 {
			prop = NewGreaterProperty(secondValue)
		}

		return NewEventFrom(prop, first, second), nil

	case *StringValue:
		second, conversionError := ToStringValue(secondValue)
		if conversionError != nil {
			return nil, conversionError
		}

		if first.StringValue() == second.StringValue() {
			return NewEventFrom(NewEqualProperty(second), first, second), nil
		}

		return NewEventFrom(NewNotEqualProperty(second), first, second), nil

	case *AnyValue:
		if firstValue.Value() == nil {
			return compare(nil, secondValue)
		}

	case nil:
		if event, isComparable := compareToNil(secondValue); isComparable {
			return event, nil
		}
	}

	return nil, fmt.Errorf("can't compare %T to %T", firstValue, secondValue)
}

// compareToNil compares nothing to a value, which nothing equals when it is empty, false, zero or nothing as well.
func compareToNil(secondValue Value) (*Event, bool) {
	var isEmpty bool
	switch second := secondValue.(type) {
	case *ArrayValue:
		isEmpty = len(second.ArrayValue()) == 0

	case *BoolValue:
		isEmpty = !second.BoolValue()

	case *DecimalValue:
		isEmpty = second.DecimalValue().IsZero()

	case *StringValue:
		isEmpty = len(second.StringValue()) == 0

	case *AnyValue:
		if second.Value() != nil {
			return nil, false
		}

		return NewEvent(NewEqualProperty(nil), nil), true

	case nil:
		return NewEvent(NewEqualProperty(nil), nil), true

	default:
		return nil, false
	}

	var first Value
	if isEmpty {
		return NewEventFrom(NewEqualProperty(secondValue), first, secondValue), true
	}

	return NewEventFrom(NewNotEqualProperty(secondValue), first, secondValue), true
}

func compareArrays(firstValue *ArrayValue, secondValue *ArrayValue) (*Event, error) {
	if len(firstValue.ArrayValue()) != len(secondValue.ArrayValue()) {
		return NewEventFrom(NewNotEqualProperty(firstValue), firstValue, secondValue), nil
	}

	for index, first := range firstValue.ArrayValue() {
		second := secondValue.ArrayValue()[index]
		event, compareError := compare(first, second)
		if compareError != nil {
			return event, compareError
		}

		if !IsSame(event.Property) {
			return NewEventFrom(NewNotEqualProperty(firstValue), firstValue, secondValue), nil
		}
	}

	return NewEventFrom(NewEqualProperty(firstValue), firstValue, secondValue), nil
}

func IsSame(value *Property) bool {
	if value == nil {
		return false
	}

	_, ok := value.Property.(*property.Equal)
	return ok
}

func IsGreater(value *Property) bool {
	if value == nil {
		return false
	}

	_, ok := value.Property.(*property.Greater)
	return ok
}

func IsLess(value *Property) bool {
	if value == nil {
		return false
	}

	_, ok := value.Property.(*property.Less)
	return ok
}

func ToString(value any) (*StringValue, error) {
	switch castValue := value.(type) {
	case string:
		return SomeStringValue(castValue, nil), nil

	case *StringValue:
		return castValue, nil

	case *AnyValue:
		aString, valueError := ToString(castValue.Value())
		stringValue := SomeStringValue(aString.StringValue(), castValue.Event())
		if valueError != nil {
			return stringValue, valueError
		}

		return stringValue, nil

	default:
		return EmptyStringValue(), fmt.Errorf("expected string, got %T", value)
	}
}
