package common

import (
	"fmt"

	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/shopspring/decimal"
)

const (
	authentication  = "authentication"
	identity        = "identity"
	authorization   = "authorization"
	confidentiality = "confidentiality"
	criticality     = "criticality"
	integrity       = "integrity"
	availability    = "availability"
	probability     = "probability"
	encryption      = "encryption"
	quantity        = "quantity"
	impact          = "impact"
	likelihood      = "likelihood"
	size            = "size"
)

var cast = map[string]castFunc{
	authentication:  toAuthentication,
	identity:        toIdentity,
	authorization:   toAuthorization,
	confidentiality: toConfidentiality,
	criticality:     toCriticality,
	integrity:       toCriticality,
	availability:    toCriticality,
	probability:     toProbability,
	encryption:      toEncryption,
	quantity:        toQuantity,
	impact:          toImpact,
	likelihood:      toLikelihood,
	size:            toSize,
}

type castFunc func(value Value) (Value, error)

func CastValue(value Value, castType string) (Value, error) {
	if value == nil {
		return NilValue(), nil
	}

	caster, ok := cast[castType]
	if !ok {
		return nil, fmt.Errorf("unknown cast type %v", castType)
	}

	return caster(value)
}

func toConfidentiality(value Value) (Value, error) {
	return castToEnum(value, types.Confidentiality(0).Find)
}

func toCriticality(value Value) (Value, error) {
	return castToEnum(value, types.Criticality(0).Find)
}

func toAuthentication(value Value) (Value, error) {
	return castToEnum(value, types.Authentication(0).Find)
}

func toIdentity(value Value) (Value, error) {
	return castToEnum(value, types.Identity(0).Find)
}

func toAuthorization(value Value) (Value, error) {
	return castToEnum(value, types.Authorization(0).Find)
}

func toProbability(value Value) (Value, error) {
	return castToEnum(value, types.DataBreachProbability(0).Find)
}

func toEncryption(value Value) (Value, error) {
	return castToEnum(value, types.EncryptionStyle(0).Find)
}

func toQuantity(value Value) (Value, error) {
	return castToEnum(value, types.Quantity(0).Find)
}

func toImpact(value Value) (Value, error) {
	return castToEnum(value, types.RiskExploitationImpact(0).Find)
}

func toLikelihood(value Value) (Value, error) {
	return castToEnum(value, types.RiskExploitationLikelihood(0).Find)
}

func toSize(value Value) (Value, error) {
	return castToEnum(value, types.TechnicalAssetSize(0).Find)
}

// castToEnum casts a value to the number of a value of an enum type: the value is either a name that find finds, or
// the number already.
func castToEnum[T ~int](value Value, find func(name string) (T, error)) (Value, error) {
	switch castValue := value.Value().(type) {
	case string:
		converted, conversionError := find(castValue)
		if conversionError != nil {
			return nil, conversionError
		}

		return SomeDecimalValue(decimal.NewFromInt(int64(converted)), value.Event()), nil

	case int:
		return SomeDecimalValue(decimal.NewFromInt(int64(castValue)), value.Event()), nil

	case int64:
		return SomeDecimalValue(decimal.NewFromInt(castValue), value.Event()), nil

	case Value:
		return castToEnum(castValue, find)

	default:
		return nil, fmt.Errorf("toConfidentiality: unexpected type %T", value)
	}
}
