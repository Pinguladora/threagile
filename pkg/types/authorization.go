/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"encoding/json"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Authorization is how finely the target of a communication link checks what the caller may do. Which identity
// the check is about is the Identity of the link.
type Authorization int

const (
	UnknownAuthorization Authorization = iota
	NoneAuthorization
	AuthenticatedOnly
	FunctionLevel
	ObjectLevel
)

func AuthorizationValues() []TypeEnum {
	return []TypeEnum{
		UnknownAuthorization,
		NoneAuthorization,
		AuthenticatedOnly,
		FunctionLevel,
		ObjectLevel,
	}
}

var AuthorizationTypeDescription = [...]TypeDescription{
	{"unknown", "Not modelled; the risk rules assume nothing about the authorization"},
	{"none", "No authorization: every caller may do everything"},
	{"authenticated-only", "Every authenticated caller may do everything"},
	{"function-level", "Each operation checks whether the caller may call it, for example by role"},
	{"object-level", "Each operation also checks whether the caller may access the object at hand, like the " +
		"order or the account"},
}

func ParseAuthorization(value string) (authorization Authorization, err error) {
	return Authorization(0).Find(value)
}

func (what Authorization) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return AuthorizationTypeDescription[what].Name
}

func (what Authorization) Explain() string {
	return AuthorizationTypeDescription[what].Description
}

func (what Authorization) Find(value string) (Authorization, error) {
	if strings.TrimSpace(value) == "" {
		return UnknownAuthorization, nil // not modelled
	}
	for index, description := range AuthorizationTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return Authorization(index), nil
		}
	}

	return Authorization(0), fmt.Errorf("unknown authorization value %q", value)
}

func (what Authorization) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *Authorization) UnmarshalJSON(data []byte) error {
	var text string
	unmarshalError := json.Unmarshal(data, &text)
	if unmarshalError != nil {
		return unmarshalError
	}

	value, findError := what.Find(text)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what Authorization) MarshalYAML() (any, error) {
	return what.String(), nil
}

func (what *Authorization) UnmarshalYAML(node *yaml.Node) error {
	value, findError := what.Find(node.Value)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}
