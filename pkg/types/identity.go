/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Identity is the identity that a communication link carries to its target: whose permissions the target
// checks.
type Identity int

const (
	NoneIdentity Identity = iota
	ServiceAccount
	Workload
	EndUser
)

func IdentityValues() []TypeEnum {
	return []TypeEnum{
		NoneIdentity,
		ServiceAccount,
		Workload,
		EndUser,
	}
}

var IdentityTypeDescription = [...]TypeDescription{
	{"none", "No identity reaches the target, like an anonymous call"},
	{"service-account", "The caller's own account with static credentials, like a database user (formerly the " +
		"technical-user authorization)"},
	{"workload", "The caller's own identity, short-lived and issued by the platform, like a cloud IAM role, a " +
		"Kubernetes service account token or a SPIFFE ID"},
	{"end-user", "The identity of the end user is passed on, like a forwarded or exchanged user token (formerly " +
		"the end-user-identity-propagation authorization)"},
}

// legacyIdentityNames are the values of the authorization of a communication link that earlier versions of the
// model used for its identity, with the spelling that releases up to 0.9 accepted (threagile#92).
var legacyIdentityNames = map[string]Identity{
	"technical-user":                ServiceAccount,
	"end-user-identity-propagation": EndUser,
	"enduser-identity-propagation":  EndUser,
}

// LegacyIdentity returns the identity that an authorization value of earlier versions of the model stands for, and
// whether it is one: none, technical-user or end-user-identity-propagation.
func LegacyIdentity(authorization string) (Identity, bool) {
	if strings.EqualFold(authorization, NoneIdentity.String()) {
		return NoneIdentity, true
	}
	identity, ok := legacyIdentityNames[strings.ToLower(authorization)]
	return identity, ok
}

func ParseIdentity(value string) (identity Identity, err error) {
	return Identity(0).Find(value)
}

func (what Identity) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return IdentityTypeDescription[what].Name
}

func (what Identity) Explain() string {
	return IdentityTypeDescription[what].Description
}

func (what Identity) Find(value string) (Identity, error) {
	if strings.TrimSpace(value) == "" {
		return NoneIdentity, nil // not modelled
	}
	for index, description := range IdentityTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return Identity(index), nil
		}
	}

	if legacy, ok := legacyIdentityNames[strings.ToLower(value)]; ok {
		return legacy, nil
	}

	return Identity(0), fmt.Errorf("unknown identity value %q", value)
}

func (what Identity) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *Identity) UnmarshalJSON(data []byte) error {
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

func (what Identity) MarshalYAML() (any, error) {
	return what.String(), nil
}

func (what *Identity) UnmarshalYAML(node *yaml.Node) error {
	value, findError := what.Find(node.Value)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}
