/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"encoding/json"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v4"
)

type Authentication int

const (
	NoneAuthentication Authentication = iota
	Credentials
	SessionId
	Token
	ClientCertificate
	MultiFactor
	Externalized
	ShortLivedToken
	LongLivedToken
)

func AuthenticationValues() []TypeEnum {
	return []TypeEnum{
		NoneAuthentication,
		Credentials,
		SessionId,
		Token,
		ShortLivedToken,
		LongLivedToken,
		ClientCertificate,
		MultiFactor,
		Externalized,
	}
}

var AuthenticationTypeDescription = [...]TypeDescription{
	{"none", "No authentication"},
	{"credentials", "Username and password, pin or passphrase"},
	{"session-id", "A server generated session id with limited life span"},
	{"token", "A cryptographically signed token whose lifetime is not modelled; prefer short-lived-token or " +
		"long-lived-token"},
	{"client-certificate", "A certificate file stored on the client identifying this specific client"},
	{"multi-factor", "Credentials plus one or more other factors, like a security key, an authenticator app or " +
		"biometrics (formerly two-factor)"},
	{"externalized", "Some external company handles authentication"},
	{"short-lived-token", "A signed token that expires within hours, like an OAuth 2.0 access token or an OpenID " +
		"Connect ID token"},
	{"long-lived-token", "A bearer secret that does not expire soon, like an API key or a personal access token"},
}

// legacyAuthenticationNames are the names that earlier versions of the model used.
var legacyAuthenticationNames = map[string]Authentication{
	"two-factor": MultiFactor,
}

func ParseAuthentication(value string) (authentication Authentication, err error) {
	return Authentication(0).Find(value)
}

func (what Authentication) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return AuthenticationTypeDescription[what].Name
}

func (what Authentication) Explain() string {
	return AuthenticationTypeDescription[what].Description
}

func (what Authentication) Find(value string) (Authentication, error) {
	for index, description := range AuthenticationTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return Authentication(index), nil
		}
	}

	if legacy, ok := legacyAuthenticationNames[strings.ToLower(value)]; ok {
		return legacy, nil
	}

	return Authentication(0), fmt.Errorf("unknown authentication value %q", value)
}

func (what Authentication) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *Authentication) UnmarshalJSON(data []byte) error {
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

func (what Authentication) MarshalYAML() (any, error) {
	return what.String(), nil
}

func (what *Authentication) UnmarshalYAML(node *yaml.Node) error {
	value, findError := what.Find(node.Value)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}
