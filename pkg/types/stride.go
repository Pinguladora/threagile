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

type STRIDE int

const (
	Spoofing STRIDE = iota
	Tampering
	Repudiation
	InformationDisclosure
	DenialOfService
	ElevationOfPrivilege
)

func STRIDEValues() []TypeEnum {
	return []TypeEnum{
		Spoofing,
		Tampering,
		Repudiation,
		InformationDisclosure,
		DenialOfService,
		ElevationOfPrivilege,
	}
}

var StrideTypeDescription = [...]TypeDescription{
	{"spoofing", "Spoofing, against authenticity"},
	{"tampering", "Tampering, against integrity"},
	{"repudiation", "Repudiation, against non-repudiability"},
	{"information-disclosure", "Information disclosure, against confidentiality"},
	{"denial-of-service", "Denial of service, against availability"},
	{"elevation-of-privilege", "Elevation of privilege, against authorization"},
}

func ParseSTRIDE(value string) (stride STRIDE, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range STRIDEValues() {
		if parsed, ok := candidate.(STRIDE); ok && parsed.String() == value {
			return parsed, err
		}
	}
	return stride, fmt.Errorf("unable to parse into type: %v", value)
}

func (what STRIDE) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return StrideTypeDescription[what].Name
}

func (what STRIDE) Explain() string {
	return StrideTypeDescription[what].Description
}

func (what STRIDE) Title() string {
	return [...]string{
		"Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege",
	}[what]
}

func (what STRIDE) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *STRIDE) UnmarshalJSON(data []byte) error {
	var text string
	unmarshalError := json.Unmarshal(data, &text)
	if unmarshalError != nil {
		return unmarshalError
	}

	value, findError := what.find(text)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what STRIDE) MarshalYAML() (any, error) {
	return what.String(), nil
}

func (what *STRIDE) UnmarshalYAML(node *yaml.Node) error {
	value, findError := what.find(node.Value)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what STRIDE) find(value string) (STRIDE, error) {
	for index, description := range StrideTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return STRIDE(index), nil
		}
	}

	return STRIDE(0), fmt.Errorf("unknown STRIDE value %q", value)
}
