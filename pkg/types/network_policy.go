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

// NetworkPolicy is the traffic that the network policies of a Kubernetes namespace, an execution environment trust
// boundary, deny unless they allow it.
type NetworkPolicy int

const (
	UnknownNetworkPolicy NetworkPolicy = iota
	NoNetworkPolicy
	IngressNetworkPolicy
	EgressNetworkPolicy
	IngressAndEgressNetworkPolicy
)

func NetworkPolicyValues() []TypeEnum {
	return []TypeEnum{
		UnknownNetworkPolicy,
		NoNetworkPolicy,
		IngressNetworkPolicy,
		EgressNetworkPolicy,
		IngressAndEgressNetworkPolicy,
	}
}

var NetworkPolicyTypeDescription = [...]TypeDescription{
	{"unknown", "Not modelled, or not a Kubernetes namespace; the risk rules assume nothing about network policies"},
	{"none", "No network policy: every pod of the cluster may reach the pods of the namespace, and they may reach " +
		"anything"},
	{"ingress", "Incoming traffic is denied unless a policy allows it; outgoing traffic is not restricted"},
	{"egress", "Outgoing traffic is denied unless a policy allows it; incoming traffic is not restricted"},
	{"ingress-and-egress", "Incoming and outgoing traffic are denied unless a policy allows them"},
}

// RestrictsIngress tells whether the policies deny the traffic into the namespace that they do not allow.
func (what NetworkPolicy) RestrictsIngress() bool {
	return what == IngressNetworkPolicy || what == IngressAndEgressNetworkPolicy
}

// RestrictsEgress tells whether the policies deny the traffic out of the namespace that they do not allow.
func (what NetworkPolicy) RestrictsEgress() bool {
	return what == EgressNetworkPolicy || what == IngressAndEgressNetworkPolicy
}

func ParseNetworkPolicy(value string) (NetworkPolicy, error) {
	return NetworkPolicy(0).Find(value)
}

func (what NetworkPolicy) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return NetworkPolicyTypeDescription[what].Name
}

func (what NetworkPolicy) Explain() string {
	return NetworkPolicyTypeDescription[what].Description
}

func (what NetworkPolicy) Find(value string) (NetworkPolicy, error) {
	if strings.TrimSpace(value) == "" {
		return UnknownNetworkPolicy, nil // not modelled
	}
	for index, description := range NetworkPolicyTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return NetworkPolicy(index), nil
		}
	}

	return NetworkPolicy(0), fmt.Errorf("unknown network policy value %q", value)
}

func (what NetworkPolicy) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *NetworkPolicy) UnmarshalJSON(data []byte) error {
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

func (what NetworkPolicy) MarshalYAML() (any, error) {
	return what.String(), nil
}

func (what *NetworkPolicy) UnmarshalYAML(node *yaml.Node) error {
	value, findError := what.Find(node.Value)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}
