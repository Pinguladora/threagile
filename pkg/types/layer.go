package types

import (
	"encoding/json"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Layer is the part of the system a technical asset belongs to, so that a report can focus on some of them: the
// application, the platform it runs on, or how it is delivered.
type Layer int

const (
	// UnsetLayer leaves the layer to the usage of the asset, see TechnicalAsset.ReportLayer.
	UnsetLayer Layer = iota
	ApplicationLayer
	PlatformLayer
	DeliveryLayer
)

// LayerValues returns the layers a model may name, without UnsetLayer.
func LayerValues() []TypeEnum {
	return []TypeEnum{
		ApplicationLayer,
		PlatformLayer,
		DeliveryLayer,
	}
}

var LayerTypeDescription = [...]TypeDescription{
	{"", "Not set: business assets are application, devops assets delivery"},
	{"application", "The system itself: what serves its users and handles its business data"},
	{"platform", "What the system is deployed on and run by, such as clusters, hypervisors, workload identity, " +
		"logging and monitoring"},
	{"delivery", "How the system is built, released and maintained, such as source repositories, CI, artifact " +
		"registries, bots and developer machines"},
}

// ParseLayer parses the name of a layer. An empty name is UnsetLayer.
func ParseLayer(value string) (Layer, error) {
	return UnsetLayer.find(strings.TrimSpace(value))
}

func (what Layer) String() string {
	return LayerTypeDescription[what].Name
}

func (what Layer) Explain() string {
	return LayerTypeDescription[what].Description
}

func (what Layer) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *Layer) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	value, err := what.find(text)
	if err != nil {
		return err
	}
	*what = value
	return nil
}

func (what Layer) MarshalYAML() (any, error) {
	return what.String(), nil
}

func (what *Layer) UnmarshalYAML(node *yaml.Node) error {
	value, err := what.find(node.Value)
	if err != nil {
		return err
	}
	*what = value
	return nil
}

func (what Layer) find(value string) (Layer, error) {
	for index, description := range LayerTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return Layer(index), nil
		}
	}
	return UnsetLayer, fmt.Errorf("unknown layer value %q", value)
}

// ReportLayer is the layer of the technical asset: the one it names, or else application for a business asset and
// delivery for a devops one.
func (what TechnicalAsset) ReportLayer() Layer {
	switch {
	case what.Layer != UnsetLayer:
		return what.Layer
	case what.Usage == DevOps:
		return DeliveryLayer
	default:
		return ApplicationLayer
	}
}
