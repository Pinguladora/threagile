package otm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/Pinguladora/threagile/pkg/interchange"
	"github.com/Pinguladora/threagile/pkg/types"
	"go.yaml.in/yaml/v3"
)

// UnmarshalJSON reads attributes, turning values that are not strings into their JSON text. OTM
// files in the wild have attributes that are no object, such as a list; those are left out
// rather than failing the whole document.
func (what *Attributes) UnmarshalJSON(data []byte) error {
	var values map[string]json.RawMessage
	if trimmed := bytes.TrimSpace(data); len(trimmed) == 0 || trimmed[0] != '{' {
		*what = nil
		return nil
	}

	if err := json.Unmarshal(data, &values); err != nil {
		return fmt.Errorf("unable to parse attributes: %w", err)
	}

	attributes := make(Attributes, len(values))
	for key, raw := range values {
		var text string
		if json.Unmarshal(raw, &text) == nil {
			attributes[key] = text
			continue
		}
		attributes[key] = string(raw)
	}

	*what = attributes
	return nil
}

// Parse reads an OTM document, which may be JSON or YAML.
func Parse(data []byte) (*Document, error) {
	var content any
	if err := yaml.Unmarshal(data, &content); err != nil {
		return nil, fmt.Errorf("unable to parse OTM: %w", err)
	}

	// YAML is a superset of JSON; going through JSON lets the types carry a single set of tags
	jsonData, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("unable to parse OTM: %w", err)
	}

	var document Document
	if err := json.Unmarshal(jsonData, &document); err != nil {
		return nil, fmt.Errorf("unable to parse OTM: %w", err)
	}

	if document.OTMVersion == "" {
		return nil, errors.New("unable to parse OTM: the document has no otmVersion")
	}

	return &document, nil
}

// ToInterchange turns an OTM document into elements. Threats and mitigations are left out, as
// threagile generates the risks of a model when it analyzes it, and so is the trust zone of the
// components outside of all trust boundaries. A parent component of a trust zone or a component
// becomes its ParentID, for interchange.ToInput to resolve.
func ToInterchange(document *Document) *interchange.Model {
	outside := outsideZone(document.TrustZones)
	return &interchange.Model{
		Project: interchange.Project{
			ID:           document.Project.ID,
			Name:         document.Project.Name,
			Description:  document.Project.Description,
			Owner:        document.Project.Owner,
			OwnerContact: document.Project.OwnerContact,
			Tags:         document.Project.Tags,
			Properties:   properties(document.Project.Attributes),
		},
		Zones:      zones(document.TrustZones, outside),
		Components: componentElements(document.Components, outside),
		Flows:      flows(document.Dataflows),
		DataAssets: dataAssets(document.Assets),
	}
}

// outsideZone is the id of the trust zone FromInterchange added for the components outside of all
// trust boundaries, empty when the document has none (as any OTM file from another tool).
func outsideZone(trustZones []TrustZone) string {
	for _, zone := range trustZones {
		if zone.Attributes[outsideZoneAttribute] == "true" {
			return zone.ID
		}
	}

	return ""
}

func zones(trustZones []TrustZone, outside string) []interchange.Zone {
	result := make([]interchange.Zone, 0, len(trustZones))
	for _, zone := range trustZones {
		if outside != "" && zone.ID == outside {
			continue
		}

		result = append(result, interchange.Zone{
			ID:          zone.ID,
			Name:        zone.Name,
			Type:        zone.Type,
			Description: zone.Description,
			ParentID:    parentID(zone.Parent, outside),
			Properties:  properties(zone.Attributes),
		})
	}

	return result
}

func componentElements(components []Component, outside string) []interchange.Component {
	result := make([]interchange.Component, 0, len(components))
	for _, component := range components {
		element := interchange.Component{
			ID:          component.ID,
			Name:        component.Name,
			Type:        component.Type,
			Description: component.Description,
			ParentID:    parentID(&component.Parent, outside),
			Tags:        component.Tags,
			Properties:  properties(component.Attributes),
		}
		if component.Assets != nil {
			element.Processed = component.Assets.Processed
			element.Stored = component.Assets.Stored
		}
		result = append(result, element)
	}

	return result
}

func flows(dataflows []Dataflow) []interchange.Flow {
	result := make([]interchange.Flow, 0, len(dataflows))
	for _, flow := range dataflows {
		result = append(result, interchange.Flow{
			ID:            flow.ID,
			Name:          flow.Name,
			Description:   flow.Description,
			SourceID:      flow.Source,
			DestinationID: flow.Destination,
			Bidirectional: flow.Bidirectional,
			DataAssets:    flow.Assets,
			Tags:          flow.Tags,
			Properties:    properties(flow.Attributes),
		})
	}

	return result
}

func dataAssets(assets []Asset) []interchange.DataAsset {
	result := make([]interchange.DataAsset, 0, len(assets))
	for _, asset := range assets {
		result = append(result, interchange.DataAsset{
			ID:              asset.ID,
			Name:            asset.Name,
			Description:     asset.Description,
			Confidentiality: types.Confidentiality(level(asset.Risk.Confidentiality, len(types.ConfidentialityValues()))),
			Integrity:       types.Criticality(level(asset.Risk.Integrity, len(types.CriticalityValues()))),
			Availability:    types.Criticality(level(asset.Risk.Availability, len(types.CriticalityValues()))),
			Justification:   asset.Risk.Comment,
			Properties:      properties(asset.Attributes),
		})
	}

	return result
}

// parentID is the id of the enclosing trust zone or component, empty for none or the outside zone
// (the trust zone of the components outside of all trust boundaries).
func parentID(parent *Parent, outside string) string {
	if parent == nil || (outside != "" && parent.TrustZone == outside) {
		return ""
	}
	if parent.TrustZone != "" {
		return parent.TrustZone
	}
	return parent.Component
}

// level is the nearest of the levels of a rating to the score.
func level(score float64, levels int) int {
	return int(min(max(math.Round(score/scoreStep), 0), float64(levels-1)))
}

// properties return the threagile attributes of an element as its properties.
func properties(attributes Attributes) interchange.Properties {
	result := make(interchange.Properties)
	for key, value := range attributes {
		if name, found := strings.CutPrefix(key, attributePrefix); found {
			result[name] = value
		}
	}
	return result
}
