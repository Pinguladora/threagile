// Package interchange is the format-neutral layer between threagile's models and the threat model
// formats that threagile exchanges models in, such as the Open Threat Model (OTM).
//
// FromModel turns an analyzed model into a flat set of elements that refer to each other by id,
// and ToInput turns such elements back into a model as a model YAML file holds it. The elements
// speak threagile's own vocabulary (its enum names, its risk statuses); each format package
// translates that vocabulary into the terms of its format and back.
package interchange

import (
	"slices"
	"strings"

	"github.com/Pinguladora/threagile/pkg/types"
)

// Model is a threat model as a set of elements. FromModel sorts every list by id.
type Model struct {
	Project    Project
	Zones      []Zone
	Components []Component
	Flows      []Flow
	DataAssets []DataAsset
	Threats    []Threat
}

// Project is the model as a whole.
type Project struct {
	ID           string
	Name         string
	Description  string
	Owner        string
	OwnerContact string
	Tags         []string
	Properties   Properties
}

// Zone is a trust boundary.
type Zone struct {
	ID          string
	Name        string
	Type        string // the name of a threagile trust boundary type
	Description string
	ParentID    string // the zone this zone is nested in, empty for a top-level zone
	Properties  Properties
}

// Component is a technical asset.
type Component struct {
	ID          string
	Name        string
	Type        string // the name of the threagile technology of the asset
	Description string
	// ParentID is the zone the component is in, empty when it is outside of all zones. Formats that
	// nest components in components may name a component here; ToInput then puts the component
	// into the zone of that component.
	ParentID   string
	Tags       []string
	Processed  []string // ids of the data assets the component processes
	Stored     []string // ids of the data assets the component stores
	Threats    []ThreatInstance
	Properties Properties
}

// Flow is a communication link.
type Flow struct {
	ID            string
	Name          string
	Description   string
	SourceID      string
	DestinationID string
	// Bidirectional is set when data flows both ways: the link sends data assets and receives some
	// back. The data-flow diagram draws such a link with an arrow at both ends.
	Bidirectional bool
	DataAssets    []string // ids of the data assets sent or received
	Tags          []string
	Threats       []ThreatInstance
	Properties    Properties
}

// DataAsset is a data asset.
type DataAsset struct {
	ID              string
	Name            string
	Description     string
	Confidentiality types.Confidentiality
	Integrity       types.Criticality
	Availability    types.Criticality
	Justification   string // the justification of the CIA rating
	Properties      Properties
}

// Threat is a risk category that the analysis found risks of.
type Threat struct {
	ID          string
	Name        string
	Description string
	STRIDE      types.STRIDE
	CWE         int // 0 when the category names no CWE
	// Likelihood and Impact are the highest of the risks of the category.
	Likelihood types.RiskExploitationLikelihood
	Impact     types.RiskExploitationImpact
	ImpactText string // what the category says about the impact
	Mitigation Mitigation
	Properties Properties
}

// Mitigation is what the risk category recommends against its risks.
type Mitigation struct {
	Name        string // the action of the category
	Description string
	Check       string
}

// ThreatInstance is a risk: one occurrence of a threat at a component or flow.
type ThreatInstance struct {
	ThreatID string
	Status   types.RiskStatus // the status of the risk tracking, unchecked when it is not tracked
}

// Properties hold the details of an element that the element has no field of its own for, keyed by
// the name of the field in a threagile model YAML file (machine, data_assets_received, ...). Formats
// keep them in their extension mechanism, such as OTM attributes, so that a threagile model keeps
// them on its way through the format and back. A list is a comma-separated value.
type Properties map[string]string

// Property names that hold a list or a flag rather than a single value.
const (
	tagsProperty = "tags"
	trueValue    = "true"
	listSep      = ","
)

// set keeps value under key unless it is empty.
func (what Properties) set(key string, value string) {
	if value != "" {
		what[key] = value
	}
}

// setFlag keeps a flag that is set.
func (what Properties) setFlag(key string, value bool) {
	if value {
		what[key] = trueValue
	}
}

// setList keeps a list that is not empty.
func (what Properties) setList(key string, values []string) {
	what.set(key, strings.Join(values, listSep))
}

// flag tells whether the flag key is set.
func (what Properties) flag(key string) bool {
	return what[key] == trueValue
}

// list returns the list under key, without empty items.
func (what Properties) list(key string) []string {
	if what[key] == "" {
		return nil
	}

	values := make([]string, 0)
	for value := range strings.SplitSeq(what[key], listSep) {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}

	return values
}

// sorted returns a sorted copy of values without duplicates, or nil when it is empty.
func sorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	return slices.Compact(slices.Sorted(slices.Values(values)))
}
