// Package otm writes threat models in the Open Threat Model (OTM) format, IriusRisk's open,
// tool-neutral threat model format: https://github.com/iriusrisk/OpenThreatModel.
//
// The types follow the OTM JSON schema of the version in Version; the field names are OTM's own.
// FromInterchange translates the format-neutral elements of package interchange into OTM.
package otm

// Version is the OTM version that threagile writes and reads.
const Version = "0.2.0"

// Document is an OTM document.
type Document struct {
	OTMVersion  string       `json:"otmVersion"`
	Project     Project      `json:"project"`
	Assets      []Asset      `json:"assets,omitempty"`
	TrustZones  []TrustZone  `json:"trustZones,omitempty"`
	Components  []Component  `json:"components,omitempty"`
	Dataflows   []Dataflow   `json:"dataflows,omitempty"`
	Threats     []Threat     `json:"threats,omitempty"`
	Mitigations []Mitigation `json:"mitigations,omitempty"`
}

// Project is the unit of work that the other elements belong to.
type Project struct {
	Name         string     `json:"name"`
	ID           string     `json:"id"`
	Description  string     `json:"description,omitempty"`
	Owner        string     `json:"owner,omitempty"`
	OwnerContact string     `json:"ownerContact,omitempty"`
	Tags         []string   `json:"tags,omitempty"`
	Attributes   Attributes `json:"attributes,omitempty"`
}

// Asset is a kind of sensitive information.
type Asset struct {
	Name        string     `json:"name"`
	ID          string     `json:"id"`
	Description string     `json:"description,omitempty"`
	Risk        AssetRisk  `json:"risk"`
	Attributes  Attributes `json:"attributes,omitempty"`
}

// AssetRisk rates, from 0 to 100, how bad it would be to have an attacker see the asset, modify it,
// or make it unavailable.
type AssetRisk struct {
	Confidentiality float64 `json:"confidentiality"`
	Integrity       float64 `json:"integrity"`
	Availability    float64 `json:"availability"`
	Comment         string  `json:"comment,omitempty"`
}

// TrustZone is an area that components are in.
type TrustZone struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Type        string        `json:"type,omitempty"`
	Description string        `json:"description,omitempty"`
	Risk        TrustZoneRisk `json:"risk"`
	Parent      *Parent       `json:"parent,omitempty"`
	Attributes  Attributes    `json:"attributes,omitempty"`
}

// TrustZoneRisk rates how trustworthy a trust zone is, from 0 to 100.
type TrustZoneRisk struct {
	TrustRating float64 `json:"trustRating"`
}

// Parent is the trust zone or the component that encloses an element; exactly one is set.
type Parent struct {
	TrustZone string `json:"trustZone,omitempty"`
	Component string `json:"component,omitempty"`
}

// Component is a piece of software or hardware.
type Component struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Type        string           `json:"type"`
	Description string           `json:"description,omitempty"`
	Parent      Parent           `json:"parent"`
	Assets      *AssetInstance   `json:"assets,omitempty"`
	Threats     []ThreatInstance `json:"threats,omitempty"`
	Tags        []string         `json:"tags,omitempty"`
	Attributes  Attributes       `json:"attributes,omitempty"`
}

// AssetInstance names the assets that a component processes and stores.
type AssetInstance struct {
	Processed []string `json:"processed,omitempty"`
	Stored    []string `json:"stored,omitempty"`
}

// Dataflow is a movement of assets from one component to another.
type Dataflow struct {
	ID            string           `json:"id"`
	Name          string           `json:"name"`
	Description   string           `json:"description,omitempty"`
	Bidirectional bool             `json:"bidirectional,omitempty"`
	Source        string           `json:"source"`
	Destination   string           `json:"destination"`
	Assets        []string         `json:"assets,omitempty"`
	Threats       []ThreatInstance `json:"threats,omitempty"`
	Tags          []string         `json:"tags,omitempty"`
	Attributes    Attributes       `json:"attributes,omitempty"`
}

// Threat is an undesirable outcome.
type Threat struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Categories  []string   `json:"categories,omitempty"`
	CWEs        []string   `json:"cwes,omitempty"`
	Risk        ThreatRisk `json:"risk"`
	Tags        []string   `json:"tags,omitempty"`
	Attributes  Attributes `json:"attributes,omitempty"`
}

// ThreatRisk rates, from 0 to 100, how likely a threat is and how bad it would be.
type ThreatRisk struct {
	Likelihood        float64 `json:"likelihood"`
	LikelihoodComment string  `json:"likelihoodComment,omitempty"`
	Impact            float64 `json:"impact"`
	ImpactComment     string  `json:"impactComment,omitempty"`
}

// Mitigation is an action or control against a threat.
type Mitigation struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Description   string     `json:"description,omitempty"`
	RiskReduction float64    `json:"riskReduction"`
	Attributes    Attributes `json:"attributes,omitempty"`
}

// ThreatInstance is a threat at a component or a dataflow, in a state.
type ThreatInstance struct {
	Threat      string               `json:"threat"`
	State       string               `json:"state"`
	Mitigations []MitigationInstance `json:"mitigations,omitempty"`
}

// MitigationInstance is a mitigation of a threat instance, in a state.
type MitigationInstance struct {
	Mitigation string `json:"mitigation"`
	State      string `json:"state"`
}

// Attributes complete the description of an element with free-form values.
type Attributes map[string]string
