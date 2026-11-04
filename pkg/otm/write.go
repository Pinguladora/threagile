package otm

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/Pinguladora/threagile/pkg/interchange"
	"github.com/Pinguladora/threagile/pkg/types"
)

// OutsideZoneID is the id of the trust zone that holds the components outside of all trust
// boundaries, as OTM requires every component to have a parent. FromInterchange adds it only when
// there are such components (with a numeric suffix if a trust boundary already has this id) and
// marks it with the outsideZoneAttribute, by which ToInterchange recognises and leaves it out.
const OutsideZoneID = "outside-trust-boundaries"

const (
	outsideZoneName = "Outside of all trust boundaries"
	outsideZoneType = "untrusted"
	// outsideZoneAttribute marks the trust zone FromInterchange adds for the components outside of
	// all trust boundaries.
	outsideZoneAttribute = attributePrefix + OutsideZoneID
	// attributePrefix namespaces the threagile properties among the attributes of an element.
	attributePrefix = "threagile:"
	// mitigationSuffix makes the id of the mitigation of a threat from the id of the threat.
	mitigationSuffix = "-mitigation"
	cwePrefix        = "CWE-"
)

// The OTM scales run from 0 to 100. Threagile's ratings have four or five levels, which are spread
// evenly over that range: the lowest level is 0 (CIA) or 25 (likelihood, impact), each further
// level adds 25.
const (
	maxScore  = 100
	scoreStep = 25
	// riskReduction is how much a mitigation reduces the risk of its threat: threagile considers
	// a mitigated risk as no longer at risk.
	riskReduction = maxScore
)

// Trust ratings of the trust zones, from 0 (untrusted) to 100. A trust boundary that protects a
// smaller part of the network is trusted more than one around a whole network; a dedicated hoster
// or a cloud provider is trusted less than one's own premises.
const (
	outsideTrustRating      = 0  // outside of all trust boundaries
	defaultTrustRating      = 50 // a zone type that is no threagile trust boundary type
	onPremTrustRating       = 50 // network-on-prem
	hostedTrustRating       = 40 // network-dedicated-hoster, network-cloud-provider
	segmentedTrustRating    = 60 // network-virtual-lan, network-cloud-security-group
	namespacedTrustRating   = 70 // network-policy-namespace-isolation
	topLevelExecutionRating = defaultTrustRating
)

// trustRatings rate the network trust boundaries. An execution environment is a logical group
// rather than a protective boundary, so it has the rating of the zone it is nested in.
var trustRatings = map[string]float64{
	types.NetworkOnPrem.String():                   onPremTrustRating,
	types.NetworkDedicatedHoster.String():          hostedTrustRating,
	types.NetworkCloudProvider.String():            hostedTrustRating,
	types.NetworkVirtualLAN.String():               segmentedTrustRating,
	types.NetworkCloudSecurityGroup.String():       segmentedTrustRating,
	types.NetworkPolicyNamespaceIsolation.String(): namespacedTrustRating,
}

// The states of threat and mitigation instances. OTM leaves them open: its examples use exposed and
// mitigated for threats and required and implemented for mitigations; the others follow suit.
const (
	threatExposed         = "exposed"
	threatAccepted        = "accepted"
	threatMitigated       = "mitigated"
	notApplicable         = "not-applicable"
	mitigationRecommended = "recommended"
	mitigationRequired    = "required"
	mitigationRejected    = "rejected"
	mitigationImplemented = "implemented"
)

// state is the OTM state of a threat instance and of its mitigation.
type state struct {
	threat     string
	mitigation string
}

// states map the status of the risk tracking to the state of the threat instance and its
// mitigation: a risk that is still at risk leaves the threat exposed, and the mitigation is
// recommended until the risk is being mitigated.
var states = map[types.RiskStatus]state{
	types.Unchecked:     {threat: threatExposed, mitigation: mitigationRecommended},
	types.InDiscussion:  {threat: threatExposed, mitigation: mitigationRecommended},
	types.InProgress:    {threat: threatExposed, mitigation: mitigationRequired},
	types.Accepted:      {threat: threatAccepted, mitigation: mitigationRejected},
	types.Mitigated:     {threat: threatMitigated, mitigation: mitigationImplemented},
	types.FalsePositive: {threat: notApplicable, mitigation: notApplicable},
}

// FromInterchange turns elements into an OTM document, with every list sorted by id.
func FromInterchange(model *interchange.Model) *Document {
	outside := outsideZoneID(model.Zones)
	document := &Document{
		OTMVersion: Version,
		Project: Project{
			Name:         model.Project.Name,
			ID:           model.Project.ID,
			Description:  model.Project.Description,
			Owner:        model.Project.Owner,
			OwnerContact: model.Project.OwnerContact,
			Tags:         model.Project.Tags,
			Attributes:   attributes(model.Project.Properties),
		},
		TrustZones: trustZones(model, outside),
		Components: components(model.Components, outside),
		Dataflows:  dataflows(model.Flows),
		Assets:     assets(model.DataAssets),
	}

	for _, threat := range model.Threats {
		otmThreat, mitigation := newThreat(threat)
		document.Threats = append(document.Threats, otmThreat)
		document.Mitigations = append(document.Mitigations, mitigation)
	}

	sortByID(document)
	return document
}

func components(elements []interchange.Component, outside string) []Component {
	result := make([]Component, 0, len(elements))
	for _, component := range elements {
		parent := component.ParentID
		if parent == "" {
			parent = outside
		}

		otmComponent := Component{
			ID:          component.ID,
			Name:        component.Name,
			Type:        component.Type,
			Description: component.Description,
			Parent:      Parent{TrustZone: parent},
			Threats:     threatInstances(component.Threats),
			Tags:        component.Tags,
			Attributes:  attributes(component.Properties),
		}
		if len(component.Processed) > 0 || len(component.Stored) > 0 {
			otmComponent.Assets = &AssetInstance{Processed: component.Processed, Stored: component.Stored}
		}
		result = append(result, otmComponent)
	}

	return result
}

func dataflows(elements []interchange.Flow) []Dataflow {
	result := make([]Dataflow, 0, len(elements))
	for _, flow := range elements {
		result = append(result, Dataflow{
			ID:            flow.ID,
			Name:          flow.Name,
			Description:   flow.Description,
			Bidirectional: flow.Bidirectional,
			Source:        flow.SourceID,
			Destination:   flow.DestinationID,
			Assets:        flow.DataAssets,
			Threats:       threatInstances(flow.Threats),
			Tags:          flow.Tags,
			Attributes:    attributes(flow.Properties),
		})
	}

	return result
}

func assets(elements []interchange.DataAsset) []Asset {
	result := make([]Asset, 0, len(elements))
	for _, asset := range elements {
		result = append(result, Asset{
			Name:        asset.Name,
			ID:          asset.ID,
			Description: asset.Description,
			Risk: AssetRisk{
				Confidentiality: float64(asset.Confidentiality) * scoreStep,
				Integrity:       float64(asset.Integrity) * scoreStep,
				Availability:    float64(asset.Availability) * scoreStep,
				Comment:         asset.Justification,
			},
			Attributes: attributes(asset.Properties),
		})
	}

	return result
}

// outsideZoneID is OutsideZoneID, or the first OutsideZoneID-<n> that no trust boundary uses.
func outsideZoneID(zones []interchange.Zone) string {
	taken := make(map[string]bool, len(zones))
	for _, zone := range zones {
		taken[zone.ID] = true
	}

	id := OutsideZoneID
	for n := 2; taken[id]; n++ {
		id = fmt.Sprintf("%s-%d", OutsideZoneID, n)
	}

	return id
}

func trustZones(model *interchange.Model, outside string) []TrustZone {
	zones := make(map[string]interchange.Zone, len(model.Zones))
	for _, zone := range model.Zones {
		zones[zone.ID] = zone
	}

	trustZones := make([]TrustZone, 0, len(model.Zones)+1)
	for _, zone := range model.Zones {
		trustZone := TrustZone{
			ID:          zone.ID,
			Name:        zone.Name,
			Type:        zone.Type,
			Description: zone.Description,
			Risk:        TrustZoneRisk{TrustRating: trustRating(zone, zones)},
			Attributes:  attributes(zone.Properties),
		}
		if zone.ParentID != "" {
			trustZone.Parent = &Parent{TrustZone: zone.ParentID}
		}
		trustZones = append(trustZones, trustZone)
	}

	isOutside := func(component interchange.Component) bool { return component.ParentID == "" }
	if slices.ContainsFunc(model.Components, isOutside) {
		trustZones = append(trustZones, TrustZone{
			ID:          outside,
			Name:        outsideZoneName,
			Type:        outsideZoneType,
			Description: "The technical assets that are in no trust boundary of the threagile model.",
			Risk:        TrustZoneRisk{TrustRating: outsideTrustRating},
			Attributes:  Attributes{outsideZoneAttribute: "true"},
		})
	}

	return trustZones
}

// trustRating rates the zone by its type, an execution environment by the zone it is nested in.
func trustRating(zone interchange.Zone, zones map[string]interchange.Zone) float64 {
	seen := make(map[string]bool)
	for zone.Type == types.ExecutionEnvironment.String() && !seen[zone.ID] {
		seen[zone.ID] = true
		parent, found := zones[zone.ParentID]
		if !found {
			return topLevelExecutionRating
		}
		zone = parent
	}

	if rating, found := trustRatings[zone.Type]; found {
		return rating
	}
	return defaultTrustRating
}

func newThreat(threat interchange.Threat) (Threat, Mitigation) {
	otmThreat := Threat{
		ID:          threat.ID,
		Name:        threat.Name,
		Description: threat.Description,
		Categories:  []string{threat.STRIDE.Title()},
		Risk: ThreatRisk{
			Likelihood:    float64(threat.Likelihood.Weight() * scoreStep),
			Impact:        float64(threat.Impact.Weight() * scoreStep),
			ImpactComment: threat.ImpactText,
		},
		Attributes: attributes(threat.Properties),
	}
	if threat.CWE > 0 {
		otmThreat.CWEs = []string{cwePrefix + strconv.Itoa(threat.CWE)}
	}

	mitigation := Mitigation{
		ID:            threat.ID + mitigationSuffix,
		Name:          threat.Mitigation.Name,
		Description:   threat.Mitigation.Description,
		RiskReduction: riskReduction,
	}
	if mitigation.Name == "" {
		mitigation.Name = threat.Name
	}
	if threat.Mitigation.Check != "" {
		mitigation.Attributes = Attributes{attributePrefix + "check": threat.Mitigation.Check}
	}

	return otmThreat, mitigation
}

// threatInstances turns the risks of an element into threat instances. An OTM threat instance
// names only its threat and states, so several risks of one category at an element in the same
// states, such as risks about different data assets, become a single threat instance.
func threatInstances(instances []interchange.ThreatInstance) []ThreatInstance {
	type key struct {
		threat string
		state  state
	}

	result := make([]ThreatInstance, 0, len(instances))
	seen := make(map[key]bool, len(instances))
	for _, instance := range instances {
		instanceState := states[instance.Status]
		if seen[key{threat: instance.ThreatID, state: instanceState}] {
			continue
		}
		seen[key{threat: instance.ThreatID, state: instanceState}] = true

		result = append(result, ThreatInstance{
			Threat: instance.ThreatID,
			State:  instanceState.threat,
			Mitigations: []MitigationInstance{
				{Mitigation: instance.ThreatID + mitigationSuffix, State: instanceState.mitigation},
			},
		})
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

// attributes namespace the properties of an element as its attributes.
func attributes(properties interchange.Properties) Attributes {
	if len(properties) == 0 {
		return nil
	}

	result := make(Attributes, len(properties))
	for key, value := range properties {
		result[attributePrefix+key] = value
	}
	return result
}

func sortByID(document *Document) {
	slices.SortFunc(document.TrustZones, func(a, b TrustZone) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(document.Components, func(a, b Component) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(document.Dataflows, func(a, b Dataflow) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(document.Assets, func(a, b Asset) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(document.Threats, func(a, b Threat) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(document.Mitigations, func(a, b Mitigation) int { return strings.Compare(a.ID, b.ID) })
}
