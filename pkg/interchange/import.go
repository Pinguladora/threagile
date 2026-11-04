package interchange

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Pinguladora/threagile/pkg/input"
	"github.com/Pinguladora/threagile/pkg/types"
)

// The values that ToInput gives the fields that threagile requires and the elements leave open,
// when their properties do not hold them either. Where the right value is unknown, the defaults
// lean towards more risks rather than fewer: a link authenticates and authorizes nothing, an asset
// encrypts nothing. Review them in the imported model.
const (
	DefaultBusinessCriticality = "important"          // business_criticality of the model
	DefaultTrustBoundaryType   = "network-on-prem"    // type of a trust boundary of an unknown zone type
	DefaultTechnology          = "unknown-technology" // technology of an asset of an unknown component type
	DefaultTechnicalAssetType  = "process"            // type of a technical asset
	DefaultSize                = "application"        // size of a technical asset
	DefaultMachine             = "virtual"            // machine of a technical asset
	DefaultEncryption          = "none"               // encryption of a technical asset
	DefaultUsage               = "business"           // usage of a technical asset, communication link or data asset
	DefaultConfidentiality     = "internal"           // confidentiality of a technical asset
	DefaultCriticality         = "operational"        // integrity and availability of a technical asset
	DefaultProtocol            = "unknown-protocol"   // protocol of a communication link
	DefaultAuthentication      = "none"               // authentication of a communication link
	DefaultAuthorization       = "none"               // authorization of a communication link
	DefaultQuantity            = "few"                // quantity of a data asset
)

var invalidIDCharacters = regexp.MustCompile(`[^a-zA-Z0-9\-]+`)

// ToInput turns elements into a threagile model as a model YAML file holds it, and returns it with
// notes on what it could not carry over. Zones become trust boundaries, components technical
// assets, flows communication links of their source asset, and data assets data assets. A field
// that threagile requires and the elements have no value for takes its value from the properties,
// or else one of the defaults above. Threats are left out: threagile generates the risks of a
// model when it analyzes it.
//
// Ids that threagile does not accept (it takes letters, digits and hyphens) are turned into such
// ids. As threagile keys trust boundaries, assets and links by name, a name that is taken already
// gets the id of its element appended. Technologies are looked up in technologies.
func ToInput(model *Model, technologies types.TechnologyMap) (*input.Model, []string) {
	importer := newImporter(model, technologies)
	result := new(input.Model).Defaults()

	result.Title = model.Project.Name
	result.Author = input.Author{Name: model.Project.Owner, Contact: model.Project.OwnerContact}
	result.AppDescription.Description = model.Project.Description
	project := importer.fieldsOf(model.Project.Properties, "the project")
	result.BusinessCriticality = project.enum("business_criticality", DefaultBusinessCriticality,
		parses(types.ParseCriticality))
	if date := model.Project.Properties["date"]; date != "" {
		if _, err := time.Parse(dateFormat, date); err == nil {
			result.Date = date
		} else {
			importer.note("the project: date %q is not like %s, left out", date, dateFormat)
		}
	}

	importer.addDataAssets(result)
	importer.addTechnicalAssets(result)
	importer.addCommunicationLinks(result)
	importer.addTrustBoundaries(result)
	result.TagsAvailable = sorted(append(slices.Clone(model.Project.Tags), importer.tags...))

	return result, importer.notes
}

type importer struct {
	model        *Model
	technologies types.TechnologyMap
	components   map[string]Component // by element id
	zoneIDs      map[string]string    // threagile id by element id
	componentIDs map[string]string
	dataAssetIDs map[string]string
	assetTitles  map[string]string // title of the technical asset by component id
	tags         []string          // every tag an element uses, all of which the model needs to declare
	notes        []string
}

func newImporter(model *Model, technologies types.TechnologyMap) *importer {
	what := &importer{
		model:        model,
		technologies: technologies,
		components:   make(map[string]Component, len(model.Components)),
		assetTitles:  make(map[string]string, len(model.Components)),
	}
	for _, component := range model.Components {
		what.components[component.ID] = component
	}

	what.zoneIDs = newIDs(what, "trust zone", model.Zones, func(zone Zone) string { return zone.ID })
	what.componentIDs = newIDs(what, "component", model.Components, func(element Component) string { return element.ID })
	what.dataAssetIDs = newIDs(what, "data asset", model.DataAssets, func(asset DataAsset) string { return asset.ID })
	return what
}

func (what *importer) addDataAssets(result *input.Model) {
	titles := make(map[string]bool)
	for _, asset := range what.model.DataAssets {
		properties := asset.Properties
		fields := what.fieldsOf(properties, fmt.Sprintf("data asset %q", asset.ID))
		result.DataAssets[uniqueName(titles, identity, asset.Name, asset.ID)] = input.DataAsset{
			ID:                     what.dataAssetIDs[asset.ID],
			Description:            asset.Description,
			Usage:                  fields.enum("usage", DefaultUsage, parses(types.ParseUsage)),
			Tags:                   what.useTags(properties.list(tagsProperty)),
			Origin:                 properties["origin"],
			Owner:                  properties["owner"],
			Quantity:               fields.enum("quantity", DefaultQuantity, parses(types.ParseQuantity)),
			Confidentiality:        asset.Confidentiality.String(),
			Integrity:              asset.Integrity.String(),
			Availability:           asset.Availability.String(),
			JustificationCiaRating: asset.Justification,
		}
	}
}

func (what *importer) addTechnicalAssets(result *input.Model) {
	titles := make(map[string]bool)
	for _, component := range what.model.Components {
		where := fmt.Sprintf("component %q", component.ID)
		properties := component.Properties
		fields := what.fieldsOf(properties, where)
		asset := input.TechnicalAsset{
			ID:                      what.componentIDs[component.ID],
			Description:             component.Description,
			Type:                    fields.enum("type", DefaultTechnicalAssetType, parses(types.ParseTechnicalAssetType)),
			Usage:                   fields.enum("usage", DefaultUsage, parses(types.ParseUsage)),
			UsedAsClientByHuman:     properties.flag("used_as_client_by_human"),
			OutOfScope:              properties.flag("out_of_scope"),
			JustificationOutOfScope: properties["justification_out_of_scope"],
			Size:                    fields.enum("size", DefaultSize, parses(types.ParseTechnicalAssetSize)),
			Tags:                    what.useTags(component.Tags),
			Internet:                properties.flag("internet"),
			Machine:                 fields.enum("machine", DefaultMachine, parses(types.ParseTechnicalAssetMachine)),
			Encryption:              fields.enum("encryption", DefaultEncryption, parses(types.ParseEncryptionStyle)),
			Owner:                   properties["owner"],
			Confidentiality:         fields.enum("confidentiality", DefaultConfidentiality, parses(types.ParseConfidentiality)),
			Integrity:               fields.enum("integrity", DefaultCriticality, parses(types.ParseCriticality)),
			Availability:            fields.enum("availability", DefaultCriticality, parses(types.ParseCriticality)),
			JustificationCiaRating:  properties["justification_cia_rating"],
			MultiTenant:             properties.flag("multi_tenant"),
			Redundant:               properties.flag("redundant"),
			CustomDevelopedParts:    properties.flag("custom_developed_parts"),
			DataAssetsProcessed:     what.dataAssetRefs(component.Processed, where),
			DataAssetsStored:        what.dataAssetRefs(component.Stored, where),
		}
		what.setTechnologies(&asset, component, where)

		for _, format := range properties.list("data_formats_accepted") {
			if _, err := types.ParseDataFormat(format); err != nil {
				what.note("%s: data format %q is unknown to threagile, left out", where, format)
				continue
			}
			asset.DataFormatsAccepted = append(asset.DataFormatsAccepted, format)
		}

		title := uniqueName(titles, identity, component.Name, component.ID)
		what.assetTitles[component.ID] = title
		result.TechnicalAssets[title] = asset
	}
}

// setTechnologies sets the technologies of the asset from the technologies property of the
// component, or else from its type.
func (what *importer) setTechnologies(asset *input.TechnicalAsset, component Component, where string) {
	names := component.Properties.list("technologies")
	if len(names) == 0 {
		names = []string{component.Type}
	}

	technologies := make([]string, 0, len(names))
	for _, name := range names {
		if what.technologies.Get(name) == nil {
			what.note("%s: type %q is no threagile technology, imported as %s", where, name, DefaultTechnology)
			name = DefaultTechnology
		}
		if !slices.Contains(technologies, name) {
			technologies = append(technologies, name)
		}
	}

	if len(technologies) == 1 {
		asset.Technology = technologies[0]
		return
	}
	asset.Technologies = technologies
}

func (what *importer) addCommunicationLinks(result *input.Model) {
	titlesBySource := make(map[string]map[string]bool)
	for _, flow := range what.model.Flows {
		where := fmt.Sprintf("dataflow %q", flow.ID)
		sourceTitle, sourceFound := what.assetTitles[flow.SourceID]
		_, targetFound := what.assetTitles[flow.DestinationID]
		if !sourceFound || !targetFound {
			what.note("%s: leads from %q to %q, but threagile only links components, left out",
				where, flow.SourceID, flow.DestinationID)
			continue
		}

		if titlesBySource[sourceTitle] == nil {
			titlesBySource[sourceTitle] = make(map[string]bool)
		}

		source := result.TechnicalAssets[sourceTitle]
		if source.CommunicationLinks == nil {
			source.CommunicationLinks = make(map[string]input.CommunicationLink)
		}

		properties := flow.Properties
		fields := what.fieldsOf(properties, where)
		sent, received := what.flowDataAssets(flow, where)
		// threagile derives the id of a link from its name, so the names need to differ in more than case
		title := uniqueName(titlesBySource[sourceTitle], Slug, flow.Name, flow.ID)
		source.CommunicationLinks[title] = input.CommunicationLink{
			Target:             what.componentIDs[flow.DestinationID],
			Description:        flow.Description,
			Protocol:           fields.enum("protocol", DefaultProtocol, parses(types.ParseProtocol)),
			Authentication:     fields.enum("authentication", DefaultAuthentication, parses(types.ParseAuthentication)),
			Authorization:      fields.enum("authorization", DefaultAuthorization, parses(types.ParseAuthorization)),
			Tags:               what.useTags(flow.Tags),
			VPN:                properties.flag("vpn"),
			IpFiltered:         properties.flag("ip_filtered"),
			Readonly:           properties.flag("readonly"),
			Usage:              fields.enum("usage", DefaultUsage, parses(types.ParseUsage)),
			DataAssetsSent:     sent,
			DataAssetsReceived: received,
		}
		result.TechnicalAssets[sourceTitle] = source
	}
}

// flowDataAssets returns the data assets the flow sends and receives: those of its properties,
// or else its data assets, which a bidirectional flow sends and receives back.
func (what *importer) flowDataAssets(flow Flow, where string) ([]string, []string) {
	properties := flow.Properties
	if properties["data_assets_sent"] != "" || properties["data_assets_received"] != "" {
		return what.dataAssetRefs(properties.list("data_assets_sent"), where),
			what.dataAssetRefs(properties.list("data_assets_received"), where)
	}

	sent := what.dataAssetRefs(flow.DataAssets, where)
	if flow.Bidirectional {
		return sent, slices.Clone(sent)
	}
	return sent, nil
}

func (what *importer) addTrustBoundaries(result *input.Model) {
	titles := make(map[string]bool)
	boundaryTitles := make(map[string]string, len(what.model.Zones)) // by zone id
	for _, zone := range what.model.Zones {
		fields := what.fieldsOf(Properties{"type": zone.Type}, fmt.Sprintf("trust zone %q", zone.ID))
		title := uniqueName(titles, identity, zone.Name, zone.ID)
		boundaryTitles[zone.ID] = title
		result.TrustBoundaries[title] = input.TrustBoundary{
			ID:          what.zoneIDs[zone.ID],
			Description: zone.Description,
			Type:        fields.enum("type", DefaultTrustBoundaryType, parses(types.ParseTrustBoundary)),
			Tags:        what.useTags(zone.Properties.list(tagsProperty)),
		}
	}

	for _, zone := range what.model.Zones {
		if zone.ParentID == "" {
			continue
		}

		parentTitle, found := boundaryTitles[zone.ParentID]
		if !found {
			what.note("trust zone %q: its parent %q is no trust zone, imported as a top-level trust boundary",
				zone.ID, zone.ParentID)
			continue
		}

		parent := result.TrustBoundaries[parentTitle]
		parent.TrustBoundariesNested = append(parent.TrustBoundariesNested, what.zoneIDs[zone.ID])
		result.TrustBoundaries[parentTitle] = parent
	}

	for _, component := range what.model.Components {
		zoneID := what.zoneOf(component)
		if zoneID == "" {
			continue
		}

		boundary := result.TrustBoundaries[boundaryTitles[zoneID]]
		boundary.TechnicalAssetsInside = append(boundary.TechnicalAssetsInside, what.componentIDs[component.ID])
		result.TrustBoundaries[boundaryTitles[zoneID]] = boundary
	}
}

// zoneOf returns the zone of the component, which for a component nested in another component is
// the zone of that one, or empty when the component is outside of all zones.
func (what *importer) zoneOf(component Component) string {
	if component.ParentID == "" {
		return ""
	}

	if _, isZone := what.zoneIDs[component.ParentID]; isZone {
		return component.ParentID
	}

	where := fmt.Sprintf("component %q", component.ID)
	if _, isComponent := what.components[component.ParentID]; !isComponent {
		what.note("%s: its parent %q is unknown, imported outside of all trust boundaries", where, component.ParentID)
		return ""
	}

	what.note("%s: is nested in component %q, but threagile does not nest technical assets, "+
		"imported into its trust boundary", where, component.ParentID)
	seen := map[string]bool{component.ID: true}
	for parentID := component.ParentID; parentID != "" && !seen[parentID]; {
		if _, isZone := what.zoneIDs[parentID]; isZone {
			return parentID
		}

		seen[parentID] = true
		parentID = what.components[parentID].ParentID
	}

	return ""
}

// dataAssetRefs returns the threagile ids of the data assets, leaving out unknown ones.
func (what *importer) dataAssetRefs(ids []string, where string) []string {
	refs := make([]string, 0, len(ids))
	for _, id := range ids {
		ref, found := what.dataAssetIDs[id]
		if !found {
			what.note("%s: data asset %q is unknown, left out", where, id)
			continue
		}
		refs = append(refs, ref)
	}

	return sorted(refs)
}

// useTags returns the tags in their order without empty ones and duplicates, and records them for
// the tags the model declares.
func (what *importer) useTags(tags []string) []string {
	used := make([]string, 0, len(tags))
	for _, tag := range tags {
		if tag = strings.TrimSpace(tag); tag != "" && !slices.Contains(used, tag) {
			used = append(used, tag)
		}
	}

	what.tags = append(what.tags, used...)
	if len(used) == 0 {
		return nil
	}
	return used
}

// fields reads the properties of an element, noting values that threagile does not accept.
type fields struct {
	importer   *importer
	properties Properties
	where      string // the element, for the notes
}

func (what *importer) fieldsOf(properties Properties, where string) fields {
	return fields{importer: what, properties: properties, where: where}
}

// enum returns the property key when parse accepts it, or else the fallback.
func (what fields) enum(key string, fallback string, parse func(string) error) string {
	value := strings.TrimSpace(what.properties[key])
	if value == "" {
		return fallback
	}

	if err := parse(value); err != nil {
		what.importer.note("%s: %s %q is unknown to threagile, imported as %s", what.where, key, value, fallback)
		return fallback
	}

	return value
}

func (what *importer) note(format string, a ...any) {
	what.notes = append(what.notes, fmt.Sprintf(format, a...))
}

// newIDs gives each element an id that threagile accepts, unique among the elements.
func newIDs[T any](what *importer, kind string, elements []T, elementID func(T) string) map[string]string {
	ids := make(map[string]string, len(elements))
	taken := make(map[string]bool, len(elements))
	for _, element := range elements {
		id := elementID(element)
		base := strings.Trim(invalidIDCharacters.ReplaceAllString(id, "-"), "-")
		if base == "" {
			base = Slug(kind)
		}

		newID := base
		for suffix := 2; taken[newID]; suffix++ {
			newID = fmt.Sprintf("%s-%d", base, suffix)
		}

		if newID != id {
			what.note("%s %q: threagile ids take letters, digits and hyphens only, imported as %q", kind, id, newID)
		}
		ids[id] = newID
		taken[newID] = true
	}

	return ids
}

// uniqueName returns the name, or the id when the name is empty, with the id appended when the
// key of the name is taken already, and takes the key.
func uniqueName(taken map[string]bool, key func(string) string, name string, id string) string {
	base := strings.TrimSpace(name)
	if base == "" {
		base = id
	}

	candidate := base
	for attempt := 1; taken[key(candidate)]; attempt++ {
		candidate = fmt.Sprintf("%s (%s)", base, id)
		if attempt > 1 {
			candidate = fmt.Sprintf("%s (%s %d)", base, id, attempt)
		}
	}

	taken[key(candidate)] = true
	return candidate
}

func identity(name string) string {
	return name
}

// parses turns a threagile Parse function into a check of a value.
func parses[T any](parse func(string) (T, error)) func(string) error {
	return func(value string) error {
		_, err := parse(value)
		return err
	}
}
