package interchange

import (
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/Pinguladora/threagile/pkg/types"
)

// defaultProjectName names a model without a title.
const defaultProjectName = "Threagile Model"

// dateFormat is the format of the date of a model.
const dateFormat = "2006-01-02"

var nonIDCharacters = regexp.MustCompile(`[^a-z0-9]+`)

// FromModel turns an analyzed model into elements: its trust boundaries into zones, its technical
// assets into components, its communication links into flows, its data assets into data assets,
// and the risk categories it found risks of into threats. Each risk becomes a threat instance at
// its most relevant communication link or else its most relevant technical asset; a risk that has
// neither (a risk of a trust boundary or a shared runtime) goes to each technical asset it names
// as a possible data breach. Shared runtimes, risk tracking details and the model's texts, such as
// questions and abuse cases, are left out.
func FromModel(model *types.Model) *Model {
	result := &Model{
		Project:    newProject(model),
		Zones:      newZones(model),
		Components: newComponents(model),
		Flows:      newFlows(model),
		DataAssets: newDataAssets(model),
	}
	result.Threats = newThreats(model, result)

	return result
}

func newProject(model *types.Model) Project {
	name := strings.TrimSpace(model.Title)
	if name == "" {
		name = defaultProjectName
	}

	project := Project{
		ID:         Slug(name),
		Name:       name,
		Tags:       slices.Clone(model.TagsAvailable),
		Properties: Properties{},
	}
	if model.AppDescription != nil {
		project.Description = model.AppDescription.Description
	}
	if model.Author != nil {
		project.Owner = model.Author.Name
		project.OwnerContact = model.Author.Contact
	}

	project.Properties.set("business_criticality", model.BusinessCriticality.String())
	if !model.Date.IsZero() {
		project.Properties.set("date", model.Date.Format(dateFormat))
	}

	return project
}

func newZones(model *types.Model) []Zone {
	zones := make([]Zone, 0, len(model.TrustBoundaries))
	for _, id := range slices.Sorted(maps.Keys(model.TrustBoundaries)) {
		boundary := model.TrustBoundaries[id]
		zone := Zone{
			ID:          id,
			Name:        boundary.Title,
			Type:        boundary.Type.String(),
			Description: boundary.Description,
			Properties:  Properties{},
		}
		if parent := model.FindParentTrustBoundary(boundary); parent != nil {
			zone.ParentID = parent.Id
		}

		zone.Properties.setList(tagsProperty, boundary.Tags)
		zones = append(zones, zone)
	}

	return zones
}

func newComponents(model *types.Model) []Component {
	components := make([]Component, 0, len(model.TechnicalAssets))
	for _, id := range model.SortedTechnicalAssetIDs() {
		asset := model.TechnicalAssets[id]
		component := Component{
			ID:          id,
			Name:        asset.Title,
			Type:        types.UnknownTechnology,
			Description: asset.Description,
			Tags:        slices.Clone(asset.Tags),
			Processed:   sorted(asset.DataAssetsProcessed),
			Stored:      sorted(asset.DataAssetsStored),
			Properties:  technicalAssetProperties(asset),
		}
		if len(asset.Technologies) > 0 {
			component.Type = asset.Technologies[0].Name
		}
		if boundary, ok := model.DirectContainingTrustBoundaryMappedByTechnicalAssetId[id]; ok {
			component.ParentID = boundary.Id
		}

		components = append(components, component)
	}

	return components
}

func technicalAssetProperties(asset *types.TechnicalAsset) Properties {
	properties := Properties{}
	properties.set("type", asset.Type.String())
	properties.set("usage", asset.Usage.String())
	properties.set("size", asset.Size.String())
	properties.set("machine", asset.Machine.String())
	properties.set("encryption", asset.Encryption.String())
	properties.set("owner", asset.Owner)
	properties.set("confidentiality", asset.Confidentiality.String())
	properties.set("integrity", asset.Integrity.String())
	properties.set("availability", asset.Availability.String())
	properties.set("justification_cia_rating", asset.JustificationCiaRating)
	properties.set("justification_out_of_scope", asset.JustificationOutOfScope)
	properties.setFlag("internet", asset.Internet)
	properties.setFlag("multi_tenant", asset.MultiTenant)
	properties.setFlag("redundant", asset.Redundant)
	properties.setFlag("custom_developed_parts", asset.CustomDevelopedParts)
	properties.setFlag("out_of_scope", asset.OutOfScope)
	properties.setFlag("used_as_client_by_human", asset.UsedAsClientByHuman)

	// the component type names the first technology; more of them need a property
	if len(asset.Technologies) > 1 {
		technologies := make([]string, 0, len(asset.Technologies))
		for _, technology := range asset.Technologies {
			technologies = append(technologies, technology.Name)
		}
		properties.setList("technologies", technologies)
	}

	formats := make([]string, 0, len(asset.DataFormatsAccepted))
	for _, format := range asset.DataFormatsAccepted {
		formats = append(formats, format.String())
	}
	properties.setList("data_formats_accepted", formats)

	return properties
}

func newFlows(model *types.Model) []Flow {
	flows := make([]Flow, 0, len(model.CommunicationLinks))
	for _, id := range slices.Sorted(maps.Keys(model.CommunicationLinks)) {
		link := model.CommunicationLinks[id]
		flow := Flow{
			ID:            id,
			Name:          link.Title,
			Description:   link.Description,
			SourceID:      link.SourceId,
			DestinationID: link.TargetId,
			Bidirectional: link.IsBidirectional(),
			DataAssets:    sorted(append(slices.Clone(link.DataAssetsSent), link.DataAssetsReceived...)),
			Tags:          slices.Clone(link.Tags),
			Properties:    Properties{},
		}

		flow.Properties.set("protocol", link.Protocol.String())
		flow.Properties.set("authentication", link.Authentication.String())
		flow.Properties.set("identity", link.Identity.String())
		if link.Authorization != types.UnknownAuthorization {
			flow.Properties.set("authorization", link.Authorization.String())
		}
		flow.Properties.set("usage", link.Usage.String())
		flow.Properties.setFlag("vpn", link.VPN)
		flow.Properties.setFlag("ip_filtered", link.IpFiltered)
		flow.Properties.setFlag("readonly", link.Readonly)
		// the data assets of the flow do not tell which way each of them goes
		flow.Properties.setList("data_assets_sent", link.DataAssetsSent)
		flow.Properties.setList("data_assets_received", link.DataAssetsReceived)

		flows = append(flows, flow)
	}

	return flows
}

func newDataAssets(model *types.Model) []DataAsset {
	dataAssets := make([]DataAsset, 0, len(model.DataAssets))
	for _, id := range slices.Sorted(maps.Keys(model.DataAssets)) {
		asset := model.DataAssets[id]
		dataAsset := DataAsset{
			ID:              id,
			Name:            asset.Title,
			Description:     asset.Description,
			Confidentiality: asset.Confidentiality,
			Integrity:       asset.Integrity,
			Availability:    asset.Availability,
			Justification:   asset.JustificationCiaRating,
			Properties:      Properties{},
		}

		dataAsset.Properties.set("usage", asset.Usage.String())
		dataAsset.Properties.set("quantity", asset.Quantity.String())
		dataAsset.Properties.set("origin", asset.Origin)
		dataAsset.Properties.set("owner", asset.Owner)
		dataAsset.Properties.setList(tagsProperty, asset.Tags)

		dataAssets = append(dataAssets, dataAsset)
	}

	return dataAssets
}

func newThreats(model *types.Model, result *Model) []Threat {
	components := make(map[string]*Component, len(result.Components))
	for index := range result.Components {
		components[result.Components[index].ID] = &result.Components[index]
	}

	flows := make(map[string]*Flow, len(result.Flows))
	for index := range result.Flows {
		flows[result.Flows[index].ID] = &result.Flows[index]
	}

	threats := make([]Threat, 0, len(model.GeneratedRisksByCategory))
	for _, categoryID := range slices.Sorted(maps.Keys(model.GeneratedRisksByCategory)) {
		risks := slices.SortedFunc(slices.Values(model.GeneratedRisksByCategory[categoryID]), func(a, b *types.Risk) int {
			return strings.Compare(a.SyntheticId, b.SyntheticId)
		})
		if len(risks) == 0 {
			continue
		}

		category := model.GetRiskCategory(categoryID)
		if category == nil {
			category = &types.RiskCategory{ID: categoryID, Title: categoryID}
		}
		threats = append(threats, newThreat(category, risks))

		for _, risk := range risks {
			addThreatInstance(ThreatInstance{ThreatID: category.ID, Status: model.GetRiskTrackingWithDefault(risk).Status},
				risk, components, flows)
		}
	}

	return threats
}

// addThreatInstance adds the instance of a risk to the flow of its most relevant communication
// link, or else to the component of its most relevant technical asset, or else to the components
// of the technical assets it names as a possible data breach.
func addThreatInstance(instance ThreatInstance, risk *types.Risk,
	components map[string]*Component, flows map[string]*Flow,
) {
	if flow, ok := flows[risk.MostRelevantCommunicationLinkId]; ok {
		flow.Threats = append(flow.Threats, instance)
		return
	}

	if component, ok := components[risk.MostRelevantTechnicalAssetId]; ok {
		component.Threats = append(component.Threats, instance)
		return
	}

	for _, id := range sorted(risk.DataBreachTechnicalAssetIDs) {
		if component, ok := components[id]; ok {
			component.Threats = append(component.Threats, instance)
		}
	}
}

func newThreat(category *types.RiskCategory, risks []*types.Risk) Threat {
	threat := Threat{
		ID:          category.ID,
		Name:        category.Title,
		Description: category.Description,
		STRIDE:      category.STRIDE,
		CWE:         category.CWE,
		References:  category.References,
		ImpactText:  category.Impact,
		Mitigation: Mitigation{
			Name:        category.Action,
			Description: category.Mitigation,
			Check:       category.Check,
		},
		Properties: Properties{},
	}

	for _, risk := range risks {
		threat.Likelihood = max(threat.Likelihood, risk.ExploitationLikelihood)
		threat.Impact = max(threat.Impact, risk.ExploitationImpact)
	}

	threat.Properties.set("function", category.Function.String())
	threat.Properties.set("asvs", category.ASVS)
	threat.Properties.set("cheat_sheet", category.CheatSheet)

	return threat
}

// Slug turns text into an id of lower-case letters, digits and hyphens, as threagile ids are.
func Slug(text string) string {
	return strings.Trim(nonIDCharacters.ReplaceAllString(strings.ToLower(text), "-"), "-")
}
