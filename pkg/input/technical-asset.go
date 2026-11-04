package input

import "fmt"

type TechnicalAsset struct {
	ID                      string                       `json:"id,omitempty"                         yaml:"id,omitempty"`
	Description             string                       `json:"description,omitempty"                yaml:"description,omitempty"`
	Type                    string                       `json:"type,omitempty"                       yaml:"type,omitempty"`
	Usage                   string                       `json:"usage,omitempty"                      yaml:"usage,omitempty"`
	UsedAsClientByHuman     bool                         `json:"used_as_client_by_human,omitempty"    yaml:"used_as_client_by_human,omitempty"`
	OutOfScope              bool                         `json:"out_of_scope,omitempty"               yaml:"out_of_scope,omitempty"`
	JustificationOutOfScope string                       `json:"justification_out_of_scope,omitempty" yaml:"justification_out_of_scope,omitempty"`
	Size                    string                       `json:"size,omitempty"                       yaml:"size,omitempty"`
	Technology              string                       `json:"technology,omitempty"                 yaml:"technology,omitempty"`
	Technologies            []string                     `json:"technologies,omitempty"               yaml:"technologies,omitempty"`
	Tags                    []string                     `json:"tags,omitempty"                       yaml:"tags,omitempty"`
	Internet                bool                         `json:"internet,omitempty"                   yaml:"internet,omitempty"`
	Machine                 string                       `json:"machine,omitempty"                    yaml:"machine,omitempty"`
	Encryption              string                       `json:"encryption,omitempty"                 yaml:"encryption,omitempty"`
	Owner                   string                       `json:"owner,omitempty"                      yaml:"owner,omitempty"`
	Confidentiality         string                       `json:"confidentiality,omitempty"            yaml:"confidentiality,omitempty"`
	Integrity               string                       `json:"integrity,omitempty"                  yaml:"integrity,omitempty"`
	Availability            string                       `json:"availability,omitempty"               yaml:"availability,omitempty"`
	JustificationCiaRating  string                       `json:"justification_cia_rating,omitempty"   yaml:"justification_cia_rating,omitempty"`
	MultiTenant             bool                         `json:"multi_tenant,omitempty"               yaml:"multi_tenant,omitempty"`
	Redundant               bool                         `json:"redundant,omitempty"                  yaml:"redundant,omitempty"`
	CustomDevelopedParts    bool                         `json:"custom_developed_parts,omitempty"     yaml:"custom_developed_parts,omitempty"`
	DataAssetsProcessed     []string                     `json:"data_assets_processed,omitempty"      yaml:"data_assets_processed,omitempty"`
	DataAssetsStored        []string                     `json:"data_assets_stored,omitempty"         yaml:"data_assets_stored,omitempty"`
	DataFormatsAccepted     []string                     `json:"data_formats_accepted,omitempty"      yaml:"data_formats_accepted,omitempty"`
	DiagramTweakOrder       int                          `json:"diagram_tweak_order,omitempty"        yaml:"diagram_tweak_order,omitempty"`
	CommunicationLinks      map[string]CommunicationLink `json:"communication_links,omitempty"        yaml:"communication_links,omitempty"`
}

func (what *TechnicalAsset) Merge(other TechnicalAsset) error {
	mergeError := mergeSingletons(
		singleton("id", &what.ID, other.ID),
		singleton("description", &what.Description, other.Description),
		singleton("type", &what.Type, other.Type),
		singleton("usage", &what.Usage, other.Usage),
	)
	if mergeError != nil {
		return mergeError
	}

	mergeFlag(&what.UsedAsClientByHuman, other.UsedAsClientByHuman)
	mergeFlag(&what.OutOfScope, other.OutOfScope)

	what.JustificationOutOfScope = new(Strings).MergeMultiline(what.JustificationOutOfScope, other.JustificationOutOfScope)

	mergeError = mergeSingletons(
		singleton("size", &what.Size, other.Size),
		singleton("technology", &what.Technology, other.Technology),
	)
	if mergeError != nil {
		return mergeError
	}

	what.mergeLists(other)

	mergeFlag(&what.Internet, other.Internet)

	mergeError = mergeSingletons(
		singleton("machine", &what.Machine, other.Machine),
		singleton("encryption", &what.Encryption, other.Encryption),
		singleton("owner", &what.Owner, other.Owner),
		singleton("confidentiality", &what.Confidentiality, other.Confidentiality),
		singleton("integrity", &what.Integrity, other.Integrity),
		singleton("availability", &what.Availability, other.Availability),
	)
	if mergeError != nil {
		return mergeError
	}

	what.JustificationCiaRating = new(Strings).MergeMultiline(what.JustificationCiaRating, other.JustificationCiaRating)

	mergeFlag(&what.MultiTenant, other.MultiTenant)
	mergeFlag(&what.Redundant, other.Redundant)
	mergeFlag(&what.CustomDevelopedParts, other.CustomDevelopedParts)

	if what.DiagramTweakOrder == 0 {
		what.DiagramTweakOrder = other.DiagramTweakOrder
	}

	what.CommunicationLinks, mergeError = new(CommunicationLink).MergeMap(what.CommunicationLinks,
		other.CommunicationLinks)
	if mergeError != nil {
		return fmt.Errorf("failed to merge communication_links: %w", mergeError)
	}

	return nil
}

// mergeLists adds the technologies, tags, data assets and data formats of another technical asset that it
// doesn't have yet.
func (what *TechnicalAsset) mergeLists(other TechnicalAsset) {
	what.Technologies = new(Strings).MergeUniqueSlice(what.Technologies, other.Technologies)
	what.Tags = new(Strings).MergeUniqueSlice(what.Tags, other.Tags)
	what.DataAssetsProcessed = new(Strings).MergeUniqueSlice(what.DataAssetsProcessed, other.DataAssetsProcessed)
	what.DataAssetsStored = new(Strings).MergeUniqueSlice(what.DataAssetsStored, other.DataAssetsStored)
	what.DataFormatsAccepted = new(Strings).MergeUniqueSlice(what.DataFormatsAccepted, other.DataFormatsAccepted)
}

func (what *TechnicalAsset) MergeMap(
	first map[string]TechnicalAsset, second map[string]TechnicalAsset,
) (map[string]TechnicalAsset, error) {
	if first == nil {
		// first is nil for a section that is missing, or a key left without a value, in the model merged into
		first = make(map[string]TechnicalAsset, len(second))
	}

	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			mergeError := mapItem.Merge(mapValue)
			if mergeError != nil {
				return first, fmt.Errorf("failed to merge technical asset %q: %w", mapKey, mergeError)
			}

			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}

	return first, nil
}
