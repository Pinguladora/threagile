package input

import "fmt"

type CommunicationLink struct {
	Target                 string   `json:"target,omitempty"                   yaml:"target,omitempty"`
	Description            string   `json:"description,omitempty"              yaml:"description,omitempty"`
	Protocol               string   `json:"protocol,omitempty"                 yaml:"protocol,omitempty"`
	Authentication         string   `json:"authentication,omitempty"           yaml:"authentication,omitempty"`
	Authorization          string   `json:"authorization,omitempty"            yaml:"authorization,omitempty"`
	Tags                   []string `json:"tags,omitempty"                     yaml:"tags,omitempty"`
	VPN                    bool     `json:"vpn,omitempty"                      yaml:"vpn,omitempty"`
	IpFiltered             bool     `json:"ip_filtered,omitempty"              yaml:"ip_filtered,omitempty"`
	Readonly               bool     `json:"readonly,omitempty"                 yaml:"readonly,omitempty"`
	Usage                  string   `json:"usage,omitempty"                    yaml:"usage,omitempty"`
	DataAssetsSent         []string `json:"data_assets_sent,omitempty"         yaml:"data_assets_sent,omitempty"`
	DataAssetsReceived     []string `json:"data_assets_received,omitempty"     yaml:"data_assets_received,omitempty"`
	DiagramTweakWeight     int      `json:"diagram_tweak_weight,omitempty"     yaml:"diagram_tweak_weight,omitempty"`
	DiagramTweakConstraint bool     `json:"diagram_tweak_constraint,omitempty" yaml:"diagram_tweak_constraint,omitempty"`
}

func (what *CommunicationLink) Merge(other CommunicationLink) error {
	var mergeError error
	what.Target, mergeError = new(Strings).MergeSingleton(what.Target, other.Target)
	if mergeError != nil {
		return fmt.Errorf("failed to merge target: %w", mergeError)
	}

	what.Description, mergeError = new(Strings).MergeSingleton(what.Description, other.Description)
	if mergeError != nil {
		return fmt.Errorf("failed to merge description: %w", mergeError)
	}

	what.Protocol, mergeError = new(Strings).MergeSingleton(what.Protocol, other.Protocol)
	if mergeError != nil {
		return fmt.Errorf("failed to merge protocol: %w", mergeError)
	}

	what.Authentication, mergeError = new(Strings).MergeSingleton(what.Authentication, other.Authentication)
	if mergeError != nil {
		return fmt.Errorf("failed to merge authentication: %w", mergeError)
	}

	what.Authorization, mergeError = new(Strings).MergeSingleton(what.Authorization, other.Authorization)
	if mergeError != nil {
		return fmt.Errorf("failed to merge authorization: %w", mergeError)
	}

	what.Tags = new(Strings).MergeUniqueSlice(what.Tags, other.Tags)

	if !what.VPN {
		what.VPN = other.VPN
	}

	if !what.IpFiltered {
		what.IpFiltered = other.IpFiltered
	}

	if !what.Readonly {
		what.Readonly = other.Readonly
	}

	what.Usage, mergeError = new(Strings).MergeSingleton(what.Usage, other.Usage)
	if mergeError != nil {
		return fmt.Errorf("failed to merge usage: %w", mergeError)
	}

	what.DataAssetsSent = new(Strings).MergeUniqueSlice(what.DataAssetsSent, other.DataAssetsSent)

	what.DataAssetsReceived = new(Strings).MergeUniqueSlice(what.DataAssetsReceived, other.DataAssetsReceived)

	if what.DiagramTweakWeight == 0 {
		what.DiagramTweakWeight = other.DiagramTweakWeight
	}

	if !what.DiagramTweakConstraint {
		what.DiagramTweakConstraint = other.DiagramTweakConstraint
	}

	return nil
}

func (what *CommunicationLink) MergeMap(first map[string]CommunicationLink, second map[string]CommunicationLink) (map[string]CommunicationLink, error) {
	if first == nil {
		// first is nil for a section that is missing, or a key left without a value, in the model merged into
		first = make(map[string]CommunicationLink, len(second))
	}

	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			mergeError := mapItem.Merge(mapValue)
			if mergeError != nil {
				return first, fmt.Errorf("failed to merge commuinication link %q: %w", mapKey, mergeError)
			}

			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}

	return first, nil
}
