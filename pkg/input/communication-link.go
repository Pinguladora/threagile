package input

import (
	"fmt"
	"slices"
)

type CommunicationLink struct {
	Target                 string   `json:"target,omitempty"                   yaml:"target,omitempty"`
	Via                    []string `json:"via,omitempty"                      yaml:"via,omitempty"`
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
	mergeError := mergeSingletons(singleton("target", &what.Target, other.Target))
	if mergeError != nil {
		return mergeError
	}

	// the via list is a path in order, so it merges like a single value
	if len(what.Via) == 0 {
		what.Via = other.Via
	} else if len(other.Via) > 0 && !slices.Equal(what.Via, other.Via) {
		return fmt.Errorf("failed to merge via: conflicting values: %q versus %q", what.Via, other.Via)
	}

	mergeError = mergeSingletons(
		singleton("description", &what.Description, other.Description),
		singleton("protocol", &what.Protocol, other.Protocol),
		singleton("authentication", &what.Authentication, other.Authentication),
		singleton("authorization", &what.Authorization, other.Authorization),
	)
	if mergeError != nil {
		return mergeError
	}

	what.Tags = new(Strings).MergeUniqueSlice(what.Tags, other.Tags)

	mergeFlag(&what.VPN, other.VPN)
	mergeFlag(&what.IpFiltered, other.IpFiltered)
	mergeFlag(&what.Readonly, other.Readonly)

	mergeError = mergeSingletons(singleton("usage", &what.Usage, other.Usage))
	if mergeError != nil {
		return mergeError
	}

	what.DataAssetsSent = new(Strings).MergeUniqueSlice(what.DataAssetsSent, other.DataAssetsSent)

	what.DataAssetsReceived = new(Strings).MergeUniqueSlice(what.DataAssetsReceived, other.DataAssetsReceived)

	if what.DiagramTweakWeight == 0 {
		what.DiagramTweakWeight = other.DiagramTweakWeight
	}

	mergeFlag(&what.DiagramTweakConstraint, other.DiagramTweakConstraint)

	return nil
}

func (what *CommunicationLink) MergeMap(
	first map[string]CommunicationLink, second map[string]CommunicationLink,
) (map[string]CommunicationLink, error) {
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
