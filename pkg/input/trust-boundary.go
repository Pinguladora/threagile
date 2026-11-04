package input

import "fmt"

type TrustBoundary struct {
	ID                    string   `json:"id,omitempty"                      yaml:"id,omitempty"`
	Description           string   `json:"description,omitempty"             yaml:"description,omitempty"`
	Type                  string   `json:"type,omitempty"                    yaml:"type,omitempty"`
	Tags                  []string `json:"tags,omitempty"                    yaml:"tags,omitempty"`
	TechnicalAssetsInside []string `json:"technical_assets_inside,omitempty" yaml:"technical_assets_inside,omitempty"`
	TrustBoundariesNested []string `json:"trust_boundaries_nested,omitempty" yaml:"trust_boundaries_nested,omitempty"`
}

func (what *TrustBoundary) Merge(other TrustBoundary) error {
	var mergeError error
	what.ID, mergeError = new(Strings).MergeSingleton(what.ID, other.ID)
	if mergeError != nil {
		return fmt.Errorf("failed to merge id: %w", mergeError)
	}

	what.Description, mergeError = new(Strings).MergeSingleton(what.Description, other.Description)
	if mergeError != nil {
		return fmt.Errorf("failed to merge description: %w", mergeError)
	}

	what.Type, mergeError = new(Strings).MergeSingleton(what.Type, other.Type)
	if mergeError != nil {
		return fmt.Errorf("failed to merge type: %w", mergeError)
	}

	what.Tags = new(Strings).MergeUniqueSlice(what.Tags, other.Tags)

	what.TechnicalAssetsInside = new(Strings).MergeUniqueSlice(what.TechnicalAssetsInside, other.TechnicalAssetsInside)

	what.TrustBoundariesNested = new(Strings).MergeUniqueSlice(what.TrustBoundariesNested, other.TrustBoundariesNested)

	return nil
}

func (what *TrustBoundary) MergeMap(
	first map[string]TrustBoundary, second map[string]TrustBoundary,
) (map[string]TrustBoundary, error) {
	if first == nil {
		// first is nil for a section that is missing, or a key left without a value, in the model merged into
		first = make(map[string]TrustBoundary, len(second))
	}

	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			mergeError := mapItem.Merge(mapValue)
			if mergeError != nil {
				return first, fmt.Errorf("failed to merge trust boundary %q: %w", mapKey, mergeError)
			}

			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}

	return first, nil
}
