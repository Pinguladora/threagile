package input

import "fmt"

type SharedRuntime struct {
	ID                     string   `json:"id,omitempty"                       yaml:"id,omitempty"`
	Description            string   `json:"description,omitempty"              yaml:"description,omitempty"`
	Tags                   []string `json:"tag,omitempty"                      yaml:"tags,omitempty"`
	TechnicalAssetsRunning []string `json:"technical_assets_running,omitempty" yaml:"technical_assets_running,omitempty"`
}

func (what *SharedRuntime) Merge(other SharedRuntime) error {
	var mergeError error
	what.ID, mergeError = new(Strings).MergeSingleton(what.ID, other.ID)
	if mergeError != nil {
		return fmt.Errorf("failed to merge id: %w", mergeError)
	}

	what.Description, mergeError = new(Strings).MergeSingleton(what.Description, other.Description)
	if mergeError != nil {
		return fmt.Errorf("failed to merge description: %w", mergeError)
	}

	what.Tags = new(Strings).MergeUniqueSlice(what.Tags, other.Tags)

	what.TechnicalAssetsRunning = new(Strings).MergeUniqueSlice(what.TechnicalAssetsRunning, other.TechnicalAssetsRunning)

	return nil
}

func (what *SharedRuntime) MergeMap(first map[string]SharedRuntime, second map[string]SharedRuntime) (map[string]SharedRuntime, error) {
	if first == nil {
		// first is nil for a section that is missing, or a key left without a value, in the model merged into
		first = make(map[string]SharedRuntime, len(second))
	}

	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			mergeError := mapItem.Merge(mapValue)
			if mergeError != nil {
				return first, fmt.Errorf("failed to merge shared runtime %q: %w", mapKey, mergeError)
			}

			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}

	return first, nil
}
