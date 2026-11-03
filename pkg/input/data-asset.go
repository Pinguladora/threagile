package input

import "fmt"

type DataAsset struct {
	ID                     string   `json:"id,omitempty"                       yaml:"id,omitempty"`
	Description            string   `json:"description,omitempty"              yaml:"description,omitempty"`
	Usage                  string   `json:"usage,omitempty"                    yaml:"usage,omitempty"`
	Tags                   []string `json:"tags,omitempty"                     yaml:"tags,omitempty"`
	Origin                 string   `json:"origin,omitempty"                   yaml:"origin,omitempty"`
	Owner                  string   `json:"owner,omitempty"                    yaml:"owner,omitempty"`
	Quantity               string   `json:"quantity,omitempty"                 yaml:"quantity,omitempty"`
	Confidentiality        string   `json:"confidentiality,omitempty"          yaml:"confidentiality,omitempty"`
	Integrity              string   `json:"integrity,omitempty"                yaml:"integrity,omitempty"`
	Availability           string   `json:"availability,omitempty"             yaml:"availability,omitempty"`
	JustificationCiaRating string   `json:"justification_cia_rating,omitempty" yaml:"justification_cia_rating,omitempty"`
}

func (what *DataAsset) Merge(other DataAsset) error {
	var mergeError error
	what.ID, mergeError = new(Strings).MergeSingleton(what.ID, other.ID)
	if mergeError != nil {
		return fmt.Errorf("failed to merge id: %w", mergeError)
	}

	what.Description, mergeError = new(Strings).MergeSingleton(what.Description, other.Description)
	if mergeError != nil {
		return fmt.Errorf("failed to merge description: %w", mergeError)
	}

	what.Usage, mergeError = new(Strings).MergeSingleton(what.Usage, other.Usage)
	if mergeError != nil {
		return fmt.Errorf("failed to merge usage: %w", mergeError)
	}

	what.Tags = new(Strings).MergeUniqueSlice(what.Tags, other.Tags)

	what.Origin, mergeError = new(Strings).MergeSingleton(what.Origin, other.Origin)
	if mergeError != nil {
		return fmt.Errorf("failed to merge origin: %w", mergeError)
	}

	what.Owner, mergeError = new(Strings).MergeSingleton(what.Owner, other.Owner)
	if mergeError != nil {
		return fmt.Errorf("failed to merge owner: %w", mergeError)
	}

	what.Quantity, mergeError = new(Strings).MergeSingleton(what.Quantity, other.Quantity)
	if mergeError != nil {
		return fmt.Errorf("failed to merge quantity: %w", mergeError)
	}

	what.Confidentiality, mergeError = new(Strings).MergeSingleton(what.Confidentiality, other.Confidentiality)
	if mergeError != nil {
		return fmt.Errorf("failed to merge confidentiality: %w", mergeError)
	}

	what.Integrity, mergeError = new(Strings).MergeSingleton(what.Integrity, other.Integrity)
	if mergeError != nil {
		return fmt.Errorf("failed to merge integrity: %w", mergeError)
	}

	what.Availability, mergeError = new(Strings).MergeSingleton(what.Availability, other.Availability)
	if mergeError != nil {
		return fmt.Errorf("failed to merge availability: %w", mergeError)
	}

	what.JustificationCiaRating = new(Strings).MergeMultiline(what.JustificationCiaRating, other.JustificationCiaRating)

	return nil
}

func (what *DataAsset) MergeMap(first map[string]DataAsset, second map[string]DataAsset) (map[string]DataAsset, error) {
	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			mergeError := mapItem.Merge(mapValue)
			if mergeError != nil {
				return first, fmt.Errorf("failed to merge data asset %q: %w", mapKey, mergeError)
			}

			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}

	return first, nil
}
