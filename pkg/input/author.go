package input

import (
	"fmt"
	"sort"
	"strings"
)

type Author struct {
	Name     string `json:"name,omitempty"     yaml:"name,omitempty"`
	Contact  string `json:"contact,omitempty"  yaml:"contact,omitempty"`
	Homepage string `json:"homepage,omitempty" yaml:"homepage,omitempty"`
}

// Merge merges another entry of the same author: a field that only one of them has is kept, and a field
// they both have must match.
func (what *Author) Merge(other Author) error {
	for _, field := range []struct {
		name         string
		value, other *string
	}{
		{"name", &what.Name, &other.Name},
		{"contact", &what.Contact, &other.Contact},
		{"homepage", &what.Homepage, &other.Homepage},
	} {
		switch {
		case len(*field.other) == 0:
		case len(*field.value) == 0:
			*field.value = *field.other
		case !strings.EqualFold(*field.value, *field.other):
			return fmt.Errorf("author %v mismatch", field.name)
		}
	}

	return nil
}

func (what *Author) MergeList(list []Author) ([]Author, error) {
	sort.Slice(list, func(i int, j int) bool {
		return strings.Compare(list[i].Name, list[j].Name) < 0
	})

	if len(list) <= 1 {
		return list, nil
	}

	first := list[0]
	tail, mergeError := what.MergeList(list[1:])
	if mergeError != nil {
		return nil, mergeError
	}

	others := make([]Author, 0, len(tail))
	for _, second := range tail {
		if first.Match(second) {
			mergeError = first.Merge(second)
			if mergeError != nil {
				return nil, mergeError
			}
		} else {
			others = append(others, second)
		}
	}

	// first is added only now, with what the other entries of the same author added to it
	return append([]Author{first}, others...), nil
}

func (what *Author) Match(other Author) bool {
	return strings.EqualFold(what.Name, other.Name)
}
