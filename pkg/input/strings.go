package input

import (
	"fmt"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	lineSeparator = "\n<br><br>\n"
)

type Strings struct{}

func (what *Strings) MergeSingleton(first string, second string) (string, error) {
	if len(first) > 0 {
		if len(second) > 0 {
			if !strings.EqualFold(first, second) {
				return first, fmt.Errorf("conflicting string values: %q versus %q", first, second)
			}
		}

		return first, nil
	}

	return second, nil
}

func (what *Strings) MergeMultiline(first string, second string) string {
	text := first
	if len(first) > 0 {
		if len(second) > 0 && !strings.EqualFold(first, second) {
			text = text + lineSeparator + second
		}
	} else {
		text = second
	}

	return text
}

func (what *Strings) MergeMap(first map[string]string, second map[string]string) (map[string]string, error) {
	if first == nil {
		// first is nil for a section that is missing, or a key left without a value, in the model merged into
		first = make(map[string]string, len(second))
	}

	for mapKey, mapValue := range second {
		_, ok := first[mapKey]
		if ok {
			return nil, fmt.Errorf("duplicate item %q", mapKey)
		}

		first[mapKey] = mapValue
	}

	return first, nil
}

func (what *Strings) MergeUniqueSlice(first []string, second []string) []string {
	for _, item := range second {
		if !slices.Contains(first, item) {
			first = append(first, item)
		}
	}

	return first
}

func (what *Strings) AddLineNumbers(script any) string {
	text, isString := script.(string)
	if !isString {
		data, _ := yaml.Marshal(script)
		text = string(data)
	}

	lines := strings.Split(text, "\n")
	for n, line := range lines {
		lines[n] = fmt.Sprintf("%3d:\t%v", n+1, line)
	}

	return strings.Join(lines, "\n")
}

func (what *Strings) IndentPrintf(level int, script any) string {
	text, isString := script.(string)
	if !isString {
		data, _ := yaml.Marshal(script)
		text = string(data)
	}

	lines := strings.Split(text, "\n")
	for n, line := range lines {
		lines[n] = strings.Repeat("    ", level) + line
	}

	return strings.Join(lines, "\n")
}

func (what *Strings) IndentLine(level int, format string, params ...any) string {
	return strings.Repeat("    ", level) + fmt.Sprintf(format, params...)
}

// singletonField is a string field that merges like a single value (see Strings.MergeSingleton),
// with the name its merge errors give it.
type singletonField struct {
	name  string
	value *string
	other string
}

// singleton describes a field for mergeSingletons.
func singleton(name string, value *string, other string) singletonField {
	return singletonField{name: name, value: value, other: other}
}

// mergeSingletons merges each field in turn and stops at the first conflict.
func mergeSingletons(fields ...singletonField) error {
	for _, field := range fields {
		var mergeError error
		*field.value, mergeError = new(Strings).MergeSingleton(*field.value, field.other)
		if mergeError != nil {
			return fmt.Errorf("failed to merge %s: %w", field.name, mergeError)
		}
	}

	return nil
}

// mergeFlag sets a flag that is not set yet to the other value.
func mergeFlag(value *bool, other bool) {
	if !*value {
		*value = other
	}
}
