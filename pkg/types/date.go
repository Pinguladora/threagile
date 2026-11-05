package types

import (
	"os"
	"strconv"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	jsonDateFormat = `"2006-01-02"`
	yamlDateFormat = `2006-01-02`

	// sourceDateEpochEnv is the reproducible-builds variable holding a Unix
	// timestamp, see https://reproducible-builds.org/specs/source-date-epoch/.
	sourceDateEpochEnv = "SOURCE_DATE_EPOCH"
)

// Now returns the time that reports are stamped with. When SOURCE_DATE_EPOCH
// holds a Unix timestamp it is used (in UTC), so the same model always gives the
// same reports; otherwise, or if the value does not parse, it is the current time.
func Now() time.Time {
	if epoch, ok := os.LookupEnv(sourceDateEpochEnv); ok {
		if seconds, err := strconv.ParseInt(epoch, 10, 64); err == nil {
			return time.Unix(seconds, 0).UTC()
		}
	}

	return time.Now()
}

type Date struct {
	time.Time
}

func (what Date) MarshalJSON() ([]byte, error) {
	return []byte(what.Format(jsonDateFormat)), nil
}

func (what *Date) UnmarshalJSON(bytes []byte) error {
	date, parseError := time.Parse(jsonDateFormat, string(bytes))
	if parseError != nil {
		return parseError
	}

	what.Time = date

	return nil
}

func (what Date) MarshalYAML() (any, error) {
	return what.Format(yamlDateFormat), nil
}

func (what *Date) UnmarshalYAML(node *yaml.Node) error {
	date, parseError := time.Parse(yamlDateFormat, node.Value)
	if parseError != nil {
		return parseError
	}

	what.Time = date

	return nil
}
