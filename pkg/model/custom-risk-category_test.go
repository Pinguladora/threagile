package model

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errorReporter collects the errors it is given.
type errorReporter struct {
	errors []string
}

func (*errorReporter) Info(...any)                 {}
func (*errorReporter) Warn(...any)                 {}
func (*errorReporter) Infof(string, ...any)        {}
func (*errorReporter) Warnf(string, ...any)        {}
func (r *errorReporter) Error(a ...any)            { r.errors = append(r.errors, fmt.Sprint(a...)) }
func (r *errorReporter) Errorf(f string, a ...any) { r.errors = append(r.errors, fmt.Sprintf(f, a...)) }

func TestLoadCustomRiskRulesSkipsRulesThatFailToLoad(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "a-folder"), 0o700))
	reporter := new(errorReporter)

	rules := LoadCustomRiskRules(dir, []string{"missing-plugin", "a-folder"}, reporter)

	assert.Empty(t, rules)
	assert.Len(t, reporter.errors, 2)
}
