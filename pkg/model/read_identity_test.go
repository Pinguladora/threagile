package model_test

import (
	"fmt"
	"testing"

	"github.com/Pinguladora/threagile/internal/threagile"
	"github.com/Pinguladora/threagile/pkg/model"
	"github.com/Pinguladora/threagile/pkg/risks"
	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// warningReporter collects the warnings it is given.
type warningReporter struct {
	warnings []string
}

func (*warningReporter) Info(...any)          {}
func (*warningReporter) Infof(string, ...any) {}
func (r *warningReporter) Warn(a ...any)      { r.warnings = append(r.warnings, fmt.Sprint(a...)) }
func (r *warningReporter) Warnf(f string, a ...any) {
	r.warnings = append(r.warnings, fmt.Sprintf(f, a...))
}
func (*warningReporter) Error(...any)          {}
func (*warningReporter) Errorf(string, ...any) {}

// TestAnalyzeModelReadsLegacyIdentityWithWarning analyzes a model of an earlier version, whose links hold their
// identity in their authorization and use the earlier name of multi-factor authentication.
func TestAnalyzeModelReadsLegacyIdentityWithWarning(t *testing.T) {
	config := new(threagile.Config).Defaults("")
	config.SetAppFolder(t.TempDir())
	config.SetPluginFolder(t.TempDir())
	config.SetInputFile("testdata/legacy-identity.yaml")
	config.SetOutputFolder(t.TempDir())
	config.SetTempFolder(t.TempDir())
	reporter := new(warningReporter)

	result, err := model.ReadAndAnalyzeModel(config, risks.GetBuiltInRiskRules(), reporter)
	require.NoError(t, err)

	links := result.ParsedModel.CommunicationLinks
	assert.Equal(t, types.ServiceAccount, links["shop>order-queries"].Identity)
	assert.Equal(t, types.EndUser, links["shop>order-events"].Identity)
	assert.Equal(t, types.MultiFactor, links["shop>order-events"].Authentication)
	for _, link := range links {
		assert.Equal(t, types.UnknownAuthorization, link.Authorization, link.Id)
	}
	assert.Contains(t, reporter.warnings, "the authorization of 2 communication links holds their identity (none, "+
		"technical-user or end-user-identity-propagation), as earlier versions of the model did: read it as their "+
		"identity, and their authorization as not modelled; set identity and authorization to remove this warning")
}
