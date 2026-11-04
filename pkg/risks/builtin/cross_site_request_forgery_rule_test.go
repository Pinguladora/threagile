package builtin

import (
	"testing"

	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestCrossSiteRequestForgeryRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewCrossSiteRequestForgeryRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestCrossSiteRequestForgeryRuleGenerateRisksOutOfScopeNotRisksCreated(t *testing.T) {
	rule := NewCrossSiteRequestForgeryRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				OutOfScope: true,
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestCrossSiteRequestForgeryRuleGenerateRisksTechAssetNotWebApplicationNotRisksCreated(t *testing.T) {
	rule := NewCrossSiteRequestForgeryRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Technologies: types.TechnologyList{
					{
						Name: "tool",
						Attributes: map[string]bool{
							types.IsWebApplication: false,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestCrossSiteRequestForgeryRuleGenerateRisksTechAssetWebApplicationWithoutIncomingCommunicationNotRisksCreated(t *testing.T) {
	rule := NewCrossSiteRequestForgeryRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"ta1": {
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.IsWebApplication: true,
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestCrossSiteRequestForgeryRuleGenerateRisksTechAssetWebApplicationIncomingRequestNotWebAccessProtocolNotRiskCreated(t *testing.T) {
	rule := NewCrossSiteRequestForgeryRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"web-app": {
				Id: "web-app",
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.IsWebApplication: true,
						},
					},
				},
			},
			"file-scrapper": {
				Technologies: types.TechnologyList{
					{
						Name: "tool",
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"web-app": {
				{
					Protocol: types.LocalFileAccess,
					SourceId: "file-scrapper",
					TargetId: "web-app",
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

func TestCrossSiteRequestForgeryRuleGenerateRisksTechAssetWebApplicationIncomingRequestWebAccessProtocolRiskCreated(t *testing.T) {
	rule := NewCrossSiteRequestForgeryRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"web-app": {
				Id:    "web-app",
				Title: "Web Application",
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.IsWebApplication: true,
						},
					},
				},
			},
			"user": {
				Title:               "user",
				UsedAsClientByHuman: true,
				Technologies: types.TechnologyList{
					{
						Name: "user",
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"web-app": {
				{
					Title:    "HTTP",
					Protocol: types.HTTP,
					SourceId: "user",
					TargetId: "web-app",
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, "<b>Cross-Site Request Forgery (CSRF)</b> risk at <b>Web Application</b> via <b>HTTP</b> from <b>user</b>", risks[0].Title)
	assert.Equal(t, types.VeryLikely, risks[0].ExploitationLikelihood)
	assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
}

func TestCrossSiteRequestForgeryRuleGenerateRisksTechAssetWebApplicationIncomingRequestWebAccessProtocolViaDevOpsRiskCreatedWithLikelyLikelihood(t *testing.T) {
	rule := NewCrossSiteRequestForgeryRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"web-app": {
				Id:    "web-app",
				Title: "Web Application",
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.IsWebApplication: true,
						},
					},
				},
			},
			"ci/cd": {
				Title:               "ci/cd",
				UsedAsClientByHuman: true, // the web interface of a pipeline that an administrator uses
				Technologies: types.TechnologyList{
					{
						Name: "ci/cd",
					},
				},
			},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"web-app": {
				{
					Title:    "HTTP",
					Protocol: types.HTTP,
					SourceId: "ci/cd",
					TargetId: "web-app",
					Usage:    types.DevOps,
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, "<b>Cross-Site Request Forgery (CSRF)</b> risk at <b>Web Application</b> via <b>HTTP</b> from <b>ci/cd</b>", risks[0].Title)
	assert.Equal(t, types.Likely, risks[0].ExploitationLikelihood)
	assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
}

func TestCrossSiteRequestForgeryRuleGenerateRisksTechAssetWebApplicationIncomingRequestWebAccessProtocolRiskCreatedWithMediumImpactWhenIntegrityIsMissionCritical(t *testing.T) {
	rule := NewCrossSiteRequestForgeryRule()

	risks, err := rule.GenerateRisks(&types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"web-app": {
				Id:    "web-app",
				Title: "Web Application",
				Technologies: types.TechnologyList{
					{
						Name: "web-app",
						Attributes: map[string]bool{
							types.IsWebApplication: true,
						},
					},
				},
			},
			"user": {
				Title:               "user",
				UsedAsClientByHuman: true,
				Technologies: types.TechnologyList{
					{
						Name: "user",
					},
				},
			},
		},
		DataAssets: map[string]*types.DataAsset{
			"mission-critical-data": {
				Id:        "mission-critical-data",
				Title:     "Mission Critical Data",
				Integrity: types.MissionCritical,
			},
		},

		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"web-app": {
				{
					Title:              "HTTP",
					Protocol:           types.HTTP,
					SourceId:           "user",
					TargetId:           "web-app",
					DataAssetsReceived: []string{"mission-critical-data"},
				},
			},
		},
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, risks)
	assert.Equal(t, "<b>Cross-Site Request Forgery (CSRF)</b> risk at <b>Web Application</b> via <b>HTTP</b> from <b>user</b>", risks[0].Title)
	assert.Equal(t, types.VeryLikely, risks[0].ExploitationLikelihood)
	assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)
}

func TestCrossSiteRequestForgeryRuleGenerateRisksLikelihoodByAuthentication(t *testing.T) {
	for authentication, likelihood := range map[types.Authentication]types.RiskExploitationLikelihood{
		types.SessionId:         types.VeryLikely,
		types.ClientCertificate: types.VeryLikely, // a browser sends it along like a cookie
		types.Token:             types.Unlikely,
		types.ShortLivedToken:   types.Unlikely,
		types.LongLivedToken:    types.Unlikely,
	} {
		risks, err := NewCrossSiteRequestForgeryRule().GenerateRisks(&types.Model{
			TechnicalAssets: map[string]*types.TechnicalAsset{
				"web-app": {
					Id: "web-app", Title: "Web Application",
					Technologies: types.TechnologyList{
						{Name: "web-app", Attributes: map[string]bool{types.IsWebApplication: true}},
					},
				},
				"user": {Title: "user", UsedAsClientByHuman: true, Technologies: types.TechnologyList{{Name: "user"}}},
			},
			IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
				"web-app": {{
					Title: "HTTP", Protocol: types.HTTPS, SourceId: "user", TargetId: "web-app",
					Authentication: authentication,
				}},
			},
		})

		assert.NoError(t, err)
		if assert.Len(t, risks, 1, authentication.String()) {
			assert.Equal(t, likelihood, risks[0].ExploitationLikelihood, authentication.String())
		}
	}
}

func TestCrossSiteRequestForgeryRuleGenerateRisksOnlyFromBrowsers(t *testing.T) {
	webApplication := types.TechnologyList{{Name: "web-app", Attributes: map[string]bool{types.IsWebApplication: true}}}
	forwarding := types.TechnologyList{{Name: "proxy", Attributes: map[string]bool{types.IsTrafficForwarding: true}}}
	link := func(id, source, target string) *types.CommunicationLink {
		return &types.CommunicationLink{Id: id, Title: id, Protocol: types.HTTPS, SourceId: source, TargetId: target}
	}
	model := &types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{
			"web-app": {Id: "web-app", Title: "Web Application", Technologies: webApplication},
			"browser": {
				Id: "browser", Title: "Browser",
				Technologies: types.TechnologyList{{Name: "browser", Attributes: map[string]bool{types.Browser: true}}},
			},
			"proxy":     {Id: "proxy", Title: "Proxy", Technologies: forwarding},
			"loop":      {Id: "loop", Title: "Loop", Technologies: forwarding},
			"batch-job": {Id: "batch-job", Title: "Batch Job", Technologies: types.TechnologyList{{Name: "batch"}}},
		},
		IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
			"web-app": {
				link("browser>direct", "browser", "web-app"),
				link("proxy>forwarded", "proxy", "web-app"),
				link("batch-job>import", "batch-job", "web-app"),
				link("loop>looped", "loop", "web-app"),
			},
			"proxy": {link("browser>to-proxy", "browser", "proxy")},
			"loop":  {link("loop>itself", "loop", "loop")}, // forwards only its own traffic
		},
	}

	risks, err := NewCrossSiteRequestForgeryRule().GenerateRisks(model)

	assert.NoError(t, err)
	links := make([]string, 0, len(risks))
	for _, risk := range risks {
		links = append(links, risk.MostRelevantCommunicationLinkId)
	}
	assert.ElementsMatch(t, []string{"browser>direct", "proxy>forwarded"}, links)
}
