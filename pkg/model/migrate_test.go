package model

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

const legacyModel = `title: Legacy # a model of an earlier version

includes:
  - clients.yaml

technical_assets:

  Shop:
    id: shop
    communication_links:
      Orders:
        target: orders-db
        authentication: credentials # values: none, credentials, session-id, token, client-certificate, two-factor
        authorization: technical-user # values: none, technical-user, end-user-identity-propagation

        usage: business
      Events:
        target: orders-db
        authentication: token
        authorization: end-user-identity-propagation # forwards the token of the customer
      Current:
        target: orders-db
        authentication: credentials
        identity: workload
        authorization: none
      Inline: { target: orders-db, authentication: none, authorization: none }
`

const legacyInclude = `technical_assets:
  Admin:
    id: admin
    used_as_client_by_human: true
    communication_links:
      Deployment:
        target: shop
        authentication: credentials
        authorization: technical-user
      Administration:
        target: shop
        authentication: two-factor
        authorization: none`

func TestMigrateModelFileRewritesOnlyTheChangedLines(t *testing.T) {
	dir := t.TempDir()
	modelFile, includeFile := filepath.Join(dir, "threagile.yaml"), filepath.Join(dir, "clients.yaml")
	require.NoError(t, os.WriteFile(modelFile, []byte(legacyModel), 0o600))
	require.NoError(t, os.WriteFile(includeFile, []byte(legacyInclude), 0o600))

	migration, err := MigrateModelFile(modelFile)
	require.NoError(t, err)

	migrated, err := os.ReadFile(filepath.Clean(modelFile))
	require.NoError(t, err)
	assert.Equal(t, `title: Legacy # a model of an earlier version

includes:
  - clients.yaml

technical_assets:

  Shop:
    id: shop
    communication_links:
      Orders:
        target: orders-db
        authentication: credentials # values: none, credentials, session-id, token, short-lived-token, long-lived-token, client-certificate, multi-factor, externalized
        identity: service-account # values: none, service-account, workload, end-user
        authorization: unknown # values: unknown, none, authenticated-only, function-level, object-level

        usage: business
      Events:
        target: orders-db
        authentication: token
        identity: end-user # forwards the token of the customer
        authorization: unknown
      Current:
        target: orders-db
        authentication: credentials
        identity: workload
        authorization: none
      Inline: { target: orders-db, authentication: none, authorization: none }
`, string(migrated))

	included, err := os.ReadFile(filepath.Clean(includeFile))
	require.NoError(t, err)
	assert.Equal(t, `technical_assets:
  Admin:
    id: admin
    used_as_client_by_human: true
    communication_links:
      Deployment:
        target: shop
        authentication: credentials
        identity: service-account
        authorization: unknown
      Administration:
        target: shop
        authentication: multi-factor
        identity: none
        authorization: unknown`, string(included), "the include keeps its missing final newline")

	assert.Len(t, migration.Changes, 5)
	assert.Equal(t, []string{
		modelFile + `: technical asset "Shop" communication link "Events": authentication token, choose ` +
			"short-lived-token or long-lived-token",
		modelFile + `: technical asset "Shop" communication link "Inline": written in flow style, migrate it by hand`,
		includeFile + `: technical asset "Admin" communication link "Deployment": the caller is used by humans, set ` +
			"the identity to end-user if they sign in with their own accounts",
		"set the authorization of the 4 links whose identity moved (none, authenticated-only, function-level or " +
			"object-level)",
	}, migration.Notes)

	again, err := MigrateModelFile(modelFile)
	require.NoError(t, err)
	assert.Empty(t, again.Changes, "a migrated model needs no more changes")
}

func TestMigrateModelFileTurnsIndividualRiskCategoriesIntoCustomRiskCategories(t *testing.T) {
	modelFile := filepath.Join(t.TempDir(), "threagile.yaml")
	require.NoError(t, os.WriteFile(modelFile, []byte(`title: Legacy

individual_risk_categories: # manually identified risks
  Some Individual Risk: # the title
    id: something-strange
    description: Some text
    risks_identified:
      Something Strange at Shop:
        severity: critical
  Other Risk:
    id: other
    title: Other Risk Titled Again`), 0o600))

	migration, err := MigrateModelFile(modelFile)
	require.NoError(t, err)

	migrated, err := os.ReadFile(filepath.Clean(modelFile))
	require.NoError(t, err)
	assert.Equal(t, `title: Legacy

custom_risk_categories: # manually identified risks
  - title: Some Individual Risk # the title
    id: something-strange
    description: Some text
    risks_identified:
      Something Strange at Shop:
        severity: critical
  -
    id: other
    title: Other Risk Titled Again`, string(migrated), "a category that names its title keeps it")
	assert.Equal(t, []string{modelFile + ": individual_risk_categories: now custom_risk_categories, 2 categories"},
		migration.Changes)

	var model struct {
		Custom []struct {
			ID    string `yaml:"id"`
			Title string `yaml:"title"`
		} `yaml:"custom_risk_categories"`
	}
	require.NoError(t, yaml.Unmarshal(migrated, &model))
	assert.Equal(t, "Some Individual Risk", model.Custom[0].Title)
	assert.Equal(t, "Other Risk Titled Again", model.Custom[1].Title)

	again, err := MigrateModelFile(modelFile)
	require.NoError(t, err)
	assert.Empty(t, again.Changes, "a migrated model needs no more changes")
}

func TestMigrateModelFileLeavesIndividualRiskCategoriesItCannotRewrite(t *testing.T) {
	for name, content := range map[string]string{
		"a quoted title": `individual_risk_categories:
  "Quoted: Risk":
    id: quoted
`,
		"both keys": `individual_risk_categories:
  Some Risk:
    id: some
custom_risk_categories:
  - id: other
    title: Other
`,
	} {
		modelFile := filepath.Join(t.TempDir(), "threagile.yaml")
		require.NoError(t, os.WriteFile(modelFile, []byte(content), 0o600))

		migration, err := MigrateModelFile(modelFile)
		require.NoError(t, err)

		migrated, err := os.ReadFile(filepath.Clean(modelFile))
		require.NoError(t, err)
		assert.Equal(t, content, string(migrated), name)
		assert.Empty(t, migration.Changes, name)
		assert.Len(t, migration.Notes, 1, name)
	}
}
