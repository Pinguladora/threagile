package macros

import (
	"bufio"
	"slices"
	"strings"
	"testing"

	"github.com/Pinguladora/threagile/pkg/input"
	"github.com/Pinguladora/threagile/pkg/types"
)

func TestSelectValuesKeepsTheOrderOfTheAnswers(t *testing.T) {
	question := MacroQuestion{PossibleAnswers: []string{"a", "b", "c", "d", "e"}, MultiSelect: true}

	for range 20 {
		got, err := selectValues(question, bufio.NewReader(strings.NewReader("5\n2\n4\n1\n0\n")))
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"a", "b", "d", "e"}; !slices.Equal(got, want) {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

// vaultModel returns a model with a client that has no communication links, as input and as parsed.
func vaultModel() (*input.Model, *types.Model) {
	modelInput := &input.Model{
		DataAssets:      map[string]input.DataAsset{},
		TechnicalAssets: map[string]input.TechnicalAsset{"App": {ID: "app"}},
	}
	parsedModel := &types.Model{
		DataAssets:      map[string]*types.DataAsset{},
		TechnicalAssets: map[string]*types.TechnicalAsset{"app": {Id: "app", Title: "App"}},
	}

	return modelInput, parsedModel
}

func addVault(t *testing.T, modelInput *input.Model, parsedModel *types.Model) {
	t.Helper()

	macro := NewAddVault()
	for id, answer := range map[string]string{
		"vault-name":                "Hashi",
		"storage-type":              storageTypes[0],
		"authentication-type":       authenticationTypes[0],
		"multi-tenant":              "no",
		withinTrustBoundaryQuestion: "no",
	} {
		applyAnswer(t, macro, id, answer)
	}
	applyAnswer(t, macro, "clients", "app")

	if _, valid, err := macro.Execute(modelInput, parsedModel); err != nil || !valid {
		t.Fatalf("valid %v, error %v", valid, err)
	}
}

func applyAnswer(t *testing.T, macro Macros, questionID string, answer string) {
	t.Helper()

	if message, valid, err := macro.ApplyAnswer(questionID, answer); err != nil || !valid {
		t.Fatalf("answer to %v: %v, error %v", questionID, message, err)
	}
}

func TestAddVaultToAClientWithoutLinks(t *testing.T) {
	modelInput, parsedModel := vaultModel()
	addVault(t, modelInput, parsedModel)

	app := modelInput.TechnicalAssets["App"]
	if _, ok := app.CommunicationLinks["Vault Access (app)"]; !ok {
		t.Errorf("no vault access link: %v", app.CommunicationLinks)
	}
	if !slices.Equal(app.DataAssetsProcessed, []string{configurationSecretsDataAsset}) {
		t.Errorf("processed %q", app.DataAssetsProcessed)
	}
}
