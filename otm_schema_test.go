package threagile_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	root "github.com/Pinguladora/threagile"
	cli "github.com/Pinguladora/threagile/internal/threagile"
	"github.com/Pinguladora/threagile/pkg/interchange"
	"github.com/Pinguladora/threagile/pkg/model"
	"github.com/Pinguladora/threagile/pkg/otm"
	"github.com/Pinguladora/threagile/pkg/risks"
)

// otmSchemaFile is the official OTM JSON schema; its .license file next to it says where it is from.
const otmSchemaFile = "pkg/otm/testdata/otm_schema.json"

// TestOTMOutputMatchesSchema checks the OTM that threagile writes for the bundled models against
// the official OTM schema of the version threagile writes.
func TestOTMOutputMatchesSchema(t *testing.T) {
	var schema map[string]any
	readJSON(t, otmSchemaFile, &schema)
	if want := "https://iriusrisk.com/schema/otm-" + otm.Version + ".schema.json"; schema["$id"] != want {
		t.Fatalf("the schema is %v, want %v, the version threagile writes", schema["$id"], want)
	}

	for bundled, content := range root.DemoModels(t) {
		modelFile := filepath.Join(t.TempDir(), "threagile.yaml")
		if err := os.WriteFile(modelFile, content, 0o600); err != nil {
			t.Fatal(err)
		}

		config := new(cli.Config).Defaults("")
		config.SetAppFolder(t.TempDir())
		config.SetPluginFolder(t.TempDir())
		config.SetInputFile(modelFile)
		config.SetOutputFolder(t.TempDir())
		config.SetTempFolder(t.TempDir())

		result, err := model.ReadAndAnalyzeModel(config, risks.GetBuiltInRiskRules(), quietReporter{})
		if err != nil {
			t.Fatalf("%s: %v", bundled, err)
		}

		otmJSON, err := json.Marshal(otm.FromInterchange(interchange.FromModel(result.ParsedModel)))
		if err != nil {
			t.Fatal(err)
		}

		var document any
		if err := json.Unmarshal(otmJSON, &document); err != nil {
			t.Fatal(err)
		}

		for _, problem := range root.ValidateSchema(schema, document) {
			t.Errorf("%s: %s", bundled, problem)
		}

		// make sure the schema does get applied: a component without a parent is invalid
		components, _ := document.(map[string]any)["components"].([]any)
		if len(components) == 0 {
			t.Fatalf("%s: no components", bundled)
		}
		component, _ := components[0].(map[string]any)
		delete(component, "parent")
		if problems := root.ValidateSchema(schema, document); len(problems) != 1 {
			t.Errorf("%s: a component without a parent should be the one problem, got %q", bundled, problems)
		}
	}
}

func readJSON(t *testing.T, filename string, value any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(filename))
	if err != nil {
		t.Fatal(err)
	}

	if err := json.Unmarshal(data, value); err != nil {
		t.Fatalf("parsing %s: %v", filename, err)
	}
}

type quietReporter struct{}

func (quietReporter) Info(...any)           {}
func (quietReporter) Infof(string, ...any)  {}
func (quietReporter) Warn(...any)           {}
func (quietReporter) Warnf(string, ...any)  {}
func (quietReporter) Error(...any)          {}
func (quietReporter) Errorf(string, ...any) {}
