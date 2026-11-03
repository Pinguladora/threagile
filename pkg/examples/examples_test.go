package examples

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Pinguladora/threagile"
)

func TestCreateFilesFromEmbeddedAssets(t *testing.T) {
	appFolder := filepath.Join(t.TempDir(), "missing-app-folder")
	outputDir := t.TempDir()

	if err := CreateExampleModelFile(appFolder, outputDir, "threagile.yaml"); err != nil {
		t.Fatalf("CreateExampleModelFile: %v", err)
	}

	if err := CreateStubModelFile(appFolder, outputDir, "threagile.yaml"); err != nil {
		t.Fatalf("CreateStubModelFile: %v", err)
	}

	if err := CreateEditingSupportFiles(appFolder, outputDir); err != nil {
		t.Fatalf("CreateEditingSupportFiles: %v", err)
	}

	for name, asset := range map[string]threagile.Asset{
		"threagile-example-model.yaml": threagile.ExampleModel,
		"threagile-stub-model.yaml":    threagile.StubModel,
		"schema.json":                  threagile.Schema,
		"live-templates.txt":           threagile.LiveTemplates,
	} {
		if got := readFile(t, filepath.Join(outputDir, name)); !bytes.Equal(got, asset.Bytes()) {
			t.Errorf("%v differs from the embedded %v", name, asset)
		}
	}
}

func TestCreateFilesFromAppFolder(t *testing.T) {
	appFolder := t.TempDir()
	outputDir := t.TempDir()
	writeFile(t, filepath.Join(appFolder, "threagile-example-model.yaml"), "custom example")
	writeFile(t, filepath.Join(appFolder, "threagile.yaml"), "custom stub")
	writeFile(t, filepath.Join(appFolder, "schema.json"), "custom schema")

	if err := CreateExampleModelFile(appFolder, outputDir, "threagile.yaml"); err != nil {
		t.Fatalf("CreateExampleModelFile: %v", err)
	}

	if err := CreateStubModelFile(appFolder, outputDir, "threagile.yaml"); err != nil {
		t.Fatalf("CreateStubModelFile: %v", err)
	}

	if err := CreateEditingSupportFiles(appFolder, outputDir); err != nil {
		t.Fatalf("CreateEditingSupportFiles: %v", err)
	}

	for name, want := range map[string][]byte{
		"threagile-example-model.yaml": []byte("custom example"),
		"threagile-stub-model.yaml":    []byte("custom stub"),
		"schema.json":                  []byte("custom schema"),
		"live-templates.txt":           threagile.LiveTemplates.Bytes(),
	} {
		if got := readFile(t, filepath.Join(outputDir, name)); !bytes.Equal(got, want) {
			t.Errorf("%v: got %.40q, want %.40q", name, got, want)
		}
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
