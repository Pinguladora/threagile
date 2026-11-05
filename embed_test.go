package threagile

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

var allAssets = []Asset{License, ExampleModel, StubModel, Logo, Schema, OpenAPI, LiveTemplates}

func TestAssetBytesMatchRepositoryFiles(t *testing.T) {
	for _, asset := range allAssets {
		onDisk, err := os.ReadFile(string(asset))
		if err != nil {
			t.Fatalf("reading %q from the repository: %v", asset, err)
		}

		if !bytes.Equal(asset.Bytes(), onDisk) {
			t.Errorf("embedded %q differs from the file in the repository", asset)
		}
	}
}

func TestReadFileFallsBackToEmbeddedCopy(t *testing.T) {
	dir := t.TempDir()

	data, err := Schema.ReadFile(filepath.Join(dir, "schema.json"), filepath.Join(dir, "missing", "schema.json"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if !bytes.Equal(data, Schema.Bytes()) {
		t.Error("expected the embedded schema when no file exists on disk")
	}
}

func TestReadFilePrefersFirstFileOnDisk(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.yaml")
	second := filepath.Join(dir, "second.yaml")
	writeFile(t, second, "second")

	data, err := ExampleModel.ReadFile(first, second)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if string(data) != "second" {
		t.Errorf("got %q, want the only file that exists on disk", data)
	}

	writeFile(t, first, "first")

	data, err = ExampleModel.ReadFile(first, second)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if string(data) != "first" {
		t.Errorf("got %q, want the first file that exists on disk", data)
	}
}

func TestReadFileReportsUnreadableFile(t *testing.T) {
	// A directory exists but cannot be read as a file: that is a misconfiguration
	// to report, not a missing file to replace with the embedded copy.
	if _, err := License.ReadFile(t.TempDir()); err == nil {
		t.Error("expected an error for a path that is a directory")
	}
}

func TestStaticHoldsWebUI(t *testing.T) {
	for _, name := range []string{
		"index.html", "edit-model.html", "css/edit-model.css", "js/edit-model.js", "js/property-editor.js", "js/schema.js",
		"threagile.png", "site.webmanifest", "favicon.ico",
	} {
		embedded, err := fs.ReadFile(Static(), name)
		if err != nil {
			t.Errorf("reading %q from the embedded web UI: %v", name, err)
			continue
		}

		onDisk, err := os.ReadFile(filepath.Join("server", "static", filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("reading %q from the repository: %v", name, err)
		}

		if !bytes.Equal(embedded, onDisk) {
			t.Errorf("embedded %q differs from the file in the repository", name)
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
