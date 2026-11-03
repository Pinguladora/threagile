package threagile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAcceptsMissingAppFolder(t *testing.T) {
	config := new(Config).Defaults("")
	if err := config.Load(writeConfig(t, filepath.Join(t.TempDir(), "missing"))); err != nil {
		t.Errorf("a missing app folder should be fine, got: %v", err)
	}
}

func TestLoadRejectsAppFolderThatIsAFile(t *testing.T) {
	appFolder := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(appFolder, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	config := new(Config).Defaults("")
	if err := config.Load(writeConfig(t, appFolder)); err == nil {
		t.Error("expected an error for an app folder that is a file")
	}
}

// writeConfig writes a config file with the given app folder and existing
// folders for everything else Load checks.
func writeConfig(t *testing.T, appFolder string) string {
	t.Helper()

	data, err := json.Marshal(map[string]string{
		"AppFolder":    appFolder,
		"PluginFolder": t.TempDir(),
		"DataFolder":   t.TempDir(),
		"OutputFolder": t.TempDir(),
		"TempFolder":   t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}

	configFile := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configFile, data, 0o600); err != nil {
		t.Fatal(err)
	}

	return configFile
}
