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

func TestLoadReadsTheOTMOutputKeys(t *testing.T) {
	configFile := writeConfig(t, t.TempDir())
	data, err := os.ReadFile(filepath.Clean(configFile))
	if err != nil {
		t.Fatal(err)
	}

	var values map[string]any
	if err := json.Unmarshal(data, &values); err != nil {
		t.Fatal(err)
	}
	values["JsonOTMFilename"] = "model.otm.json"
	values["SkipOTMJSON"] = true

	data, err = json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configFile, data, 0o600); err != nil {
		t.Fatal(err)
	}

	config := new(Config).Defaults("")
	if config.GetJsonOTMFilename() != JsonOTMFilename || config.GetSkipOTMJSON() {
		t.Fatalf("defaults are %q and %v, want %q and false", config.GetJsonOTMFilename(), config.GetSkipOTMJSON(), JsonOTMFilename)
	}

	if err := config.Load(configFile); err != nil {
		t.Fatal(err)
	}
	if config.GetJsonOTMFilename() != "model.otm.json" || !config.GetSkipOTMJSON() {
		t.Errorf("got %q and %v, want the values of the config file", config.GetJsonOTMFilename(), config.GetSkipOTMJSON())
	}
}

func TestLoadReadsTheSkipKeys(t *testing.T) {
	keys := []string{
		"SkipDataFlowDiagram", "SkipDataAssetDiagram", "SkipRisksJSON", "SkipTechnicalAssetsJSON",
		"SkipStatsJSON", "SkipOTMJSON", "SkipRisksExcel", "SkipTagsExcel", "SkipReportPDF", "SkipReportADOC",
		"SkipReportHTML", "SkipReportMarkdown",
	}
	values := map[string]any{
		"PluginFolder": t.TempDir(),
		"DataFolder":   t.TempDir(),
		"OutputFolder": t.TempDir(),
		"TempFolder":   t.TempDir(),
	}
	for _, key := range keys {
		values[key] = true
	}

	data, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configFile, data, 0o600); err != nil {
		t.Fatal(err)
	}

	config := new(Config).Defaults("")
	if err := config.Load(configFile); err != nil {
		t.Fatal(err)
	}

	got := map[string]bool{
		"SkipDataFlowDiagram":     config.GetSkipDataFlowDiagram(),
		"SkipDataAssetDiagram":    config.GetSkipDataAssetDiagram(),
		"SkipRisksJSON":           config.GetSkipRisksJSON(),
		"SkipTechnicalAssetsJSON": config.GetSkipTechnicalAssetsJSON(),
		"SkipStatsJSON":           config.GetSkipStatsJSON(),
		"SkipOTMJSON":             config.GetSkipOTMJSON(),
		"SkipRisksExcel":          config.GetSkipRisksExcel(),
		"SkipTagsExcel":           config.GetSkipTagsExcel(),
		"SkipReportPDF":           config.GetSkipReportPDF(),
		"SkipReportADOC":          config.GetSkipReportADOC(),
		"SkipReportHTML":          config.GetSkipReportHTML(),
		"SkipReportMarkdown":      config.GetSkipReportMarkdown(),
	}
	for _, key := range keys {
		if !got[key] {
			t.Errorf("%s from the config file was ignored", key)
		}
	}
}

func TestLoadReadsTheHTMLReportFilename(t *testing.T) {
	values := map[string]any{
		"PluginFolder":       t.TempDir(),
		"DataFolder":         t.TempDir(),
		"OutputFolder":       t.TempDir(),
		"TempFolder":         t.TempDir(),
		"ReportHTMLFilename": "threat-model.html",
	}
	data, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configFile, data, 0o600); err != nil {
		t.Fatal(err)
	}

	config := new(Config).Defaults("")
	if config.GetReportHTMLFilename() != ReportHTMLFilename || config.GetSkipReportHTML() {
		t.Fatalf("defaults are %q and %v, want %q and false", config.GetReportHTMLFilename(), config.GetSkipReportHTML(), ReportHTMLFilename)
	}
	if err := config.Load(configFile); err != nil {
		t.Fatal(err)
	}
	if config.GetReportHTMLFilename() != "threat-model.html" {
		t.Errorf("got %q, want the file name of the config file", config.GetReportHTMLFilename())
	}
}

func TestLoadReadsTheMarkdownReportFilename(t *testing.T) {
	values := map[string]any{
		"PluginFolder":           t.TempDir(),
		"DataFolder":             t.TempDir(),
		"OutputFolder":           t.TempDir(),
		"TempFolder":             t.TempDir(),
		"ReportMarkdownFilename": "docs/threat-model.md",
	}
	data, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configFile, data, 0o600); err != nil {
		t.Fatal(err)
	}

	config := new(Config).Defaults("")
	if config.GetReportMarkdownFilename() != ReportMarkdownFilename || config.GetSkipReportMarkdown() {
		t.Fatalf("defaults are %q and %v, want %q and false", config.GetReportMarkdownFilename(),
			config.GetSkipReportMarkdown(), ReportMarkdownFilename)
	}
	if err := config.Load(configFile); err != nil {
		t.Fatal(err)
	}
	if config.GetReportMarkdownFilename() != "docs/threat-model.md" {
		t.Errorf("got %q, want the file name of the config file", config.GetReportMarkdownFilename())
	}
}

func TestMergeTakesTheMarkdownReportKeys(t *testing.T) {
	config := new(Config).Defaults("")
	config.Merge(Config{ReportMarkdownFilenameValue: "threat-model.md", SkipReportMarkdownValue: true},
		map[string]any{"reportmarkdownfilename": "threat-model.md", "SkipReportMarkdown": true})
	if config.GetReportMarkdownFilename() != "threat-model.md" || !config.GetSkipReportMarkdown() {
		t.Errorf("got %q and %v, want the merged values", config.GetReportMarkdownFilename(), config.GetSkipReportMarkdown())
	}

	untouched := new(Config).Defaults("")
	untouched.Merge(Config{ReportMarkdownFilenameValue: "other.md"}, map[string]any{"ReportHTMLFilename": "x.html"})
	if untouched.GetReportMarkdownFilename() != ReportMarkdownFilename {
		t.Errorf("got %q, want the default as the key was not given", untouched.GetReportMarkdownFilename())
	}
}
