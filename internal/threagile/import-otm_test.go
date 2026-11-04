package threagile

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pinguladora/threagile/pkg/model"
	"github.com/Pinguladora/threagile/pkg/risks"
)

// exampleOTMFile is the OTM that analyze-model writes for the example model.
const exampleOTMFile = "../../pkg/report/testdata/example/otm.json"

func TestImportOTMWritesAModelThatAnalyzes(t *testing.T) {
	outputFolder := filepath.Join(t.TempDir(), "imported")
	output, err := runImportOTM(t, "--"+otmFileFlagName, exampleOTMFile, "--"+outputFlagName, outputFolder)
	if err != nil {
		t.Fatalf("%v\n%v", err, output)
	}

	for _, want := range []string{
		`Imported "Some Example Application" into ` + filepath.Join(outputFolder, InputFile),
		"5 trust boundaries, 14 technical assets, 20 communication links, 12 data assets",
		"Threats are not imported (24 threats, 71 threat instances in the file)",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("want %q in the output, got:\n%v", want, output)
		}
	}

	config := new(Config).Defaults("")
	config.SetAppFolder(t.TempDir())
	config.SetPluginFolder(t.TempDir())
	config.SetTempFolder(t.TempDir())
	config.SetInputFile(filepath.Join(outputFolder, InputFile))
	result, err := model.ReadAndAnalyzeModel(config, risks.GetBuiltInRiskRules(), DefaultProgressReporter{})
	if err != nil {
		t.Fatalf("the imported model does not analyze: %v", err)
	}
	if len(result.ParsedModel.TechnicalAssets) != 14 {
		t.Errorf("got %d technical assets, want 14", len(result.ParsedModel.TechnicalAssets))
	}

	// a second import does not overwrite the model
	output, err = runImportOTM(t, "--"+otmFileFlagName, exampleOTMFile, "--"+outputFlagName, outputFolder)
	if err == nil || !strings.Contains(err.Error(), "exists already") {
		t.Errorf("want an error about the existing model, got %v\n%v", err, output)
	}
}

func TestImportOTMWritesTheNamedFile(t *testing.T) {
	modelFile := filepath.Join(t.TempDir(), "model.yml")
	if output, err := runImportOTM(t, "--"+otmFileFlagName, exampleOTMFile, "--"+outputFlagName, modelFile); err != nil {
		t.Fatalf("%v\n%v", err, output)
	}

	modelYAML, err := os.ReadFile(filepath.Clean(modelFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(modelYAML, []byte("# Imported from the Open Threat Model file otm.json")) {
		t.Errorf("the model does not start with a comment on where it is from:\n%s", modelYAML)
	}
}

func TestImportOTMNeedsAnOTMFile(t *testing.T) {
	_, err := runImportOTM(t, "--"+outputFlagName, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "--"+otmFileFlagName) {
		t.Errorf("want an error naming the --%s flag, got %v", otmFileFlagName, err)
	}

	notOTM := filepath.Join(t.TempDir(), "threagile.yaml")
	if err := os.WriteFile(notOTM, []byte("title: A threagile model\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = runImportOTM(t, "--"+otmFileFlagName, notOTM, "--"+outputFlagName, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "no otmVersion") {
		t.Errorf("want an error about a file that is no OTM, got %v", err)
	}
}

func TestImportOutputFile(t *testing.T) {
	for output, want := range map[string]string{
		"out":            filepath.Join("out", InputFile),
		".":              InputFile,
		"out/model.yaml": "out/model.yaml",
		"out/model.YML":  "out/model.YML",
	} {
		if got := importOutputFile(output); got != want {
			t.Errorf("importOutputFile(%q) = %q, want %q", output, got, want)
		}
	}
}

func runImportOTM(t *testing.T, args ...string) (string, error) {
	t.Helper()

	// like runCommand, but the error is for the test to check
	args = append([]string{ImportOTMCommand, "--" + appDirFlagName, t.TempDir()}, args...)
	what := (&Threagile{}).initRoot().initImportOTM()
	what.processArgs(what.rootCmd, args)
	var output bytes.Buffer
	what.rootCmd.SetOut(&output)
	what.rootCmd.SetErr(&output)
	what.rootCmd.SetArgs(args)

	err := what.rootCmd.Execute()
	return output.String(), err
}
