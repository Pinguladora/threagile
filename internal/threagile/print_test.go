package threagile

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pinguladora/threagile"
)

func TestPrintLicenseUsesEmbeddedCopy(t *testing.T) {
	output := runCommand(t, PrintLicenseCommand, "--"+appDirFlagName, filepath.Join(t.TempDir(), "missing"))

	if !strings.Contains(output, string(threagile.License.Bytes())) {
		t.Errorf("expected the embedded license in the output, got:\n%v", output)
	}
}

func TestPrintLicensePrefersAppFolder(t *testing.T) {
	appFolder := t.TempDir()
	if err := os.WriteFile(filepath.Join(appFolder, "LICENSE.txt"), []byte("custom license"), 0o600); err != nil {
		t.Fatal(err)
	}

	output := runCommand(t, PrintLicenseCommand, "--"+appDirFlagName, appFolder)

	if !strings.Contains(output, "custom license") {
		t.Errorf("expected the license from the app folder in the output, got:\n%v", output)
	}
}

func runCommand(t *testing.T, args ...string) string {
	t.Helper()

	// Init applies the command line to the config before cobra runs the command
	// (processSystemArgs); do the same with args instead of os.Args.
	what := (&Threagile{}).initRoot().initPrint()
	what.processArgs(what.rootCmd, args)
	var output bytes.Buffer
	what.rootCmd.SetOut(&output)
	what.rootCmd.SetErr(&output)
	what.rootCmd.SetArgs(args)

	if err := what.rootCmd.Execute(); err != nil {
		t.Fatalf("%v: %v\n%v", args, err, output.String())
	}

	return output.String()
}
