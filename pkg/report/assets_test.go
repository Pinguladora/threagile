package report

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Pinguladora/threagile"
)

func TestReportLogo(t *testing.T) {
	t.Chdir(t.TempDir())

	logo, err := reportLogo(DefaultReportLogoImagePath)
	if err != nil || !bytes.Equal(logo, threagile.Logo.Bytes()) {
		t.Errorf("default without a file on disk: want the embedded logo, got %d bytes, error %v", len(logo), err)
	}

	logo, err = reportLogo("missing.png")
	if err != nil || logo != nil {
		t.Errorf("explicitly configured image does not exist: want no logo, got %d bytes, error %v", len(logo), err)
	}

	for _, name := range []string{DefaultReportLogoImagePath, "custom.png"} {
		writeTestFile(t, name, []byte(name))

		logo, err = reportLogo(name)
		if err != nil || string(logo) != name {
			t.Errorf("%q on disk: got %q, error %v", name, logo, err)
		}
	}
}

func writeTestFile(t *testing.T, path string, content []byte) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}
