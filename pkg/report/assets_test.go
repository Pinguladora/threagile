package report

import (
	"bytes"
	"compress/zlib"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/Pinguladora/threagile"
	"github.com/jung-kurt/gofpdf"
	"github.com/jung-kurt/gofpdf/contrib/gofpdi"
)

func TestBackgroundTemplateFile(t *testing.T) {
	appFolder := t.TempDir()
	custom := filepath.Join(t.TempDir(), "custom.pdf")
	writeTestFile(t, custom, nil)

	resolve := func(templateFilename string) string {
		t.Helper()

		path, err := backgroundTemplateFile(appFolder, templateFilename)
		if err != nil {
			t.Fatalf("backgroundTemplateFile(%q): %v", templateFilename, err)
		}

		return path
	}

	if path := resolve(DefaultTemplateFilename); path != "" {
		t.Errorf("default without a file on disk: got %q, want the embedded background", path)
	}

	if path := resolve(custom); path != custom {
		t.Errorf("absolute path: got %q, want %q", path, custom)
	}

	for _, name := range []string{DefaultTemplateFilename, "custom.pdf"} {
		inAppFolder := filepath.Join(appFolder, name)
		writeTestFile(t, inAppFolder, nil)

		if path := resolve(name); path != inAppFolder {
			t.Errorf("%q in the app folder: got %q, want %q", name, path, inAppFolder)
		}
	}

	for _, name := range []string{"missing.pdf", filepath.Join(appFolder, "missing.pdf")} {
		if _, err := backgroundTemplateFile(appFolder, name); err == nil {
			t.Errorf("explicitly configured %q does not exist: want an error", name)
		}
	}
}

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

func TestParseBackgroundTemplate(t *testing.T) {
	const marker = "CUSTOM BACKGROUND"
	custom := filepath.Join(t.TempDir(), "custom.pdf")
	writeBackground(t, custom, marker)

	// The embedded background is imported once and shared by later reports, so
	// render it twice.
	for range 2 {
		embedded := renderWithBackground(t, "")
		if len(embedded) == 0 || bytes.Contains(embedded, []byte(marker)) {
			t.Errorf("want the embedded background, got %d bytes of content", len(embedded))
		}
	}

	if !bytes.Contains(renderWithBackground(t, custom), []byte(marker)) {
		t.Error("the background on disk was not used")
	}
}

// renderWithBackground writes a one-page PDF with the cover of the given
// background ("" for the embedded one) and returns its content streams.
func renderWithBackground(t *testing.T, templateFilename string) []byte {
	t.Helper()

	r := &pdfReporter{pdf: gofpdf.New("P", "mm", "A4", "")}
	r.pdf.SetCompression(false)
	r.parseBackgroundTemplate(templateFilename)
	r.pdf.AddPage()
	gofpdi.UseImportedTemplate(r.pdf, r.coverTemplateId, 0, 0, 0, 300)

	var output bytes.Buffer
	if err := r.pdf.Output(&output); err != nil {
		t.Fatalf("rendering with background %q: %v", templateFilename, err)
	}

	return inflateStreams(output.Bytes())
}

// inflateStreams returns the decompressed content of the Flate-encoded streams
// in a PDF (gofpdi compresses the pages it imports).
func inflateStreams(pdf []byte) []byte {
	var content bytes.Buffer
	for _, chunk := range bytes.Split(pdf, []byte("stream\n"))[1:] {
		reader, err := zlib.NewReader(bytes.NewReader(chunk))
		if err != nil {
			continue
		}

		_, _ = io.Copy(&content, reader) //nolint:gosec // G110: test input written by the test itself
	}

	return content.Bytes()
}

// writeBackground writes a three-page background PDF showing text on every page.
func writeBackground(t *testing.T, path, text string) {
	t.Helper()

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetCompression(false)
	pdf.SetFont("Helvetica", "", 12)
	for range 3 {
		pdf.AddPage()
		pdf.Text(20, 20, text)
	}

	if err := pdf.OutputFileAndClose(path); err != nil {
		t.Fatal(err)
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
