package report

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/Pinguladora/threagile"
)

// Defaults of --background and --reportLogoImagePath. While a flag has its
// default value and no such file exists on disk, the report uses the copy
// embedded in the binary instead.
const (
	DefaultTemplateFilename    = "background.pdf"
	DefaultReportLogoImagePath = "report/threagile-logo.png"
)

// backgroundTemplateFile resolves --background to the PDF file to import, or to
// "" for the background embedded in the binary. An absolute path is used as is,
// a relative one is looked up in the app folder (the upstream image's /app
// layout). A file on disk always wins; when there is none, the default value
// falls back to the embedded background and any other value is an error.
func backgroundTemplateFile(appFolder, templateFilename string) (string, error) {
	path := templateFilename
	if !filepath.IsAbs(path) {
		path = filepath.Join(appFolder, path)
	}

	_, err := os.Stat(path)
	switch {
	case err == nil:
		return path, nil
	case errors.Is(err, fs.ErrNotExist) && templateFilename == DefaultTemplateFilename:
		return "", nil
	default:
		return "", fmt.Errorf("unable to use background template %q: %w", path, err)
	}
}

// reportLogo returns the content of the --reportLogoImagePath image: the file on
// disk when it exists, else the embedded logo while the flag has its default
// value. It returns nil for any other image that does not exist.
func reportLogo(logoImagePath string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Clean(logoImagePath))
	switch {
	case err == nil:
		return data, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("unable to read logo image %q: %w", logoImagePath, err)
	case logoImagePath == DefaultReportLogoImagePath:
		return threagile.Logo.Bytes(), nil
	default:
		return nil, nil
	}
}

// embeddedBackground is the stream that the PDF report imports the embedded
// background from. gofpdi caches what it imports by the address of the stream
// (like it caches files by name), so every report shares this one.
var embeddedBackground = sync.OnceValue(func() *io.ReadSeeker {
	stream := io.ReadSeeker(bytes.NewReader(threagile.Background.Bytes()))
	return &stream
})
