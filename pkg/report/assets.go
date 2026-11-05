package report

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Pinguladora/threagile"
)

// Defaults of --background, which the reports no longer use, and --reportLogoImagePath. While the logo flag has its
// default value and no such file exists on disk, the report uses the copy embedded in the binary instead.
const (
	DefaultTemplateFilename    = "background.pdf"
	DefaultReportLogoImagePath = "report/threagile-logo.png"
)

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
