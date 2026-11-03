// Package threagile embeds the files threagile needs at run time (license,
// example and stub models, editing support, report background and logo, and the
// server's web UI), so that a lone binary works without an --app-dir folder.
//
// The embedded copies are only defaults: callers look for a file on disk first
// (see Asset.ReadFile) and fall back to the copy compiled into the binary.
package threagile

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed LICENSE.txt
//go:embed demo/example/threagile.yaml demo/stub/threagile.yaml
//go:embed report/template/background.pdf report/threagile-logo.png
//go:embed support/schema.json support/openapi.yaml support/live-templates.txt
//go:embed server/static
var files embed.FS

// Asset is a run-time file embedded in the binary, named by its path in this
// repository.
type Asset string

// The assets threagile reads at run time.
const (
	License       Asset = "LICENSE.txt"
	ExampleModel  Asset = "demo/example/threagile.yaml"
	StubModel     Asset = "demo/stub/threagile.yaml"
	Background    Asset = "report/template/background.pdf"
	Logo          Asset = "report/threagile-logo.png"
	Schema        Asset = "support/schema.json"
	OpenAPI       Asset = "support/openapi.yaml"
	LiveTemplates Asset = "support/live-templates.txt"
)

// Bytes returns the copy of the asset embedded in the binary.
func (a Asset) Bytes() []byte {
	data, err := files.ReadFile(string(a))
	if err != nil {
		// Every Asset constant names a file matched by the go:embed patterns above
		// (the tests check this), so this only fires if the two get out of sync.
		panic(fmt.Sprintf("asset %q is not embedded: %v", a, err))
	}

	return data
}

// ReadFile returns the content of the first of paths that exists on disk, and
// the embedded copy of the asset when none of them does. A file that exists but
// cannot be read is an error rather than a reason to fall back.
func (a Asset) ReadFile(paths ...string) ([]byte, error) {
	for _, path := range paths {
		data, err := os.ReadFile(filepath.Clean(path))
		if err == nil {
			return data, nil
		}

		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("unable to read %q: %w", path, err)
		}
	}

	return a.Bytes(), nil
}

// Static returns the web UI that server mode serves, rooted at server/static.
func Static() fs.FS {
	static, err := fs.Sub(files, "server/static")
	if err != nil {
		// fs.Sub only fails for an invalid path, and this one is a constant.
		panic(fmt.Sprintf("server/static is not embedded: %v", err))
	}

	return static
}
