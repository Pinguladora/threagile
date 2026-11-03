package server

import (
	"bytes"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pinguladora/threagile"
	"github.com/gin-gonic/gin"
)

// appFolderConfig provides the app folder; addStaticRoutes reads nothing else.
type appFolderConfig struct {
	serverConfigReader
	appFolder string
}

func (c appFolderConfig) GetAppFolder() string {
	return c.appFolder
}

func newStaticRouter(t *testing.T, appFolder string) *gin.Engine {
	t.Helper()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	s := &server{config: appFolderConfig{appFolder: appFolder}}
	s.addStaticRoutes(router)

	return router
}

func get(t *testing.T, router *gin.Engine, path string) *httptest.ResponseRecorder {
	t.Helper()

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, http.NoBody))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET %v: status %v, body %.200q", path, recorder.Code, recorder.Body.String())
	}

	return recorder
}

func TestStaticRoutesServeEmbeddedWebUI(t *testing.T) {
	router := newStaticRouter(t, filepath.Join(t.TempDir(), "missing"))

	for path, file := range map[string]string{
		"/":                      "index.html",
		"/edit-model":            "edit-model.html",
		"/css/edit-model.css":    "css/edit-model.css",
		"/js/edit-model.js":      "js/edit-model.js",
		"/js/property-editor.js": "js/property-editor.js",
		"/js/schema.js":          "js/schema.js",
		"/favicon.ico":           "favicon.ico",
		"/site.webmanifest":      "site.webmanifest",
	} {
		want, err := fs.ReadFile(threagile.Static(), file)
		if err != nil {
			t.Fatal(err)
		}

		if got := get(t, router, path).Body.Bytes(); !bytes.Equal(got, want) {
			t.Errorf("GET %v: body differs from the embedded %v", path, file)
		}
	}

	for path, asset := range map[string]threagile.Asset{
		"/schema.json":                  threagile.Schema,
		"/live-templates.txt":           threagile.LiveTemplates,
		"/openapi.yaml":                 threagile.OpenAPI,
		"/threagile-example-model.yaml": threagile.ExampleModel,
	} {
		if got := get(t, router, path).Body.Bytes(); !bytes.Equal(got, asset.Bytes()) {
			t.Errorf("GET %v: body differs from the embedded %v", path, asset)
		}
	}

	if contentType := get(t, router, "/schema.json").Header().Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		t.Errorf("GET /schema.json: Content-Type %q", contentType)
	}
}

func TestStaticRoutesPreferAppFolder(t *testing.T) {
	appFolder := t.TempDir()
	for _, name := range []string{"schema.json", "threagile-example-model.yaml"} {
		if err := os.WriteFile(filepath.Join(appFolder, name), []byte("custom "+name), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	router := newStaticRouter(t, appFolder)

	for path, want := range map[string]string{
		"/schema.json":                  "custom schema.json",
		"/threagile-example-model.yaml": "custom threagile-example-model.yaml",
		"/openapi.yaml":                 string(threagile.OpenAPI.Bytes()),
	} {
		if got := get(t, router, path).Body.String(); got != want {
			t.Errorf("GET %v: got %.40q, want %.40q", path, got, want)
		}
	}
}
