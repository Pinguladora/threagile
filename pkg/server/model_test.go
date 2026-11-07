package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Pinguladora/threagile/pkg/input"
	"github.com/gin-gonic/gin"
)

// dataFolderConfig provides what the key, token and model routes read.
type dataFolderConfig struct {
	serverConfigReader
	dataFolder    string
	backupsToKeep int // 50 if not set
}

func (c dataFolderConfig) GetServerFolder() string   { return c.dataFolder }
func (c dataFolderConfig) GetDataFolder() string     { return c.dataFolder }
func (c dataFolderConfig) GetTempFolder() string     { return c.dataFolder }
func (dataFolderConfig) GetKeyFolder() string        { return "keys" }
func (dataFolderConfig) GetInputFile() string        { return "threagile.yaml" }
func (dataFolderConfig) GetThreagileVersion() string { return "1.0.0" }
func (dataFolderConfig) GetVerbose() bool            { return false }

func (c dataFolderConfig) GetBackupHistoryFilesToKeep() int {
	if c.backupsToKeep == 0 {
		return 50
	}
	return c.backupsToKeep
}

func newModelServer(t *testing.T) (*server, *gin.Engine) {
	t.Helper()

	gin.SetMode(gin.TestMode)
	s := &server{
		config:                      dataFolderConfig{dataFolder: t.TempDir()},
		createdObjectsThrottler:     make(map[string][]int64),
		mapTokenHashToTimeoutStruct: make(map[string]timeoutStruct),
		mapFolderNameToTokenHash:    make(map[string]string),
		locksByFolderName:           make(map[string]*sync.Mutex),
	}
	router := gin.New()
	s.addDirectRoutes(router)
	s.addModelRoutes(router)

	return s, router
}

// call sends a request with the given headers and returns the response, failing the test on any other status.
func call(
	t *testing.T, router *gin.Engine, method, path, body string, headers map[string]string, status int,
) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != status {
		t.Fatalf("%v %v: status %v, want %v, body %.300q", method, path, recorder.Code, status, recorder.Body.String())
	}

	return recorder
}

func field(t *testing.T, recorder *httptest.ResponseRecorder, name string) string {
	t.Helper()

	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	value, _ := body[name].(string)
	if value == "" {
		t.Fatalf("no %q in %.300q", name, recorder.Body.String())
	}

	return value
}

// newModel creates a key, a token and a model, and returns the token header and the model path.
func newModel(t *testing.T, router *gin.Engine) (map[string]string, string) {
	t.Helper()

	key := field(t, call(t, router, http.MethodPost, "/auth/keys", "", nil, http.StatusCreated), "key")
	token := field(t, call(t, router, http.MethodPost, "/auth/tokens", "", map[string]string{"key": key},
		http.StatusCreated), "token")
	headers := map[string]string{"token": token}
	id := field(t, call(t, router, http.MethodPost, "/models", "", headers, http.StatusCreated), "id")

	return headers, "/models/" + id
}

func TestNewModelCanBeReadBack(t *testing.T) {
	_, router := newModelServer(t)
	headers, model := newModel(t, router)

	if body := call(t, router, http.MethodGet, model, "", headers, http.StatusOK).Body.String(); !strings.Contains(
		body, "title: New Threat Model") {
		t.Errorf("GET %v: %.300q", model, body)
	}
	if title := field(t, call(t, router, http.MethodGet, model+"/cover", "", headers, http.StatusOK), "title"); title !=
		"New Threat Model" {
		t.Errorf("cover title %q", title)
	}
}

func TestUpdatesInTheSameSecondKeepTheirBackups(t *testing.T) {
	s, router := newModelServer(t)
	headers, model := newModel(t, router)

	for _, title := range []string{"First", "Second", "Third"} {
		call(t, router, http.MethodPut, model+"/cover", `{"title":"`+title+`"}`, headers, http.StatusOK)
	}

	if title := field(t, call(t, router, http.MethodGet, model+"/cover", "", headers, http.StatusOK), "title"); title !=
		"Third" {
		t.Errorf("cover title %q", title)
	}
	backups, err := filepath.Glob(filepath.Join(s.config.GetDataFolder(), "keys", "*", "*", "history", "*.backup"))
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 3 {
		t.Errorf("%v backups, want 3: %v", len(backups), backups)
	}
}

func TestUsingATokenKeepsItAlive(t *testing.T) {
	s, router := newModelServer(t)
	headers, model := newModel(t, router)

	idle := time.Now().Add(-20 * time.Minute).UnixNano()
	for hash, timeout := range s.mapTokenHashToTimeoutStruct {
		timeout.lastAccessedNanoTime = idle
		s.mapTokenHashToTimeoutStruct[hash] = timeout
	}
	call(t, router, http.MethodGet, model+"/cover", "", headers, http.StatusOK)

	for _, timeout := range s.mapTokenHashToTimeoutStruct {
		if timeout.lastAccessedNanoTime == idle {
			t.Error("the last access of the token was not updated")
		}
	}
}

func TestFolderLockIsExclusive(t *testing.T) {
	s, _ := newModelServer(t)
	folder := filepath.Join(s.config.GetDataFolder(), "keys", "a")
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatal(err)
	}

	var holders, overlaps atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			s.lockFolder(folder)
			defer s.unlockFolder(folder)
			if holders.Add(1) > 1 {
				overlaps.Add(1)
			}
			time.Sleep(time.Millisecond)
			holders.Add(-1)
		})
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the requests waiting on the folder lock deadlocked")
	}

	if overlaps.Load() > 0 {
		t.Errorf("%v times more than one request held the folder lock", overlaps.Load())
	}
}

func TestRemoveDataAssetReferencesLeavesNoGaps(t *testing.T) {
	modelInput := input.Model{TechnicalAssets: map[string]input.TechnicalAsset{
		"Web Server": {
			DataAssetsProcessed: []string{"customers", "orders", "customers"},
			DataAssetsStored:    []string{"orders"},
			CommunicationLinks: map[string]input.CommunicationLink{
				"Database": {DataAssetsSent: []string{"customers", "orders"}, DataAssetsReceived: []string{"customers"}},
			},
		},
	}}

	if !removeDataAssetReferences(&modelInput, "customers") {
		t.Error("no references reported as deleted")
	}

	asset := modelInput.TechnicalAssets["Web Server"]
	link := asset.CommunicationLinks["Database"]
	for name, got := range map[string][]string{
		"processed": asset.DataAssetsProcessed,
		"stored":    asset.DataAssetsStored,
		"sent":      link.DataAssetsSent,
	} {
		if !slices.Equal(got, []string{"orders"}) {
			t.Errorf("%v: %q, want [orders]", name, got)
		}
	}
	if len(link.DataAssetsReceived) != 0 {
		t.Errorf("received: %q, want none", link.DataAssetsReceived)
	}
}
