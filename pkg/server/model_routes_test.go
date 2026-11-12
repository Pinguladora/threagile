package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Pinguladora/threagile/pkg/input"
	"github.com/gin-gonic/gin"
	"go.yaml.in/yaml/v4"
)

// shopModel is a model with references to its data assets and shared runtimes from every place that can hold one.
const shopModel = `title: Shop
technical_assets:
  Web Server:
    id: web-server
    data_assets_processed: [customers, orders]
    data_assets_stored: [customers]
    communication_links:
      Database Access:
        target: database
        data_assets_sent: [customers]
        data_assets_received: [orders]
  Database:
    id: database
    data_assets_stored: [customers, orders]
data_assets:
  Customers:
    id: customers
    usage: business
    quantity: many
    confidentiality: confidential
    integrity: critical
    availability: important
  Orders:
    id: orders
    usage: business
    quantity: many
    confidentiality: internal
    integrity: important
    availability: important
shared_runtimes:
  Node Pool:
    id: node-pool
    technical_assets_running: [web-server]
custom_risk_categories:
  - id: something-strange
    title: Something Strange
    risks_identified:
      Leak at the Node Pool:
        most_relevant_data_asset: customers
        most_relevant_shared_runtime: node-pool
`

const customersPayload = `{"title":"Customers","id":"customers","usage":"business","quantity":"many",` +
	`"confidentiality":"confidential","integrity":"critical","availability":"important"}`

// seedModel replaces the content of a model, as an import would without analyzing it first.
func seedModel(t *testing.T, s *server, headers map[string]string, model string, yamlText string) {
	t.Helper()

	ginContext, _ := gin.CreateTestContext(httptest.NewRecorder())
	ginContext.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPut, model, http.NoBody)
	for name, value := range headers {
		ginContext.Request.Header.Set(name, value)
	}
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		t.Fatal("token not found")
	}
	if !s.writeModelYAML(ginContext, yamlText, key, folderNameForModel(folderNameOfKey, path.Base(model)), "", true) {
		t.Fatal("unable to write the model")
	}
}

// readBack reads the model as a client downloads it.
func readBack(t *testing.T, router *gin.Engine, headers map[string]string, model string) input.Model {
	t.Helper()

	modelInput := input.Model{}
	body := call(t, router, http.MethodGet, model, "", headers, http.StatusOK).Body.Bytes()
	if err := yaml.Unmarshal(body, &modelInput); err != nil {
		t.Fatal(err)
	}

	return modelInput
}

func decode[T any](t *testing.T, recorder *httptest.ResponseRecorder) T {
	t.Helper()

	var value T
	if err := json.Unmarshal(recorder.Body.Bytes(), &value); err != nil {
		t.Fatalf("%v in %.300q", err, recorder.Body.String())
	}

	return value
}

// individualRisk is the one risk of shopModel.
func individualRisk(t *testing.T, modelInput input.Model) input.RiskIdentified {
	t.Helper()

	if len(modelInput.CustomRiskCategories) != 1 {
		t.Fatalf("%v custom risk categories, want 1", len(modelInput.CustomRiskCategories))
	}

	return modelInput.CustomRiskCategories[0].RisksIdentified["Leak at the Node Pool"]
}

func TestModelRoutesNeedTheTokenOfTheirKey(t *testing.T) {
	_, router := newModelServer(t)
	headers, model := newModel(t, router)
	otherHeaders, _ := newModel(t, router)

	for name, tokenHeaders := range map[string]map[string]string{
		"no token":            nil,
		"no valid token":      {"token": base64.RawURLEncoding.EncodeToString([]byte("not a token"))},
		"the token of a key":  otherHeaders,
		"a token not encoded": {"token": "%%%"},
	} {
		t.Run(name, func(t *testing.T) {
			call(t, router, http.MethodGet, model+"/cover", "", tokenHeaders, http.StatusNotFound)
			call(t, router, http.MethodDelete, model, "", tokenHeaders, http.StatusNotFound)
		})
	}
	for _, id := range []string{"not-a-uuid", "00000000-0000-4000-8000-000000000000", ".."} {
		call(t, router, http.MethodGet, "/models/"+id+"/cover", "", headers, http.StatusNotFound)
	}
	call(t, router, http.MethodGet, model+"/cover", "", headers, http.StatusOK)
}

func TestListAndDeleteModels(t *testing.T) {
	_, router := newModelServer(t)
	headers, first := newModel(t, router)
	second := "/models/" + field(t, call(t, router, http.MethodPost, "/models", "", headers, http.StatusCreated), "id")
	call(t, router, http.MethodPut, second+"/cover", `{"title":"Second"}`, headers, http.StatusOK)

	titles := func() []string {
		models := decode[[]payloadModels](t, call(t, router, http.MethodGet, "/models", "", headers, http.StatusOK))
		titles := make([]string, 0, len(models))
		for _, listed := range models {
			if listed.TimestampCreated.IsZero() || listed.TimestampModified.IsZero() {
				t.Errorf("model %v without timestamps", listed.ID)
			}
			titles = append(titles, listed.Title)
		}
		slices.Sort(titles)
		return titles
	}
	if got := titles(); !slices.Equal(got, []string{"New Threat Model", "Second"}) {
		t.Errorf("models %q", got)
	}

	call(t, router, http.MethodDelete, first, "", headers, http.StatusOK)

	if got := titles(); !slices.Equal(got, []string{"Second"}) {
		t.Errorf("models after the deletion %q", got)
	}
	call(t, router, http.MethodGet, first, "", headers, http.StatusNotFound)
	call(t, router, http.MethodDelete, first, "", headers, http.StatusNotFound)
}

func TestCoverKeepsItsDateWhenNoneIsGiven(t *testing.T) {
	_, router := newModelServer(t)
	headers, model := newModel(t, router)

	call(t, router, http.MethodPut, model+"/cover",
		`{"title":"Shop","date":"2026-11-07T00:00:00Z","author":{"name":"Security Team","homepage":"https://example.com"}}`,
		headers, http.StatusOK)
	call(t, router, http.MethodPut, model+"/cover", `{"title":"Web Shop"}`, headers, http.StatusOK)
	call(t, router, http.MethodPut, model+"/cover", `{"title":`, headers, http.StatusBadRequest)

	cover := decode[map[string]any](t, call(t, router, http.MethodGet, model+"/cover", "", headers, http.StatusOK))
	if cover["title"] != "Web Shop" || cover["date"] != "2026-11-07" {
		t.Errorf("cover %v", cover)
	}
	if author, _ := cover["author"].(map[string]any); len(author) != 0 {
		t.Errorf("author %v, want it cleared as the payload had none", author)
	}
}

func TestOverviewTakesOnlyKnownCriticalities(t *testing.T) {
	_, router := newModelServer(t)
	headers, model := newModel(t, router)

	call(t, router, http.MethodPut, model+"/overview", `{"management_summary_comment":"Reviewed",`+
		`"business_criticality":"important","business_overview":{"description":"Sells things"},`+
		`"technical_overview":{"description":"Runs on a cluster"}}`, headers, http.StatusOK)
	call(t, router, http.MethodPut, model+"/overview", `{"business_criticality":"extreme"}`, headers,
		http.StatusBadRequest)

	overview := decode[payloadOverview](t, call(t, router, http.MethodGet, model+"/overview", "", headers,
		http.StatusOK))
	if overview.BusinessCriticality != "important" || overview.ManagementSummaryComment != "Reviewed" ||
		overview.BusinessOverview.Description != "Sells things" ||
		overview.TechnicalOverview.Description != "Runs on a cluster" {
		t.Errorf("overview %+v", overview)
	}
}

func TestAbuseCasesAndSecurityRequirementsAreReplacedAsAWhole(t *testing.T) {
	_, router := newModelServer(t)
	headers, model := newModel(t, router)

	for _, route := range []string{"/abuse-cases", "/security-requirements"} {
		t.Run(route, func(t *testing.T) {
			call(t, router, http.MethodPut, model+route, `{"First":"one","Second":"two"}`, headers, http.StatusOK)
			call(t, router, http.MethodPut, model+route, `{"Third":"three"}`, headers, http.StatusOK)
			call(t, router, http.MethodPut, model+route, `["not a map"]`, headers, http.StatusBadRequest)

			got := decode[map[string]string](t, call(t, router, http.MethodGet, model+route, "", headers,
				http.StatusOK))
			if len(got) != 1 || got["Third"] != "three" {
				t.Errorf("%v %v", route, got)
			}
		})
	}
}

func TestDataAssetLifecycle(t *testing.T) {
	_, router := newModelServer(t)
	headers, model := newModel(t, router)
	assets := model + "/data-assets"

	created := call(t, router, http.MethodPost, assets, strings.Replace(customersPayload, `"usage"`,
		`"tags":[" Billing ","Shop"],"usage"`, 1), headers, http.StatusOK)
	if id := field(t, created, "id"); id != "customers" {
		t.Errorf("created %q", id)
	}
	call(t, router, http.MethodPost, assets, customersPayload, headers, http.StatusConflict)
	call(t, router, http.MethodPost, assets, strings.Replace(customersPayload, `"Customers"`, `"Clients"`, 1), headers,
		http.StatusConflict)
	call(t, router, http.MethodPost, assets, strings.NewReplacer(`"Customers"`, `"Orders"`, `"customers"`, `"orders"`,
		`"confidential"`, `"secret-ish"`).Replace(customersPayload), headers, http.StatusBadRequest)
	call(t, router, http.MethodPost, assets, `{`, headers, http.StatusBadRequest)

	got := decode[map[string]input.DataAsset](t, call(t, router, http.MethodGet, assets+"/customers", "", headers,
		http.StatusOK))
	customers, ok := got["Customers"]
	if !ok || customers.Confidentiality != "confidential" || customers.Integrity != "critical" ||
		!slices.Equal(customers.Tags, []string{"billing", "shop"}) {
		t.Errorf("data asset %+v", got)
	}
	if all := decode[map[string]input.DataAsset](t, call(t, router, http.MethodGet, assets, "", headers,
		http.StatusOK)); len(all) != 1 {
		t.Errorf("data assets %+v", all)
	}

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		call(t, router, method, assets+"/unknown", customersPayload, headers, http.StatusNotFound)
	}
	call(t, router, http.MethodPut, assets+"/customers", `{`, headers, http.StatusBadRequest)
	call(t, router, http.MethodPut, assets+"/customers", strings.Replace(customersPayload, `"many"`, `"lots"`, 1),
		headers, http.StatusBadRequest)
}

func TestChangingTheIDOfADataAssetUpdatesItsReferences(t *testing.T) {
	s, router := newModelServer(t)
	headers, model := newModel(t, router)
	seedModel(t, s, headers, model, shopModel)

	renamed := call(t, router, http.MethodPut, model+"/data-assets/customers", strings.NewReplacer(
		`"Customers"`, `"Clients"`, `"customers"`, `"clients"`).Replace(customersPayload), headers, http.StatusOK)
	if changed := decode[map[string]any](t, renamed)["id_changed"]; changed != true {
		t.Errorf("id_changed %v", changed)
	}

	modelInput := readBack(t, router, headers, model)
	if _, ok := modelInput.DataAssets["Customers"]; ok || modelInput.DataAssets["Clients"].ID != "clients" {
		t.Errorf("data assets %+v", modelInput.DataAssets)
	}
	webServer := modelInput.TechnicalAssets["Web Server"]
	link := webServer.CommunicationLinks["Database Access"]
	for name, got := range map[string][]string{
		"processed":          webServer.DataAssetsProcessed,
		"stored":             webServer.DataAssetsStored,
		"sent":               link.DataAssetsSent,
		"received":           link.DataAssetsReceived,
		"stored by database": modelInput.TechnicalAssets["Database"].DataAssetsStored,
	} {
		if slices.Contains(got, "customers") || !slices.Contains(got, "clients") && name != "received" {
			t.Errorf("%v: %q", name, got)
		}
	}
	if risk := individualRisk(t, modelInput); risk.MostRelevantDataAsset != "clients" {
		t.Errorf("individual risk %+v", risk)
	}

	retitled := call(t, router, http.MethodPut, model+"/data-assets/clients", strings.Replace(customersPayload,
		`"customers"`, `"clients"`, 1), headers, http.StatusOK)
	if changed := decode[map[string]any](t, retitled)["id_changed"]; changed != false {
		t.Errorf("id_changed %v for a new title only", changed)
	}
}

func TestDeletingADataAssetRemovesItsReferences(t *testing.T) {
	s, router := newModelServer(t)
	headers, model := newModel(t, router)
	seedModel(t, s, headers, model, shopModel)

	deleted := call(t, router, http.MethodDelete, model+"/data-assets/customers", "", headers, http.StatusOK)
	if references := decode[map[string]any](t, deleted)["references_deleted"]; references != true {
		t.Errorf("references_deleted %v", references)
	}

	modelInput := readBack(t, router, headers, model)
	if _, ok := modelInput.DataAssets["Customers"]; ok || len(modelInput.DataAssets) != 1 {
		t.Errorf("data assets %+v", modelInput.DataAssets)
	}
	webServer := modelInput.TechnicalAssets["Web Server"]
	if slices.Contains(webServer.DataAssetsProcessed, "customers") || len(webServer.DataAssetsStored) != 0 ||
		len(webServer.CommunicationLinks["Database Access"].DataAssetsSent) != 0 {
		t.Errorf("web server %+v", webServer)
	}
	if risk := individualRisk(t, modelInput); risk.MostRelevantDataAsset != "" {
		t.Errorf("individual risk %+v", risk)
	}
}

func TestSharedRuntimeLifecycle(t *testing.T) {
	s, router := newModelServer(t)
	headers, model := newModel(t, router)
	seedModel(t, s, headers, model, shopModel)
	runtimes := model + "/shared-runtimes"
	batch := `{"title":"Batch","id":"batch","tags":[" Nightly "],"technical_assets_running":["database"]}`

	call(t, router, http.MethodPost, runtimes, batch, headers, http.StatusOK)
	call(t, router, http.MethodPost, runtimes, batch, headers, http.StatusConflict)
	call(t, router, http.MethodPost, runtimes, strings.Replace(batch, `"Batch"`, `"Jobs"`, 1), headers,
		http.StatusConflict)
	call(t, router, http.MethodPost, runtimes, `{"title":"Jobs","id":"jobs","technical_assets_running":["unknown"]}`,
		headers, http.StatusBadRequest)
	call(t, router, http.MethodPost, runtimes, `{`, headers, http.StatusBadRequest)

	got := decode[map[string]input.SharedRuntime](t, call(t, router, http.MethodGet, runtimes+"/batch", "", headers,
		http.StatusOK))
	if !slices.Equal(got["Batch"].Tags, []string{"nightly"}) {
		t.Errorf("shared runtime %+v", got)
	}
	if all := decode[map[string]input.SharedRuntime](t, call(t, router, http.MethodGet, runtimes, "", headers,
		http.StatusOK)); len(all) != 2 {
		t.Errorf("shared runtimes %+v", all)
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		call(t, router, method, runtimes+"/unknown", batch, headers, http.StatusNotFound)
	}

	renamed := call(t, router, http.MethodPut, runtimes+"/node-pool",
		`{"title":"Web Pool","id":"web-pool","technical_assets_running":["web-server"]}`, headers, http.StatusOK)
	if changed := decode[map[string]any](t, renamed)["id_changed"]; changed != true {
		t.Errorf("id_changed %v", changed)
	}
	if risk := individualRisk(t, readBack(t, router, headers, model)); risk.MostRelevantSharedRuntime != "web-pool" {
		t.Errorf("individual risk after the change of the id %+v", risk)
	}

	deleted := call(t, router, http.MethodDelete, runtimes+"/web-pool", "", headers, http.StatusOK)
	if references := decode[map[string]any](t, deleted)["references_deleted"]; references != true {
		t.Errorf("references_deleted %v", references)
	}
	modelInput := readBack(t, router, headers, model)
	if _, ok := modelInput.SharedRuntimes["Web Pool"]; ok || len(modelInput.SharedRuntimes) != 1 {
		t.Errorf("shared runtimes %+v", modelInput.SharedRuntimes)
	}
	if risk := individualRisk(t, modelInput); risk.MostRelevantSharedRuntime != "" {
		t.Errorf("individual risk after the deletion %+v", risk)
	}
}

func TestTrustBoundariesAreListed(t *testing.T) {
	s, router := newModelServer(t)
	headers, model := newModel(t, router)
	seedModel(t, s, headers, model, shopModel+`trust_boundaries:
  Cluster:
    id: cluster
    type: execution-environment
    technical_assets_inside: [web-server, database]
`)

	got := decode[map[string]input.TrustBoundary](t, call(t, router, http.MethodGet, model+"/trust-boundaries", "",
		headers, http.StatusOK))
	if cluster := got["Cluster"]; cluster.ID != "cluster" || len(cluster.TechnicalAssetsInside) != 2 {
		t.Errorf("trust boundaries %+v", got)
	}
}

func TestBackupHistoryKeepsTheNewest(t *testing.T) {
	s, router := newModelServer(t)
	s.config = dataFolderConfig{dataFolder: s.config.GetDataFolder(), backupsToKeep: 2}
	headers, model := newModel(t, router)

	backups := func() []string {
		names, err := filepath.Glob(filepath.Join(s.config.GetDataFolder(), "keys", "*", "*", "history", "*.backup"))
		if err != nil {
			t.Fatal(err)
		}
		return names
	}
	made := make([]string, 0)
	for _, title := range []string{"First", "Second", "Third", "Fourth"} {
		before := backups()
		call(t, router, http.MethodPut, model+"/cover", `{"title":"`+title+`"}`, headers, http.StatusOK)
		for _, name := range backups() {
			if !slices.Contains(before, name) {
				made = append(made, name)
			}
		}
	}

	if got := backups(); len(made) != 4 || !slices.Equal(got, made[2:]) {
		t.Errorf("backups %q, want the newest two of %q", got, made)
	}
	if !strings.HasSuffix(made[0], " Cover Update.backup") {
		t.Errorf("backup %q is not named after the change", made[0])
	}
}

func TestUpdatingADataAssetKeepsTheOthers(t *testing.T) {
	s, router := newModelServer(t)
	headers, model := newModel(t, router)
	seedModel(t, s, headers, model, shopModel)

	call(t, router, http.MethodPut, model+"/data-assets/customers", strings.Replace(customersPayload, `"Customers"`,
		`"Orders"`, 1), headers, http.StatusConflict)
	call(t, router, http.MethodPut, model+"/data-assets/customers", strings.Replace(customersPayload, `"customers"`,
		`"orders"`, 1), headers, http.StatusConflict)

	modelInput := readBack(t, router, headers, model)
	if modelInput.DataAssets["Customers"].ID != "customers" || modelInput.DataAssets["Orders"].ID != "orders" {
		t.Errorf("data assets %+v", modelInput.DataAssets)
	}
}

func TestUpdatingASharedRuntimeKeepsTheOthers(t *testing.T) {
	s, router := newModelServer(t)
	headers, model := newModel(t, router)
	seedModel(t, s, headers, model, shopModel)
	runtimes := model + "/shared-runtimes"
	call(t, router, http.MethodPost, runtimes, `{"title":"Batch","id":"batch","technical_assets_running":["database"]}`,
		headers, http.StatusOK)

	call(t, router, http.MethodPut, runtimes+"/node-pool", `{"title":"Batch","id":"node-pool"}`, headers,
		http.StatusConflict)
	call(t, router, http.MethodPut, runtimes+"/node-pool", `{"title":"Node Pool","id":"batch"}`, headers,
		http.StatusConflict)
	call(t, router, http.MethodPut, runtimes+"/node-pool",
		`{"title":"Node Pool","id":"node-pool","technical_assets_running":["unknown"]}`, headers, http.StatusBadRequest)

	modelInput := readBack(t, router, headers, model)
	if modelInput.SharedRuntimes["Node Pool"].ID != "node-pool" || modelInput.SharedRuntimes["Batch"].ID != "batch" ||
		!slices.Equal(modelInput.SharedRuntimes["Node Pool"].TechnicalAssetsRunning, []string{"web-server"}) {
		t.Errorf("shared runtimes %+v", modelInput.SharedRuntimes)
	}
}

func TestATruncatedModelFileIsAnError(t *testing.T) {
	s, router := newModelServer(t)
	headers, model := newModel(t, router)
	files, err := filepath.Glob(filepath.Join(s.config.GetDataFolder(), "keys", "*", path.Base(model), "threagile.yaml"))
	if err != nil || len(files) != 1 {
		t.Fatalf("model files %q: %v", files, err)
	}
	if err := os.WriteFile(files[0], []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}

	call(t, router, http.MethodGet, model+"/cover", "", headers, http.StatusInternalServerError)
}
