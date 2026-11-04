/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package server

import (
	"fmt"
	"html/template"
	"log"
	"maps"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/Pinguladora/threagile"
	"github.com/Pinguladora/threagile/pkg/model"
	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/gin-gonic/gin"
)

type serverConfigReader interface {
	GetBuildTimestamp() string
	GetVerbose() bool
	GetInteractive() bool
	GetAppFolder() string
	GetPluginFolder() string
	GetDataFolder() string
	GetOutputFolder() string
	GetServerFolder() string
	GetTempFolder() string
	GetKeyFolder() string
	GetInputFile() string
	GetImportedInputFile() string
	GetDataFlowDiagramFilenamePNG() string
	GetDataAssetDiagramFilenamePNG() string
	GetDataFlowDiagramFilenameDOT() string
	GetDataAssetDiagramFilenameDOT() string
	GetReportFilename() string
	GetReportHTMLFilename() string
	GetReportMarkdownFilename() string
	GetExcelRisksFilename() string
	GetRiskExcelConfigHideColumns() []string
	GetRiskExcelConfigSortByColumns() []string
	GetRiskExcelConfigWidthOfColumns() map[string]float64
	GetExcelTagsFilename() string
	GetJsonRisksFilename() string
	GetJsonTechnicalAssetsFilename() string
	GetJsonStatsFilename() string
	GetTemplateFilename() string
	GetTechnologyFilename() string
	GetRiskRulePlugins() []string
	GetSkipRiskRules() []string
	GetExecuteModelMacro() string
	GetServerMode() bool
	GetDiagramDPI() int
	GetServerPort() int
	GetGraphvizDPI() int
	GetMaxGraphvizDPI() int
	GetBackupHistoryFilesToKeep() int
	GetAddModelTitle() bool
	GetAddLegend() bool
	GetKeepDiagramSourceFiles() bool
	GetIgnoreOrphanedRiskTracking() bool
	GetThreagileVersion() string
	GetProgressReporter() types.ProgressReporter
}

type server struct {
	config                         serverConfigReader
	successCount                   int
	errorCount                     int
	globalLock                     sync.Mutex
	throttlerLock                  sync.Mutex
	createdObjectsThrottler        map[string][]int64
	mapTokenHashToTimeoutStruct    map[string]timeoutStruct
	mapFolderNameToTokenHash       map[string]string
	extremeShortTimeoutsForTesting bool
	locksByFolderName              map[string]*sync.Mutex
	builtinRiskRules               types.RiskRules
	customRiskRules                types.RiskRules
}

func RunServer(config serverConfigReader, builtinRiskRules types.RiskRules) {
	s := &server{
		config:                         config,
		createdObjectsThrottler:        make(map[string][]int64),
		mapTokenHashToTimeoutStruct:    make(map[string]timeoutStruct),
		mapFolderNameToTokenHash:       make(map[string]string),
		extremeShortTimeoutsForTesting: false,
		locksByFolderName:              make(map[string]*sync.Mutex),
		builtinRiskRules:               builtinRiskRules,
	}
	router := gin.Default()
	s.addStaticRoutes(router)
	s.addMetaRoutes(router, config)
	s.addDirectRoutes(router)
	s.addModelRoutes(router)

	s.customRiskRules = model.LoadCustomRiskRules(s.config.GetPluginFolder(), s.config.GetRiskRulePlugins(),
		config.GetProgressReporter())

	fmt.Println("Threagile is running...")
	// listen and serve on 0.0.0.0:8080 or whatever port was specified
	_ = router.Run(":" + strconv.Itoa(s.config.GetServerPort()))
}

func (s *server) addMetaRoutes(router *gin.Engine, config serverConfigReader) {
	router.GET("/meta/ping", func(c *gin.Context) {
		respondMessage(c, http.StatusOK, "pong", nil)
	})
	router.GET("/meta/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"version":         config.GetThreagileVersion(),
			"build_timestamp": s.config.GetBuildTimestamp(),
		})
	})
	router.GET("/meta/types", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"quantity":                     arrayOfStringValues(types.QuantityValues()),
			"confidentiality":              arrayOfStringValues(types.ConfidentialityValues()),
			"criticality":                  arrayOfStringValues(types.CriticalityValues()),
			"technical_asset_type":         arrayOfStringValues(types.TechnicalAssetTypeValues()),
			"technical_asset_size":         arrayOfStringValues(types.TechnicalAssetSizeValues()),
			"identity":                     arrayOfStringValues(types.IdentityValues()),
			"authorization":                arrayOfStringValues(types.AuthorizationValues()),
			"authentication":               arrayOfStringValues(types.AuthenticationValues()),
			"usage":                        arrayOfStringValues(types.UsageValues()),
			"encryption":                   arrayOfStringValues(types.EncryptionStyleValues()),
			"data_format":                  arrayOfStringValues(types.DataFormatValues()),
			"protocol":                     arrayOfStringValues(types.ProtocolValues()),
			"technical_asset_technology":   arrayOfStringValues(types.TechnicalAssetTechnologyValues(config)),
			"technical_asset_machine":      arrayOfStringValues(types.TechnicalAssetMachineValues()),
			"trust_boundary_type":          arrayOfStringValues(types.TrustBoundaryTypeValues()),
			"data_breach_probability":      arrayOfStringValues(types.DataBreachProbabilityValues()),
			"risk_severity":                arrayOfStringValues(types.RiskSeverityValues()),
			"risk_exploitation_likelihood": arrayOfStringValues(types.RiskExploitationLikelihoodValues()),
			"risk_exploitation_impact":     arrayOfStringValues(types.RiskExploitationImpactValues()),
			"risk_function":                arrayOfStringValues(types.RiskFunctionValues()),
			"risk_status":                  arrayOfStringValues(types.RiskStatusValues()),
			"stride":                       arrayOfStringValues(types.STRIDEValues()),
		})
	})

	// not served yet:
	// router.GET("/meta/risk-rules", listRiskRules)
	// router.GET("/meta/model-macros", listModelMacros)
}

// addDirectRoutes adds the stats and the routes that analyze a model without storing it, and those of the
// keys and tokens.
func (s *server) addDirectRoutes(router *gin.Engine) {
	router.GET("/meta/stats", s.stats)

	router.POST("/edit-model/analyze", s.editModelAnalyze)

	router.POST("/direct/analyze", s.analyze)
	router.POST("/direct/check", s.check)
	router.GET("/direct/stub", s.stubFile)

	router.POST("/auth/keys", s.createKey)
	router.DELETE("/auth/keys", s.deleteKey)
	router.POST("/auth/tokens", s.createToken)
	router.DELETE("/auth/tokens", s.deleteToken)
}

// addModelRoutes adds the routes of the models that the server stores.
func (s *server) addModelRoutes(router *gin.Engine) {
	router.POST("/models", s.createNewModel)
	router.GET("/models", s.listModels)
	router.DELETE("/models/:model-id", s.deleteModel)
	router.GET("/models/:model-id", s.getModel)
	router.PUT("/models/:model-id", s.importModel)
	router.GET("/models/:model-id/data-flow-diagram", s.streamDataFlowDiagram)
	router.GET("/models/:model-id/data-asset-diagram", s.streamDataAssetDiagram)
	router.GET("/models/:model-id/report-pdf", s.streamReportPDF)
	router.GET("/models/:model-id/risks-excel", s.streamRisksExcel)
	router.GET("/models/:model-id/tags-excel", s.streamTagsExcel)
	router.GET("/models/:model-id/risks", s.streamRisksJSON)
	router.GET("/models/:model-id/technical-assets", s.streamTechnicalAssetsJSON)
	router.GET("/models/:model-id/stats", s.streamStatsJSON)
	router.GET("/models/:model-id/analysis", s.analyzeModelOnServerDirectly)

	router.GET("/models/:model-id/cover", s.getCover)
	router.PUT("/models/:model-id/cover", s.setCover)
	router.GET("/models/:model-id/overview", s.getOverview)
	router.PUT("/models/:model-id/overview", s.setOverview)
	// router.GET("/models/:model-id/questions", getQuestions)
	// router.PUT("/models/:model-id/questions", setQuestions)
	router.GET("/models/:model-id/abuse-cases", s.getAbuseCases)
	router.PUT("/models/:model-id/abuse-cases", s.setAbuseCases)
	router.GET("/models/:model-id/security-requirements", s.getSecurityRequirements)
	router.PUT("/models/:model-id/security-requirements", s.setSecurityRequirements)
	// router.GET("/models/:model-id/tags", getTags)
	// router.PUT("/models/:model-id/tags", setTags)

	router.GET("/models/:model-id/data-assets", s.getDataAssets)
	router.POST("/models/:model-id/data-assets", s.createNewDataAsset)
	router.GET("/models/:model-id/data-assets/:data-asset-id", s.getDataAsset)
	router.PUT("/models/:model-id/data-assets/:data-asset-id", s.setDataAsset)
	router.DELETE("/models/:model-id/data-assets/:data-asset-id", s.deleteDataAsset)

	router.GET("/models/:model-id/trust-boundaries", s.getTrustBoundaries)
	//	router.POST("/models/:model-id/trust-boundaries", createNewTrustBoundary)
	//	router.GET("/models/:model-id/trust-boundaries/:trust-boundary-id", getTrustBoundary)
	//	router.PUT("/models/:model-id/trust-boundaries/:trust-boundary-id", setTrustBoundary)
	//	router.DELETE("/models/:model-id/trust-boundaries/:trust-boundary-id", deleteTrustBoundary)

	router.GET("/models/:model-id/shared-runtimes", s.getSharedRuntimes)
	router.POST("/models/:model-id/shared-runtimes", s.createNewSharedRuntime)
	router.GET("/models/:model-id/shared-runtimes/:shared-runtime-id", s.getSharedRuntime)
	router.PUT("/models/:model-id/shared-runtimes/:shared-runtime-id", s.setSharedRuntime)
	router.DELETE("/models/:model-id/shared-runtimes/:shared-runtime-id", s.deleteSharedRuntime)
}

// addStaticRoutes serves the web UI and the files from the app folder. The web
// UI always comes from the copy embedded in the binary (the server folder only
// holds run-time storage such as the keys). The app folder files prefer a copy
// in --app-dir and fall back to the embedded one.
func (s *server) addStaticRoutes(router *gin.Engine) {
	static := threagile.Static()
	router.SetHTMLTemplate(template.Must(template.ParseFS(static, "*.html")))
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{})
	})
	router.HEAD("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{})
	})
	router.GET("/edit-model", func(c *gin.Context) {
		c.HTML(http.StatusOK, "edit-model.html", gin.H{})
	})
	router.HEAD("/edit-model", func(c *gin.Context) {
		c.HTML(http.StatusOK, "edit-model.html", gin.H{})
	})

	for _, name := range []string{
		"css/edit-model.css", "js/edit-model.js", "js/property-editor.js", "js/schema.js",
		"threagile.png", "site.webmanifest", "favicon.ico", "favicon-32x32.png", "favicon-16x16.png",
		"apple-touch-icon.png", "android-chrome-512x512.png", "android-chrome-192x192.png",
	} {
		router.StaticFileFS("/"+name, name, http.FS(static))
	}

	for _, file := range []struct {
		name  string
		asset threagile.Asset
	}{
		{"schema.json", threagile.Schema},
		{"live-templates.txt", threagile.LiveTemplates},
		{"openapi.yaml", threagile.OpenAPI},
	} {
		router.GET("/"+file.name, s.appFile(file.asset, file.name))
		router.HEAD("/"+file.name, s.appFile(file.asset, file.name))
	}

	router.GET("/threagile-example-model.yaml", s.exampleFile)
	router.GET("/threagile-stub-model.yaml", s.stubFile)
}

// appFile serves the named file from the app folder, or the embedded asset when
// the folder does not hold it.
func (s *server) appFile(asset threagile.Asset, name string) gin.HandlerFunc {
	return func(ginContext *gin.Context) {
		data, err := asset.ReadFile(filepath.Join(s.config.GetAppFolder(), name))
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}

		contentType := mime.TypeByExtension(filepath.Ext(name))
		if contentType == "" {
			contentType = http.DetectContentType(data)
		}
		ginContext.Data(http.StatusOK, contentType, data)
	}
}

func (s *server) exampleFile(ginContext *gin.Context) {
	example, err := threagile.ExampleModel.ReadFile(filepath.Join(s.config.GetAppFolder(), "threagile-example-model.yaml"))
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	ginContext.Data(http.StatusOK, gin.MIMEYAML, example)
}

func (s *server) stubFile(ginContext *gin.Context) {
	stub, err := threagile.StubModel.ReadFile(filepath.Join(s.config.GetAppFolder(), "threagile-stub-model.yaml"))
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	// the model export serves its YAML as a file attachment instead of this way
	ginContext.Data(http.StatusOK, gin.MIMEYAML, s.addSupportedTags(stub))
}

func (s *server) addSupportedTags(input []byte) []byte {
	// add distinct tags as "tags_available"
	supportedTags := make(map[string]bool)
	for _, customRule := range s.customRiskRules {
		for _, tag := range customRule.SupportedTags() {
			supportedTags[strings.ToLower(tag)] = true
		}
	}

	for _, rule := range s.builtinRiskRules {
		for _, tag := range rule.SupportedTags() {
			supportedTags[strings.ToLower(tag)] = true
		}
	}

	tags := make([]string, 0, len(supportedTags))
	for t := range supportedTags {
		tags = append(tags, t)
	}
	if len(tags) == 0 {
		return input
	}
	sort.Strings(tags)
	if s.config.GetVerbose() {
		printSupportedTags(tags)
	}
	replacement := "tags_available:"
	for _, tag := range tags {
		replacement += "\n  - " + tag
	}
	return []byte(strings.Replace(string(input), "tags_available:", replacement, 1))
}

func printSupportedTags(tags []string) {
	fmt.Print("Supported tags of all risk rules: ")
	for i, tag := range tags {
		if i > 0 {
			fmt.Print(", ")
		}
		fmt.Print(tag)
	}
	fmt.Println()
}

func arrayOfStringValues(values []types.TypeEnum) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.String())
	}
	return result
}

// The lengths of the names of the key folders (hex SHA-512 hashes) and the model folders (UUIDs).
const (
	sha512HexLength = 128
	uuidLength      = 36
)

func (s *server) stats(ginContext *gin.Context) {
	keyCount, modelCount := 0, 0
	keyFolders, err := os.ReadDir(filepath.Join(s.config.GetServerFolder(), s.config.GetKeyFolder()))
	if err != nil {
		log.Println(err)
		respondError(ginContext, http.StatusInternalServerError, "unable to collect stats")
		return
	}
	for _, keyFolder := range keyFolders {
		// it's a sha512 token hash probably, so count it as token folder for the stats
		if len(keyFolder.Name()) == sha512HexLength {
			keyCount++
			if keyFolder.Name() != filepath.Clean(keyFolder.Name()) {
				respondError(ginContext, http.StatusInternalServerError, "weird file path")
				return
			}
			modelFolders, err := os.ReadDir(filepath.Join(s.config.GetServerFolder(), s.config.GetKeyFolder(), keyFolder.Name()))
			if err != nil {
				log.Println(err)
				respondError(ginContext, http.StatusInternalServerError, "unable to collect stats")
				return
			}
			for _, modelFolder := range modelFolders {
				// it's a uuid model folder probably, so count it as model folder for the stats
				if len(modelFolder.Name()) == uuidLength {
					modelCount++
				}
			}
		}
	}
	// the stats could also count old models and tell about the health of the server
	ginContext.JSON(http.StatusOK, gin.H{
		"key_count":     keyCount,
		"model_count":   modelCount,
		"success_count": s.successCount,
		"error_count":   s.errorCount,
	})
}

func handleErrorInServiceCall(err error, ginContext *gin.Context) {
	log.Println(err)
	respondError(ginContext, http.StatusBadRequest, strings.TrimSpace(err.Error()))
}

// panicError is the error a handler panicked with. A panic with anything else goes on to the recovery of
// gin, as the unchecked assertion to error made it do before.
func panicError(r any) error {
	err, isError := r.(error)
	if !isError {
		panic(r)
	}
	return err
}

// respondError answers a request with an error.
func respondError(ginContext *gin.Context, status int, message string) {
	ginContext.JSON(status, gin.H{
		"error": message,
	})
}

// respondMessage answers a request with a message and the given fields, if any.
func respondMessage(ginContext *gin.Context, status int, message string, fields gin.H) {
	response := gin.H{
		"message": message,
	}
	maps.Copy(response, fields)
	ginContext.JSON(status, response)
}
