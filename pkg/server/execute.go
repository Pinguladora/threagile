/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/Pinguladora/threagile/pkg/input"
	"github.com/Pinguladora/threagile/pkg/model"
	"github.com/Pinguladora/threagile/pkg/risks"
	"github.com/gin-gonic/gin"
)

func (s *server) analyze(ginContext *gin.Context) {
	s.execute(ginContext, false)
}

func (s *server) check(ginContext *gin.Context) {
	_, ok := s.execute(ginContext, true)
	if ok {
		respondMessage(ginContext, http.StatusOK, "model is ok", nil)
	}
}

// maxModelUploadSize is the size in bytes of the largest model that the server accepts.
const maxModelUploadSize = 50000000

// dryRunDPI is the DPI of the diagrams of a dry run.
const dryRunDPI = 40

func (s *server) execute(ginContext *gin.Context, dryRun bool) (yamlContent []byte, ok bool) {
	defer func() {
		var err error
		if r := recover(); r != nil {
			s.errorCount++
			err = panicError(r)
			log.Println(err)
			respondError(ginContext, http.StatusBadRequest, strings.TrimSpace(err.Error()))
			ok = false
		}
	}()

	dpi, err := strconv.Atoi(ginContext.DefaultQuery("dpi", strconv.Itoa(s.config.GetGraphvizDPI())))
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return yamlContent, false
	}

	files := new(temporaryFiles)
	defer files.remove()

	yamlFile, ok := s.saveUploadedModel(ginContext, files)
	if !ok {
		return yamlContent, false
	}

	tmpOutputDir, tmpResultFile, ok := s.createResultFiles(ginContext, files)
	if !ok {
		return yamlContent, false
	}

	if dryRun {
		s.doItViaRuntimeCall(yamlFile, tmpOutputDir, analysisOutputs{
			risksJSON: true, technicalAssetsJSON: true, statsJSON: true,
		}, dryRunDPI)
	} else {
		s.doItViaRuntimeCall(yamlFile, tmpOutputDir, allAnalysisOutputs, dpi)
	}

	yamlContent, ok = s.copyModelToOutput(ginContext, yamlFile, tmpOutputDir)
	if !ok {
		return yamlContent, false
	}

	if !dryRun && !s.streamAnalysisResult(ginContext, tmpOutputDir, tmpResultFile) {
		return yamlContent, false
	}
	s.successCount++
	return yamlContent, true
}

// copyModelToOutput copies the analyzed model into the output folder and returns it.
func (s *server) copyModelToOutput(ginContext *gin.Context, yamlFile string, tmpOutputDir string) ([]byte, bool) {
	yamlContent, err := os.ReadFile(filepath.Clean(yamlFile))
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return yamlContent, false
	}
	inputFile := filepath.Clean(filepath.Join(tmpOutputDir, s.config.GetInputFile()))
	err = os.WriteFile(inputFile, yamlContent, 0o400) // #nosec G703
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return yamlContent, false
	}
	return yamlContent, true
}

// streamAnalysisResult packs the result files of the analysis of an uploaded model and streams them back.
func (s *server) streamAnalysisResult(ginContext *gin.Context, tmpOutputDir string, tmpResultFile string) bool {
	resultFiles := s.resultFiles(tmpOutputDir)
	if s.config.GetKeepDiagramSourceFiles() {
		resultFiles = append(resultFiles, filepath.Join(tmpOutputDir, s.config.GetDataAssetDiagramFilenamePNG()))
		resultFiles = append(resultFiles, filepath.Join(tmpOutputDir, s.config.GetDataAssetDiagramFilenameDOT()))
	}
	if !zipResult(ginContext, tmpResultFile, resultFiles) {
		return false
	}
	if s.config.GetVerbose() {
		log.Println("Streaming back result file: " + tmpResultFile)
	}
	ginContext.FileAttachment(tmpResultFile, "threagile-result.zip")
	return true
}

// temporaryFiles removes the temporary files and folders of a request, in the reverse order of their
// creation.
type temporaryFiles struct {
	removals []func()
}

func (files *temporaryFiles) add(removal func()) {
	files.removals = append(files.removals, removal)
}

func (files *temporaryFiles) remove() {
	for _, removal := range slices.Backward(files.removals) {
		removal()
	}
}

// saveUploadedModel saves the uploaded model file, and unpacks it if it is an archive; it returns the
// model YAML file.
func (s *server) saveUploadedModel(ginContext *gin.Context, files *temporaryFiles) (string, bool) {
	fileUploaded, header, err := ginContext.Request.FormFile("file")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return "", false
	}

	if header.Size > maxModelUploadSize {
		msg := "maximum model upload file size exceeded (denial-of-service protection)"
		log.Println(msg)
		respondError(ginContext, http.StatusRequestEntityTooLarge, msg)
		return "", false
	}

	filenameUploaded := strings.TrimSpace(header.Filename)

	tmpInputDir, err := os.MkdirTemp(s.config.GetTempFolder(), "threagile-input-")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return "", false
	}
	files.add(func() { _ = os.RemoveAll(tmpInputDir) })

	tmpModelFile, err := os.CreateTemp(tmpInputDir, "threagile-model-*")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return "", false
	}
	files.add(func() { _ = os.Remove(tmpModelFile.Name()) })
	_, err = io.Copy(tmpModelFile, fileUploaded)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return "", false
	}

	if strings.ToLower(filepath.Ext(filenameUploaded)) == ".zip" {
		return s.unzipUploadedModel(ginContext, tmpModelFile.Name(), tmpInputDir)
	}
	return tmpModelFile.Name(), true
}

// unzipUploadedModel unpacks an uploaded archive (including the resources like images etc.) and returns
// its first YAML file.
func (s *server) unzipUploadedModel(ginContext *gin.Context, archive string, tmpInputDir string) (string, bool) {
	if s.config.GetVerbose() {
		fmt.Println("Decompressing uploaded archive")
	}
	filenamesUnzipped, err := unzip(archive, tmpInputDir)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return "", false
	}
	for _, name := range filenamesUnzipped {
		if strings.ToLower(filepath.Ext(name)) == ".yaml" {
			return name, true
		}
	}
	panic(errors.New("no yaml file found in uploaded archive"))
}

// createResultFiles creates the temporary output folder and result archive of an analysis.
func (s *server) createResultFiles(ginContext *gin.Context, files *temporaryFiles) (string, string, bool) {
	tmpOutputDir, err := os.MkdirTemp(s.config.GetTempFolder(), "threagile-output-")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return "", "", false
	}
	files.add(func() { _ = os.RemoveAll(tmpOutputDir) })

	tmpResultFile, err := os.CreateTemp(s.config.GetTempFolder(), "threagile-result-*.zip")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return "", "", false
	}
	files.add(func() { _ = os.Remove(tmpResultFile.Name()) })
	return tmpOutputDir, tmpResultFile.Name(), true
}

// resultFiles are the files in the output folder of an analysis that its result archive holds.
func (s *server) resultFiles(tmpOutputDir string) []string {
	return []string{
		filepath.Join(tmpOutputDir, s.config.GetInputFile()),
		filepath.Join(tmpOutputDir, s.config.GetDataFlowDiagramFilenamePNG()),
		filepath.Join(tmpOutputDir, s.config.GetDataAssetDiagramFilenamePNG()),
		filepath.Join(tmpOutputDir, s.config.GetReportFilename()),
		filepath.Join(tmpOutputDir, s.config.GetReportHTMLFilename()),
		filepath.Join(tmpOutputDir, s.config.GetReportMarkdownFilename()),
		filepath.Join(tmpOutputDir, s.config.GetExcelRisksFilename()),
		filepath.Join(tmpOutputDir, s.config.GetExcelTagsFilename()),
		filepath.Join(tmpOutputDir, s.config.GetJsonRisksFilename()),
		filepath.Join(tmpOutputDir, s.config.GetJsonTechnicalAssetsFilename()),
		filepath.Join(tmpOutputDir, s.config.GetJsonStatsFilename()),
	}
}

// zipResult packs the result files of an analysis into its result archive.
func zipResult(ginContext *gin.Context, tmpResultFile string, resultFiles []string) bool {
	err := zipFiles(tmpResultFile, resultFiles)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return false
	}
	return true
}

// analysisOutputs are the outputs that an analysis generates.
type analysisOutputs struct {
	dataFlowDiagram, dataAssetDiagram, reportPDF, risksExcel, tagsExcel bool
	risksJSON, technicalAssetsJSON, statsJSON                           bool
}

var allAnalysisOutputs = analysisOutputs{
	dataFlowDiagram: true, dataAssetDiagram: true, reportPDF: true, risksExcel: true, tagsExcel: true,
	risksJSON: true, technicalAssetsJSON: true, statsJSON: true,
}

// ultimately to avoid any in-process memory and/or data leaks by the used third party libs like PDF
// generation: exec and quit.
func (s *server) doItViaRuntimeCall(modelFile string, outputDir string, outputs analysisOutputs, dpi int) {
	// Remember to also add the same args to the exec based sub-process calls!
	var cmd *exec.Cmd
	args := []string{
		"analyze-model",
		"--model", modelFile,
		"--output", outputDir,
		"--execute-model-macro", s.config.GetExecuteModelMacro(),
		"--custom-risk-rules-plugin", strings.Join(s.config.GetRiskRulePlugins(), ","),
		"--skip-risk-rules", strings.Join(s.config.GetSkipRiskRules(), ","),
		"--diagram-dpi", strconv.Itoa(dpi),
	}
	for _, option := range []struct {
		given bool
		arg   string
	}{
		{s.config.GetVerbose(), "--verbose"},
		// the outer level has these options as variables too, yet they go to the analysis as arguments
		{s.config.GetIgnoreOrphanedRiskTracking(), "--ignore-orphaned-risk-tracking"},
		{outputs.dataFlowDiagram, "--generate-data-flow-diagram"},
		{outputs.dataAssetDiagram, "--generate-data-asset-diagram"},
		{outputs.reportPDF, "--generate-report-pdf"},
		{outputs.risksExcel, "--generate-risks-excel"},
		{outputs.tagsExcel, "--generate-tags-excel"},
		{outputs.risksJSON, "--generate-risks-json"},
		{outputs.technicalAssetsJSON, "--generate-technical-assets-json"},
		{outputs.statsJSON, "--generate-stats-json"},
	} {
		if option.given {
			args = append(args, option.arg)
		}
	}
	self, nameError := os.Executable()
	if nameError != nil {
		panic(nameError)
	}

	// the analysis runs until it exits: nothing cancels it
	cmd = exec.CommandContext(context.Background(), self, args...) // #nosec G204
	out, err := cmd.CombinedOutput()
	if err != nil {
		panic(fmt.Errorf("%v", string(out)))
	} else if s.config.GetVerbose() && len(out) > 0 {
		fmt.Println("---")
		fmt.Print(string(out))
		fmt.Println("---")
	}
}

func (s *server) editModelAnalyze(ginContext *gin.Context) {
	defer func() {
		var err error
		if r := recover(); r != nil {
			s.errorCount++
			err = panicError(r)
			log.Println(err)
			respondError(ginContext, http.StatusBadRequest, strings.TrimSpace(err.Error()))
		}
	}()

	var modelInput input.Model
	if err := ginContext.ShouldBindJSON(&modelInput); err != nil {
		respondError(ginContext, http.StatusBadRequest, "Invalid JSON provided")
		return
	}
	log.Printf("Received JSON: %+v\n", modelInput)

	progressReporter := DefaultProgressReporter{
		Verbose:       s.config.GetVerbose(),
		SuppressError: true,
	}
	customRiskRules := model.LoadCustomRiskRules(s.config.GetPluginFolder(), s.config.GetRiskRulePlugins(),
		progressReporter)
	builtinRiskRules := risks.GetBuiltInRiskRules()

	result, err := model.AnalyzeModel(&modelInput, s.config, builtinRiskRules, customRiskRules, progressReporter)
	if err != nil {
		respondError(ginContext, http.StatusBadRequest, "Unable to analyze model: "+err.Error())
		return
	}

	respondMessage(ginContext, http.StatusOK, "Analyzed successfully", gin.H{
		"data": result,
	})
}
