/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package server

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/gin-gonic/gin"
)

type responseType int

const (
	dataFlowDiagram responseType = iota
	dataAssetDiagram
	reportPDF
	risksExcel
	tagsExcel
	risksJSON
	technicalAssetsJSON
	statsJSON
)

func (s *server) streamDataFlowDiagram(ginContext *gin.Context) {
	s.streamResponse(ginContext, dataFlowDiagram)
}

func (s *server) streamDataAssetDiagram(ginContext *gin.Context) {
	s.streamResponse(ginContext, dataAssetDiagram)
}

func (s *server) streamReportPDF(ginContext *gin.Context) {
	s.streamResponse(ginContext, reportPDF)
}

func (s *server) streamRisksExcel(ginContext *gin.Context) {
	s.streamResponse(ginContext, risksExcel)
}

func (s *server) streamTagsExcel(ginContext *gin.Context) {
	s.streamResponse(ginContext, tagsExcel)
}

func (s *server) streamRisksJSON(ginContext *gin.Context) {
	s.streamResponse(ginContext, risksJSON)
}

func (s *server) streamTechnicalAssetsJSON(ginContext *gin.Context) {
	s.streamResponse(ginContext, technicalAssetsJSON)
}

func (s *server) streamStatsJSON(ginContext *gin.Context) {
	s.streamResponse(ginContext, statsJSON)
}

// streamedOutput is how streamResponse streams an output of the analysis.
type streamedOutput struct {
	outputs  analysisOutputs
	filename func(serverConfigReader) string
	mode     streamMode
}

type streamMode int

const (
	streamFile       streamMode = iota // serve the file
	streamAttachment                   // serve the file for download
	streamJSON                         // serve the JSON with its content type instead of as a file download
)

var streamedOutputs = map[responseType]streamedOutput{
	dataFlowDiagram: {
		outputs:  analysisOutputs{dataFlowDiagram: true},
		filename: serverConfigReader.GetDataFlowDiagramFilenamePNG,
		mode:     streamFile,
	},
	dataAssetDiagram: {
		outputs:  analysisOutputs{dataAssetDiagram: true},
		filename: serverConfigReader.GetDataAssetDiagramFilenamePNG,
		mode:     streamFile,
	},
	reportPDF: {
		outputs:  analysisOutputs{reportPDF: true},
		filename: serverConfigReader.GetReportFilename,
		mode:     streamAttachment,
	},
	risksExcel: {
		outputs:  analysisOutputs{risksExcel: true},
		filename: serverConfigReader.GetExcelRisksFilename,
		mode:     streamAttachment,
	},
	tagsExcel: {
		outputs:  analysisOutputs{tagsExcel: true},
		filename: serverConfigReader.GetExcelTagsFilename,
		mode:     streamAttachment,
	},
	risksJSON: {
		outputs:  analysisOutputs{risksJSON: true},
		filename: serverConfigReader.GetJsonRisksFilename,
		mode:     streamJSON,
	},
	technicalAssetsJSON: {
		outputs:  analysisOutputs{risksJSON: true, technicalAssetsJSON: true},
		filename: serverConfigReader.GetJsonTechnicalAssetsFilename,
		mode:     streamJSON,
	},
	statsJSON: {
		outputs:  analysisOutputs{statsJSON: true},
		filename: serverConfigReader.GetJsonStatsFilename,
		mode:     streamJSON,
	},
}

func (s *server) streamResponse(ginContext *gin.Context, responseType responseType) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer func() { s.unlockFolderAndAnswerPanic(ginContext, folderNameOfKey, recover()) }()
	dpi, err := strconv.Atoi(ginContext.DefaultQuery("dpi", strconv.Itoa(s.config.GetGraphvizDPI())))
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	_, yamlText, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if !ok {
		return
	}
	tmpModelFile, err := os.CreateTemp(s.config.GetTempFolder(), "threagile-render-*")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	defer func() { _ = os.Remove(tmpModelFile.Name()) }()
	tmpOutputDir, err := os.MkdirTemp(s.config.GetTempFolder(), "threagile-render-")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	defer func() { _ = os.RemoveAll(tmpOutputDir) }()
	err = os.WriteFile(tmpModelFile.Name(), []byte(yamlText), 0o400)
	output, known := streamedOutputs[responseType]
	if !known {
		return
	}
	s.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, output.outputs, dpi)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	s.streamOutput(ginContext, tmpOutputDir, output)
}

func (s *server) streamOutput(ginContext *gin.Context, tmpOutputDir string, output streamedOutput) {
	filename := output.filename(s.config)
	switch output.mode {
	case streamFile:
		ginContext.File(filepath.Clean(filepath.Join(tmpOutputDir, filename)))

	case streamAttachment:
		ginContext.FileAttachment(filepath.Clean(filepath.Join(tmpOutputDir, filename)), filename)

	case streamJSON:
		jsonData, err := os.ReadFile(filepath.Clean(filepath.Join(tmpOutputDir, filename)))
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.Data(http.StatusOK, "application/json", jsonData)
	}
}
