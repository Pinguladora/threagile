/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package server

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Pinguladora/threagile/pkg/input"
	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	"gopkg.in/yaml.v3"
)

// creates a sub-folder (named by a new UUID) inside the token folder.
func (s *server) createNewModel(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	ok = s.checkObjectCreationThrottler(ginContext, "MODEL")
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)

	aUuid := uuid.New().String()
	err := os.Mkdir(folderNameForModel(folderNameOfKey, aUuid), 0o700)
	if err != nil {
		respondError(ginContext, http.StatusInternalServerError, "unable to create model")
		return
	}

	aYaml := `title: New Threat Model
threagile_version: ` + s.config.GetThreagileVersion() + `
author:
  name: ""
  homepage: ""
date:
business_overview:
  description: ""
  images: []
technical_overview:
  description: ""
  images: []
business_criticality: ""
management_summary_comment: ""
questions: {}
abuse_cases: {}
security_requirements: {}
tags_available: []
data_assets: {}
technical_assets: {}
trust_boundaries: {}
shared_runtimes: {}
custom_risk_categories: []
risk_tracking: {}
diagram_tweak_nodesep: 0
diagram_tweak_ranksep: 0
diagram_tweak_edge_layout: ""
diagram_tweak_suppress_edge_labels: false
diagram_tweak_invisible_connections_between_assets: []
diagram_tweak_same_rank_assets: []`

	ok = s.writeModelYAML(ginContext, aYaml, key, folderNameForModel(folderNameOfKey, aUuid), "New Model Creation", true)
	if ok {
		respondMessage(ginContext, http.StatusCreated, "model created", gin.H{
			"id": aUuid,
		})
	}
}

type payloadModels struct {
	ID                string    `json:"id"                 yaml:"id"`
	Title             string    `json:"title"              yaml:"title"`
	TimestampCreated  time.Time `json:"timestamp_created"  yaml:"timestamp_created"`
	TimestampModified time.Time `json:"timestamp_modified" yaml:"timestamp_modified"`
}

// listModels fails as soon as any model is no longer valid in syntax; it has no fallback for invalid models.
func (s *server) listModels(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)

	result := make([]payloadModels, 0)
	modelFolders, err := os.ReadDir(folderNameOfKey)
	if err != nil {
		log.Println(err)
		respondError(ginContext, http.StatusNotFound, "token not found")
		return
	}
	for _, dirEntry := range modelFolders {
		if dirEntry.IsDir() {
			modelStat, err := os.Stat(filepath.Join(folderNameOfKey, dirEntry.Name(), s.config.GetInputFile()))
			if err != nil {
				log.Println(err)
				respondError(ginContext, http.StatusNotFound, "unable to list model")
				return
			}
			aModel, _, ok := s.readModel(ginContext, dirEntry.Name(), key, folderNameOfKey)
			if !ok {
				return
			}
			fileInfo, err := dirEntry.Info()
			if err != nil {
				log.Println(err)
				respondError(ginContext, http.StatusNotFound, "unable to get file info")
				return
			}
			result = append(result, payloadModels{
				ID:                dirEntry.Name(),
				Title:             aModel.Title,
				TimestampCreated:  fileInfo.ModTime(),
				TimestampModified: modelStat.ModTime(),
			})
		}
	}
	ginContext.JSON(http.StatusOK, result)
}

func (s *server) deleteModel(ginContext *gin.Context) {
	folderNameOfKey, _, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	folder, ok := s.checkModelFolder(ginContext, ginContext.Param("model-id"), folderNameOfKey)
	if ok {
		if folder != filepath.Clean(folder) {
			respondError(ginContext, http.StatusInternalServerError, "model-id is weird")
			return
		}
		err := os.RemoveAll(folder)
		if err != nil {
			respondError(ginContext, http.StatusNotFound, "model not found")
			return
		}
		respondMessage(ginContext, http.StatusOK, "model deleted", nil)
	}
}

type payloadCover struct {
	Title  string       `json:"title"  yaml:"title"`
	Date   time.Time    `json:"date"   yaml:"date"`
	Author input.Author `json:"author" yaml:"author"`
}

func (s *server) setCover(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadCover{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			respondError(ginContext, http.StatusBadRequest, "unable to parse request payload")
			return
		}
		modelInput.Title = payload.Title
		if !payload.Date.IsZero() {
			modelInput.Date = payload.Date.Format("2006-01-02")
		}
		modelInput.Author.Name = payload.Author.Name
		modelInput.Author.Homepage = payload.Author.Homepage
		ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Cover Update")
		if ok {
			respondMessage(ginContext, http.StatusOK, "model updated", nil)
		}
	}
}

func (s *server) getCover(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	aModel, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, gin.H{
			"title":  aModel.Title,
			"date":   aModel.Date,
			"author": aModel.Author,
		})
	}
}

type payloadOverview struct {
	ManagementSummaryComment string         `json:"management_summary_comment" yaml:"management_summary_comment"`
	BusinessCriticality      string         `json:"business_criticality"       yaml:"business_criticality"`
	BusinessOverview         input.Overview `json:"business_overview"          yaml:"business_overview"`
	TechnicalOverview        input.Overview `json:"technical_overview"         yaml:"technical_overview"`
}

func (s *server) setOverview(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadOverview{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			respondError(ginContext, http.StatusBadRequest, "unable to parse request payload")
			return
		}
		criticality, err := types.ParseCriticality(payload.BusinessCriticality)
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		modelInput.ManagementSummaryComment = payload.ManagementSummaryComment
		modelInput.BusinessCriticality = criticality.String()
		modelInput.BusinessOverview.Description = payload.BusinessOverview.Description
		modelInput.BusinessOverview.Images = payload.BusinessOverview.Images
		modelInput.TechnicalOverview.Description = payload.TechnicalOverview.Description
		modelInput.TechnicalOverview.Images = payload.TechnicalOverview.Images
		ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Overview Update")
		if ok {
			respondMessage(ginContext, http.StatusOK, "model updated", nil)
		}
	}
}

func (s *server) getOverview(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	aModel, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, gin.H{
			"management_summary_comment": aModel.ManagementSummaryComment,
			"business_criticality":       aModel.BusinessCriticality,
			"business_overview":          aModel.BusinessOverview,
			"technical_overview":         aModel.TechnicalOverview,
		})
	}
}

type payloadAbuseCases map[string]string

func (s *server) setAbuseCases(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadAbuseCases{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			respondError(ginContext, http.StatusBadRequest, "unable to parse request payload")
			return
		}
		modelInput.AbuseCases = payload
		ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Abuse Cases Update")
		if ok {
			respondMessage(ginContext, http.StatusOK, "model updated", nil)
		}
	}
}

func (s *server) getAbuseCases(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	aModel, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, aModel.AbuseCases)
	}
}

type payloadSecurityRequirements map[string]string

func (s *server) setSecurityRequirements(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadSecurityRequirements{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			respondError(ginContext, http.StatusBadRequest, "unable to parse request payload")
			return
		}
		modelInput.SecurityRequirements = payload
		ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Security Requirements Update")
		if ok {
			respondMessage(ginContext, http.StatusOK, "model updated", nil)
		}
	}
}

func (s *server) getSecurityRequirements(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	aModel, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, aModel.SecurityRequirements)
	}
}

type payloadDataAsset struct {
	Title                  string   `json:"title"                    yaml:"title"`
	Id                     string   `json:"id"                       yaml:"id"`
	Description            string   `json:"description"              yaml:"description"`
	Usage                  string   `json:"usage"                    yaml:"usage"`
	Tags                   []string `json:"tags"                     yaml:"tags"`
	Origin                 string   `json:"origin"                   yaml:"origin"`
	Owner                  string   `json:"owner"                    yaml:"owner"`
	Quantity               string   `json:"quantity"                 yaml:"quantity"`
	Confidentiality        string   `json:"confidentiality"          yaml:"confidentiality"`
	Integrity              string   `json:"integrity"                yaml:"integrity"`
	Availability           string   `json:"availability"             yaml:"availability"`
	JustificationCiaRating string   `json:"justification_cia_rating" yaml:"justification_cia_rating"`
}

func (s *server) getDataAssets(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	aModel, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, aModel.DataAssets)
	}
}

func (s *server) getDataAsset(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, dataAsset := range modelInput.DataAssets {
			if dataAsset.ID == ginContext.Param("data-asset-id") {
				ginContext.JSON(http.StatusOK, gin.H{
					title: dataAsset,
				})
				return
			}
		}
		respondError(ginContext, http.StatusNotFound, "data asset not found")
	}
}

func (s *server) deleteDataAsset(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, dataAsset := range modelInput.DataAssets {
			if dataAsset.ID == ginContext.Param("data-asset-id") {
				// also remove all usages of this data asset !!
				referencesDeleted := removeDataAssetReferences(&modelInput, dataAsset.ID)
				// remove it itself
				delete(modelInput.DataAssets, title)
				ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Data Asset Deletion")
				if ok {
					respondMessage(ginContext, http.StatusOK, "data asset deleted", gin.H{
						"id": dataAsset.ID,
						// in order to signal to clients, that other model parts might've been deleted as well
						"references_deleted": referencesDeleted,
					})
				}
				return
			}
		}
		respondError(ginContext, http.StatusNotFound, "data asset not found")
	}
}

// removeDataAssetReferences removes the references to a data asset from the technical assets, their
// communication links and the individual risks; it reports whether there were any.
func removeDataAssetReferences(modelInput *input.Model, dataAssetID string) bool {
	referencesDeleted := false
	for _, techAsset := range modelInput.TechnicalAssets {
		var removed bool
		// as before, the shortened lists stay in this copy of the asset
		techAsset.DataAssetsProcessed, removed = removeDataAssetID(techAsset.DataAssetsProcessed, dataAssetID)
		referencesDeleted = referencesDeleted || removed
		techAsset.DataAssetsStored, removed = removeDataAssetID(techAsset.DataAssetsStored, dataAssetID)
		referencesDeleted = referencesDeleted || removed
		for title, commLink := range techAsset.CommunicationLinks {
			x := techAsset.CommunicationLinks[title]
			x.DataAssetsSent, removed = removeDataAssetID(commLink.DataAssetsSent, dataAssetID)
			if removed {
				referencesDeleted = true
				techAsset.CommunicationLinks[title] = x
			}
			x = techAsset.CommunicationLinks[title]
			x.DataAssetsReceived, removed = removeDataAssetID(commLink.DataAssetsReceived, dataAssetID)
			if removed {
				referencesDeleted = true
				techAsset.CommunicationLinks[title] = x
			}
		}
	}
	for _, individualRiskCat := range modelInput.CustomRiskCategories {
		for individualRiskInstanceTitle, individualRiskInstance := range individualRiskCat.RisksIdentified {
			if individualRiskInstance.MostRelevantDataAsset == dataAssetID { // apply the removal
				referencesDeleted = true
				x := individualRiskCat.RisksIdentified[individualRiskInstanceTitle]
				x.MostRelevantDataAsset = "" // not well tested
				individualRiskCat.RisksIdentified[individualRiskInstanceTitle] = x
			}
		}
	}
	return referencesDeleted
}

// removeDataAssetID removes a data asset from a list in place and returns the shortened list; it reports
// whether the list had the data asset.
func removeDataAssetID(list []string, dataAssetID string) ([]string, bool) {
	removed := false
	for i, referencedAsset := range list {
		if referencedAsset == dataAssetID { // apply the removal
			removed = true
			// Remove the element at index i
			// this removal is not well tested
			copy(list[i:], list[i+1:]) // Shift a[i+1:] left one index.
			list[len(list)-1] = ""     // Erase last element (write zero value).
			list = list[:len(list)-1]  // Truncate slice.
		}
	}
	return list, removed
}

func (s *server) setDataAsset(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, dataAsset := range modelInput.DataAssets {
			if dataAsset.ID == ginContext.Param("data-asset-id") {
				payload := payloadDataAsset{}
				err := ginContext.BindJSON(&payload)
				if err != nil {
					log.Println(err)
					respondError(ginContext, http.StatusBadRequest, "unable to parse request payload")
					return
				}
				dataAssetInput, ok := s.populateDataAsset(ginContext, payload)
				if !ok {
					return
				}
				// in order to also update the title, remove the asset from the map and re-insert it (with new key)
				delete(modelInput.DataAssets, title)
				modelInput.DataAssets[payload.Title] = dataAssetInput
				idChanged := dataAssetInput.ID != dataAsset.ID
				if idChanged { // ID-CHANGE-PROPAGATION
					// also update all usages to point to the new (changed) ID !!
					renameDataAssetReferences(&modelInput, dataAsset.ID, dataAssetInput.ID)
				}
				ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Data Asset Update")
				if ok {
					respondMessage(ginContext, http.StatusOK, "data asset updated", gin.H{
						"id": dataAssetInput.ID,
						// in order to signal to clients, that other model parts might've received updates as well and
						// should be reloaded
						"id_changed": idChanged,
					})
				}
				return
			}
		}
		respondError(ginContext, http.StatusNotFound, "data asset not found")
	}
}

// renameDataAssetReferences points the references to a data asset in the technical assets, their
// communication links and the individual risks to its new ID.
func renameDataAssetReferences(modelInput *input.Model, oldID string, newID string) {
	for techAssetTitle, techAsset := range modelInput.TechnicalAssets {
		renameDataAssetInTechnicalAsset(modelInput, techAssetTitle, techAsset, oldID, newID)
	}
	for _, individualRiskCat := range modelInput.CustomRiskCategories {
		for individualRiskInstanceTitle, individualRiskInstance := range individualRiskCat.RisksIdentified {
			if individualRiskInstance.MostRelevantDataAsset == oldID { // apply the ID change
				x := individualRiskCat.RisksIdentified[individualRiskInstanceTitle]
				x.MostRelevantDataAsset = newID // not well tested
				individualRiskCat.RisksIdentified[individualRiskInstanceTitle] = x
			}
		}
	}
}

// renameDataAssetInTechnicalAsset points the references of a technical asset and its communication links to
// a data asset to its new ID.
func renameDataAssetInTechnicalAsset(
	modelInput *input.Model, techAssetTitle string, techAsset input.TechnicalAsset, oldID string, newID string,
) {
	for i, referencedAsset := range techAsset.DataAssetsProcessed {
		if referencedAsset == oldID { // apply the ID change
			modelInput.TechnicalAssets[techAssetTitle].DataAssetsProcessed[i] = newID
		}
	}
	for i, referencedAsset := range techAsset.DataAssetsStored {
		if referencedAsset == oldID { // apply the ID change
			modelInput.TechnicalAssets[techAssetTitle].DataAssetsStored[i] = newID
		}
	}
	for title, commLink := range techAsset.CommunicationLinks {
		for i, referencedAsset := range commLink.DataAssetsSent {
			if referencedAsset == oldID { // apply the ID change
				modelInput.TechnicalAssets[techAssetTitle].CommunicationLinks[title].DataAssetsSent[i] = newID
			}
		}
		for i, referencedAsset := range commLink.DataAssetsReceived {
			if referencedAsset == oldID { // apply the ID change
				modelInput.TechnicalAssets[techAssetTitle].CommunicationLinks[title].DataAssetsReceived[i] = newID
			}
		}
	}
}

func (s *server) createNewDataAsset(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadDataAsset{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			respondError(ginContext, http.StatusBadRequest, "unable to parse request payload")
			return
		}
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		if _, exists := modelInput.DataAssets[payload.Title]; exists {
			respondError(ginContext, http.StatusConflict, "data asset with this title already exists")
			return
		}
		// but later it will in memory keyed by its "id", so do this uniqueness check also
		for _, asset := range modelInput.DataAssets {
			if asset.ID == payload.Id {
				respondError(ginContext, http.StatusConflict, "data asset with this id already exists")
				return
			}
		}
		dataAssetInput, ok := s.populateDataAsset(ginContext, payload)
		if !ok {
			return
		}
		if modelInput.DataAssets == nil {
			modelInput.DataAssets = make(map[string]input.DataAsset)
		}
		modelInput.DataAssets[payload.Title] = dataAssetInput
		ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Data Asset Creation")
		if ok {
			respondMessage(ginContext, http.StatusOK, "data asset created", gin.H{
				"id": dataAssetInput.ID,
			})
		}
	}
}

func (s *server) populateDataAsset(
	ginContext *gin.Context, payload payloadDataAsset,
) (dataAssetInput input.DataAsset, ok bool) {
	usage, err := types.ParseUsage(payload.Usage)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return dataAssetInput, false
	}
	quantity, err := types.ParseQuantity(payload.Quantity)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return dataAssetInput, false
	}
	confidentiality, err := types.ParseConfidentiality(payload.Confidentiality)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return dataAssetInput, false
	}
	integrity, err := types.ParseCriticality(payload.Integrity)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return dataAssetInput, false
	}
	availability, err := types.ParseCriticality(payload.Availability)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return dataAssetInput, false
	}
	dataAssetInput = input.DataAsset{
		ID:                     payload.Id,
		Description:            payload.Description,
		Usage:                  usage.String(),
		Tags:                   lowerCaseAndTrim(payload.Tags),
		Origin:                 payload.Origin,
		Owner:                  payload.Owner,
		Quantity:               quantity.String(),
		Confidentiality:        confidentiality.String(),
		Integrity:              integrity.String(),
		Availability:           availability.String(),
		JustificationCiaRating: payload.JustificationCiaRating,
	}
	return dataAssetInput, true
}

func (s *server) getTrustBoundaries(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	aModel, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, aModel.TrustBoundaries)
	}
}

type payloadSharedRuntime struct {
	Title                  string   `json:"title"                    yaml:"title"`
	Id                     string   `json:"id"                       yaml:"id"`
	Description            string   `json:"description"              yaml:"description"`
	Tags                   []string `json:"tags"                     yaml:"tags"`
	TechnicalAssetsRunning []string `json:"technical_assets_running" yaml:"technical_assets_running"`
}

func (s *server) setSharedRuntime(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, sharedRuntime := range modelInput.SharedRuntimes {
			if sharedRuntime.ID == ginContext.Param("shared-runtime-id") {
				payload := payloadSharedRuntime{}
				err := ginContext.BindJSON(&payload)
				if err != nil {
					log.Println(err)
					respondError(ginContext, http.StatusBadRequest, "unable to parse request payload")
					return
				}
				sharedRuntimeInput, ok := populateSharedRuntime(ginContext, payload)
				if !ok {
					return
				}
				// in order to also update the title, remove the shared runtime from the map and re-insert it (with new key)
				delete(modelInput.SharedRuntimes, title)
				modelInput.SharedRuntimes[payload.Title] = sharedRuntimeInput
				idChanged := sharedRuntimeInput.ID != sharedRuntime.ID
				if idChanged { // ID-CHANGE-PROPAGATION
					renameSharedRuntimeReferences(&modelInput, sharedRuntime.ID, sharedRuntimeInput.ID)
				}
				ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Shared Runtime Update")
				if ok {
					respondMessage(ginContext, http.StatusOK, "shared runtime updated", gin.H{
						"id": sharedRuntimeInput.ID,
						// in order to signal to clients, that other model parts might've received updates as well and
						// should be reloaded
						"id_changed": idChanged,
					})
				}
				return
			}
		}
		respondError(ginContext, http.StatusNotFound, "shared runtime not found")
	}
}

func (s *server) getSharedRuntime(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, sharedRuntime := range modelInput.SharedRuntimes {
			if sharedRuntime.ID == ginContext.Param("shared-runtime-id") {
				ginContext.JSON(http.StatusOK, gin.H{
					title: sharedRuntime,
				})
				return
			}
		}
		respondError(ginContext, http.StatusNotFound, "shared runtime not found")
	}
}

func (s *server) createNewSharedRuntime(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadSharedRuntime{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			respondError(ginContext, http.StatusBadRequest, "unable to parse request payload")
			return
		}
		if conflict := sharedRuntimeConflict(modelInput, payload); conflict != "" {
			respondError(ginContext, http.StatusConflict, conflict)
			return
		}
		if !checkTechnicalAssetsExisting(modelInput, payload.TechnicalAssetsRunning) {
			respondError(ginContext, http.StatusBadRequest, "referenced technical asset does not exist")
			return
		}
		sharedRuntimeInput, ok := populateSharedRuntime(ginContext, payload)
		if !ok {
			return
		}
		if modelInput.SharedRuntimes == nil {
			modelInput.SharedRuntimes = make(map[string]input.SharedRuntime)
		}
		modelInput.SharedRuntimes[payload.Title] = sharedRuntimeInput
		ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Shared Runtime Creation")
		if ok {
			respondMessage(ginContext, http.StatusOK, "shared runtime created", gin.H{
				"id": sharedRuntimeInput.ID,
			})
		}
	}
}

// sharedRuntimeConflict tells why a new shared runtime would clash with one of the model, if it would.
func sharedRuntimeConflict(modelInput input.Model, payload payloadSharedRuntime) string {
	// yes, here keyed by title in YAML for better readability in the YAML file itself
	if _, exists := modelInput.SharedRuntimes[payload.Title]; exists {
		return "shared runtime with this title already exists"
	}
	// but later it will in memory keyed by its "id", so do this uniqueness check also
	for _, sharedRuntime := range modelInput.SharedRuntimes {
		if sharedRuntime.ID == payload.Id {
			return "shared runtime with this id already exists"
		}
	}
	return ""
}

// renameSharedRuntimeReferences points the references of the individual risks to a shared runtime to its
// new ID, or removes them for an empty one; it reports whether there were any.
func renameSharedRuntimeReferences(modelInput *input.Model, oldID string, newID string) bool {
	referencesChanged := false
	for _, individualRiskCat := range modelInput.CustomRiskCategories {
		for individualRiskInstanceTitle, individualRiskInstance := range individualRiskCat.RisksIdentified {
			if individualRiskInstance.MostRelevantSharedRuntime == oldID { // apply the change
				referencesChanged = true
				x := individualRiskCat.RisksIdentified[individualRiskInstanceTitle]
				x.MostRelevantSharedRuntime = newID // not well tested
				individualRiskCat.RisksIdentified[individualRiskInstanceTitle] = x
			}
		}
	}
	return referencesChanged
}

func checkTechnicalAssetsExisting(modelInput input.Model, techAssetIDs []string) (ok bool) {
	for _, techAssetID := range techAssetIDs {
		exists := false
		for _, val := range modelInput.TechnicalAssets {
			if val.ID == techAssetID {
				exists = true
				break
			}
		}
		if !exists {
			return false
		}
	}
	return true
}

func populateSharedRuntime(
	_ *gin.Context, payload payloadSharedRuntime,
) (sharedRuntimeInput input.SharedRuntime, ok bool) {
	sharedRuntimeInput = input.SharedRuntime{
		ID:                     payload.Id,
		Description:            payload.Description,
		Tags:                   lowerCaseAndTrim(payload.Tags),
		TechnicalAssetsRunning: payload.TechnicalAssetsRunning,
	}
	return sharedRuntimeInput, true
}

func (s *server) deleteSharedRuntime(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, sharedRuntime := range modelInput.SharedRuntimes {
			if sharedRuntime.ID == ginContext.Param("shared-runtime-id") {
				// also remove all usages of this shared runtime !!
				referencesDeleted := renameSharedRuntimeReferences(&modelInput, sharedRuntime.ID, "")
				// remove it itself
				delete(modelInput.SharedRuntimes, title)
				ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Shared Runtime Deletion")
				if ok {
					respondMessage(ginContext, http.StatusOK, "shared runtime deleted", gin.H{
						"id": sharedRuntime.ID,
						// in order to signal to clients, that other model parts might've been deleted as well
						"references_deleted": referencesDeleted,
					})
				}
				return
			}
		}
		respondError(ginContext, http.StatusNotFound, "shared runtime not found")
	}
}

func (s *server) getSharedRuntimes(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	aModel, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, aModel.SharedRuntimes)
	}
}

func (s *server) readModel(
	ginContext *gin.Context, modelUUID string, key []byte, folderNameOfKey string,
) (modelInputResult input.Model, yamlText string, ok bool) {
	modelFolder, ok := s.checkModelFolder(ginContext, modelUUID, folderNameOfKey)
	if !ok {
		return modelInputResult, yamlText, false
	}
	aesGcm, err := newModelCipher(key)
	if err != nil {
		log.Println(err)
		respondError(ginContext, http.StatusInternalServerError, "unable to open model")
		return modelInputResult, yamlText, false
	}

	fileBytes, err := os.ReadFile(filepath.Clean(filepath.Join(modelFolder, s.config.GetInputFile())))
	if err != nil {
		log.Println(err)
		respondError(ginContext, http.StatusInternalServerError, "unable to open model")
		return modelInputResult, yamlText, false
	}

	nonce := fileBytes[0:nonceSize]
	ciphertext := fileBytes[nonceSize:]
	plaintext, err := aesGcm.Open(nil, nonce, ciphertext, nil) // #nosec G407 // nonce read from the file to decrypt
	if err != nil {
		log.Println(err)
		respondError(ginContext, http.StatusInternalServerError, "unable to open model")
		return modelInputResult, yamlText, false
	}

	r, err := gzip.NewReader(bytes.NewReader(plaintext))
	if err != nil {
		log.Println(err)
		respondError(ginContext, http.StatusInternalServerError, "unable to open model")
		return modelInputResult, yamlText, false
	}
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(r)
	modelInput := new(input.Model).Defaults()
	yamlBytes := buf.Bytes()
	err = yaml.Unmarshal(yamlBytes, &modelInput)
	if err != nil {
		log.Println(err)
		respondError(ginContext, http.StatusInternalServerError, "unable to open model")
		return modelInputResult, yamlText, false
	}
	return *modelInput, string(yamlBytes), true
}

// newModelCipher creates the cipher of the model files of a key.
func newModelCipher(key []byte) (cipher.AEAD, error) {
	cryptoKey := generateKeyFromAlreadyStrongRandomInput(key)
	block, err := aes.NewCipher(cryptoKey)
	if err != nil {
		return nil, fmt.Errorf("unable to create the model cipher: %w", err)
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("unable to create the model cipher: %w", err)
	}
	return aesGcm, nil
}

func (s *server) writeModel(
	ginContext *gin.Context, key []byte, folderNameOfKey string, modelInput *input.Model, changeReasonForHistory string,
) (ok bool) {
	modelFolder, ok := s.checkModelFolder(ginContext, ginContext.Param("model-id"), folderNameOfKey)
	if ok {
		modelInput.ThreagileVersion = s.config.GetThreagileVersion()
		yamlBytes, err := yaml.Marshal(modelInput)
		if err != nil {
			log.Println(err)
			respondError(ginContext, http.StatusInternalServerError, "unable to write model")
			return false
		}
		/*
			yamlBytes = model.ReformatYAML(yamlBytes)
		*/
		return s.writeModelYAML(ginContext, string(yamlBytes), key, modelFolder, changeReasonForHistory, false)
	}
	return false
}

func (s *server) checkModelFolder(
	ginContext *gin.Context, modelUUID string, folderNameOfKey string,
) (modelFolder string, ok bool) {
	uuidParsed, err := uuid.Parse(modelUUID)
	if err != nil {
		respondError(ginContext, http.StatusNotFound, "model not found")
		return modelFolder, false
	}
	modelFolder = folderNameForModel(folderNameOfKey, uuidParsed.String())
	if _, err := os.Stat(modelFolder); os.IsNotExist(err) {
		respondError(ginContext, http.StatusNotFound, "model not found")
		return modelFolder, false
	}
	return modelFolder, true
}

func (s *server) getModel(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	_, yamlText, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		tmpResultFile, err := os.CreateTemp(s.config.GetTempFolder(), "threagile-*.yaml")
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		err = os.WriteFile(tmpResultFile.Name(), []byte(yamlText), 0o400) // #nosec G703
		if err != nil {
			log.Println(err)
			respondError(ginContext, http.StatusInternalServerError, "unable to stream model file")
			return
		}
		defer func() { _ = os.Remove(tmpResultFile.Name()) }() // #nosec G703
		ginContext.FileAttachment(tmpResultFile.Name(), s.config.GetInputFile())
	}
}

// fully replaces threagile.yaml in sub-folder given by UUID.
func (s *server) importModel(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)

	// UUID is syntactically validated in readModel+checkModelFolder (next line) via uuid.Parse(modelUUID)
	aUuid := ginContext.Param("model-id")
	_, _, ok = s.readModel(ginContext, aUuid, key, folderNameOfKey)
	if ok {
		// first analyze it simply by executing the full risk process (just discard the result) to ensure that
		// everything would work
		yamlContent, ok := s.execute(ginContext, true)
		if ok {
			// if we're here, then no problem was raised, so ok to proceed
			ok = s.writeModelYAML(ginContext, string(yamlContent), key, folderNameForModel(folderNameOfKey, aUuid),
				"Model Import", false)
			if ok {
				respondMessage(ginContext, http.StatusCreated, "model imported", nil)
			}
		}
	}
}

func (s *server) analyzeModelOnServerDirectly(ginContext *gin.Context) {
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

	files := new(temporaryFiles)
	defer files.remove()

	tmpModelFile, tmpOutputDir, tmpResultFile, ok := s.createDirectAnalysisFiles(ginContext, files)
	if !ok {
		return
	}

	err = os.WriteFile(tmpModelFile, []byte(yamlText), 0o400) // #nosec G703

	s.doItViaRuntimeCall(tmpModelFile, tmpOutputDir, allAnalysisOutputs, dpi)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	err = os.WriteFile(filepath.Join(tmpOutputDir, s.config.GetInputFile()), []byte(yamlText), 0o400)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}

	s.streamDirectAnalysisResult(ginContext, tmpOutputDir, tmpResultFile)
}

// streamDirectAnalysisResult packs the result files of analyzing a model on the server and streams them back.
func (s *server) streamDirectAnalysisResult(ginContext *gin.Context, tmpOutputDir string, tmpResultFile string) {
	resultFiles := s.resultFiles(tmpOutputDir)
	if s.config.GetKeepDiagramSourceFiles() {
		resultFiles = append(resultFiles, filepath.Join(tmpOutputDir, s.config.GetDataFlowDiagramFilenameDOT()))
		resultFiles = append(resultFiles, filepath.Join(tmpOutputDir, s.config.GetDataAssetDiagramFilenameDOT()))
	}
	if !zipResult(ginContext, tmpResultFile, resultFiles) {
		return
	}
	if s.config.GetVerbose() {
		fmt.Println("Streaming back result file: " + tmpResultFile)
	}
	ginContext.FileAttachment(tmpResultFile, "threagile-result.zip")
}

// createDirectAnalysisFiles creates the temporary model file, output folder and result archive of analyzing a
// model on the server.
func (s *server) createDirectAnalysisFiles(
	ginContext *gin.Context, files *temporaryFiles,
) (tmpModelFile string, tmpOutputDir string, tmpResultFile string, ok bool) {
	modelFile, err := os.CreateTemp(s.config.GetTempFolder(), "threagile-direct-analyze-*")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return "", "", "", false
	}
	files.add(func() { _ = os.Remove(modelFile.Name()) }) // #nosec G703
	tmpOutputDir, err = os.MkdirTemp(s.config.GetTempFolder(), "threagile-direct-analyze-")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return "", "", "", false
	}
	files.add(func() { _ = os.RemoveAll(tmpOutputDir) })
	resultFile, err := os.CreateTemp(s.config.GetTempFolder(), "threagile-result-*.zip")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return "", "", "", false
	}
	files.add(func() { _ = os.Remove(resultFile.Name()) }) // #nosec G703
	return modelFile.Name(), tmpOutputDir, resultFile.Name(), true
}

// unlockFolderAndAnswerPanic unlocks the folder of a key and answers the panic of a request, if any, with its
// error.
func (s *server) unlockFolderAndAnswerPanic(ginContext *gin.Context, folderNameOfKey string, r any) {
	s.unlockFolder(folderNameOfKey)
	var err error
	if r != nil {
		err = panicError(r)
		if s.config.GetVerbose() {
			log.Println(err)
		}
		log.Println(err)
		respondError(ginContext, http.StatusBadRequest, strings.TrimSpace(err.Error()))
	}
}

func (s *server) writeModelYAML(
	ginContext *gin.Context, yaml string, key []byte, modelFolder string, changeReasonForHistory string, skipBackup bool,
) (ok bool) {
	if s.config.GetVerbose() {
		fmt.Println("about to write " + strconv.Itoa(len(yaml)) + " bytes of yaml into model folder: " + modelFolder)
	}
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write([]byte(yaml))
	_ = w.Close()
	plaintext := b.Bytes()
	cryptoKey := generateKeyFromAlreadyStrongRandomInput(key)
	block, err := aes.NewCipher(cryptoKey)
	if err != nil {
		log.Println(err)
		respondError(ginContext, http.StatusInternalServerError, "unable to write model")
		return false
	}
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Println(err)
		respondError(ginContext, http.StatusInternalServerError, "unable to write model")
		return false
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println(err)
		respondError(ginContext, http.StatusInternalServerError, "unable to write model")
		return false
	}
	ciphertext := aesGcm.Seal(nil, nonce, plaintext, nil) // #nosec G407 // the nonce is random for each write
	if !skipBackup {
		err = s.backupModelToHistory(modelFolder, changeReasonForHistory)
		if err != nil {
			log.Println(err)
			respondError(ginContext, http.StatusInternalServerError, "unable to write model")
			return false
		}
	}
	f, err := os.Create(filepath.Clean(filepath.Join(modelFolder, s.config.GetInputFile())))
	if err != nil {
		log.Println(err)
		respondError(ginContext, http.StatusInternalServerError, "unable to write model")
		return false
	}
	_, _ = f.Write(nonce)
	_, _ = f.Write(ciphertext)
	_ = f.Close()
	return true
}

func (s *server) lockFolder(folderName string) {
	s.globalLock.Lock()
	defer s.globalLock.Unlock()
	_, exists := s.locksByFolderName[folderName]
	if !exists {
		s.locksByFolderName[folderName] = &sync.Mutex{}
	}
	s.locksByFolderName[folderName].Lock()
}

func (s *server) unlockFolder(folderName string) {
	if _, exists := s.locksByFolderName[folderName]; exists {
		s.locksByFolderName[folderName].Unlock()
		delete(s.locksByFolderName, folderName)
	}
}

func (s *server) backupModelToHistory(modelFolder string, changeReasonForHistory string) (err error) {
	// Sanitize inputs to prevent path traversal
	safeReason := filepath.Base(changeReasonForHistory)
	baseDir, resolveErr := filepath.Abs(s.config.GetDataFolder())
	if resolveErr != nil {
		return fmt.Errorf("failed to resolve data folder: %w", resolveErr)
	}
	cleanModelFolder, resolveErr := filepath.Abs(modelFolder)
	if resolveErr != nil {
		return fmt.Errorf("failed to resolve model folder: %w", resolveErr)
	}
	if !strings.HasPrefix(cleanModelFolder, baseDir) {
		return fmt.Errorf("model folder %q is outside data directory", modelFolder)
	}
	historyFolder := filepath.Join(cleanModelFolder, "history")
	if _, err := os.Stat(historyFolder); os.IsNotExist(err) {
		err = os.Mkdir(historyFolder, 0o700)
		if err != nil {
			return fmt.Errorf("failed to create history folder: %w", err)
		}
	}
	inputFile := filepath.Join(cleanModelFolder, filepath.Base(s.config.GetInputFile()))
	inputModel, err := os.ReadFile(filepath.Clean(inputFile))
	if err != nil {
		return fmt.Errorf("failed to read model to back up: %w", err)
	}
	historyFile := filepath.Join(historyFolder, time.Now().Format("2006-01-02 15:04:05")+" "+safeReason+".backup")
	err = os.WriteFile(historyFile, inputModel, 0o400) // #nosec G703
	if err != nil {
		return fmt.Errorf("failed to write model backup: %w", err)
	}
	// now delete any old files if over limit to keep
	files, err := os.ReadDir(filepath.Clean(historyFolder))
	if err != nil {
		return fmt.Errorf("failed to list model backups: %w", err)
	}
	if len(files) > s.config.GetBackupHistoryFilesToKeep() {
		return removeOldestBackups(historyFolder, files, len(files)-s.config.GetBackupHistoryFilesToKeep())
	}
	return
}

// removeOldestBackups removes the given number of the oldest backups from the history folder.
func removeOldestBackups(historyFolder string, files []os.DirEntry, requiredToDelete int) error {
	sort.Slice(files, func(i, j int) bool {
		return files[i].Name() < files[j].Name()
	})
	for _, file := range files {
		requiredToDelete--
		if file.Name() != filepath.Clean(file.Name()) {
			return fmt.Errorf("weird file name %v", file.Name())
		}
		err := os.Remove(filepath.Clean(filepath.Join(historyFolder, file.Name())))
		if err != nil {
			return fmt.Errorf("failed to remove old model backup: %w", err)
		}
		if requiredToDelete <= 0 {
			break
		}
	}
	return nil
}

func folderNameForModel(folderNameOfKey string, uuid string) string {
	return filepath.Join(folderNameOfKey, uuid)
}

// nonceSize is the size of the nonce that a model file starts with.
const nonceSize = 12

// The parameters of Argon2 for deriving the key of the model files.
const (
	argon2Memory      = 64 * 1024
	argon2Iterations  = 3
	argon2Parallelism = 2
	argon2SaltLength  = 16
)

type argon2Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

func generateKeyFromAlreadyStrongRandomInput(alreadyRandomInput []byte) []byte {
	// Establish the parameters to use for Argon2.
	p := &argon2Params{
		memory:      argon2Memory,
		iterations:  argon2Iterations,
		parallelism: argon2Parallelism,
		saltLength:  argon2SaltLength,
		keyLength:   keySize,
	}
	// As the input is already cryptographically secure random, the salt is simply the first n bytes
	salt := alreadyRandomInput[0:p.saltLength]
	hash := argon2.IDKey(alreadyRandomInput[p.saltLength:], salt, p.iterations, p.memory, p.parallelism, p.keyLength)
	return hash
}

func lowerCaseAndTrim(tags []string) []string {
	for i := range tags {
		tags[i] = strings.ToLower(strings.TrimSpace(tags[i]))
	}
	return tags
}
