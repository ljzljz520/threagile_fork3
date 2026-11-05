/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/types"
	"golang.org/x/crypto/argon2"
)

// creates a sub-folder (named by a new UUID) inside the token folder
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
	err := os.Mkdir(folderNameForModel(folderNameOfKey, aUuid), 0700)
	if err != nil {
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to create model",
		})
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
individual_risk_categories: {}
risk_tracking: {}
diagram_tweak_nodesep: 0
diagram_tweak_ranksep: 0
diagram_tweak_edge_layout: ""
diagram_tweak_suppress_edge_labels: false
diagram_tweak_invisible_connections_between_assets: []
diagram_tweak_same_rank_assets: []`

	revision, err := s.store.create(folderNameForModel(folderNameOfKey, aUuid), key, aYaml, "New Model Creation")
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return
	}
	s.respondRevision(ginContext, revision)
	ginContext.JSON(http.StatusCreated, gin.H{
		"message":  "model created",
		"id":       aUuid,
		"revision": revision,
	})
}

type payloadModels struct {
	ID                string    `yaml:"id" json:"id"`
	Title             string    `yaml:"title" json:"title"`
	TimestampCreated  time.Time `yaml:"timestamp_created" json:"timestamp_created"`
	TimestampModified time.Time `yaml:"timestamp_modified" json:"timestamp_modified"`
}

func (s *server) listModels(ginContext *gin.Context) { // TODO currently returns error when any model is no longer valid in syntax, so eventually have some fallback to not just bark on an invalid model...
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
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return
	}
	for _, dirEntry := range modelFolders {
		if dirEntry.IsDir() {
			modelStat, err := os.Stat(filepath.Join(folderNameOfKey, dirEntry.Name(), s.config.GetInputFile()))
			if err != nil {
				log.Println(err)
				ginContext.JSON(http.StatusNotFound, gin.H{
					"error": "unable to list model",
				})
				return
			}
			aModel, _, _, ok := s.readModel(ginContext, dirEntry.Name(), key, folderNameOfKey)
			if !ok {
				return
			}
			fileInfo, err := dirEntry.Info()
			if err != nil {
				log.Println(err)
				ginContext.JSON(http.StatusNotFound, gin.H{
					"error": "unable to get file info",
				})
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
			ginContext.JSON(http.StatusInternalServerError, gin.H{
				"error": "model-id is weird",
			})
			return
		}
		err := os.RemoveAll(folder)
		if err != nil {
			ginContext.JSON(http.StatusNotFound, gin.H{
				"error": "model not found",
			})
			return
		}
		ginContext.JSON(http.StatusOK, gin.H{
			"message": "model deleted",
		})
	}
}

type payloadCover struct {
	Title  string       `yaml:"title" json:"title"`
	Date   time.Time    `yaml:"date" json:"date"`
	Author input.Author `yaml:"author" json:"author"`
}

func (s *server) setCover(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, expectedRevision, ok := s.readModelForUpdate(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadCover{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		modelInput.Title = payload.Title
		if !payload.Date.IsZero() {
			modelInput.Date = payload.Date.Format("2006-01-02")
		}
		modelInput.Author.Name = payload.Author.Name
		modelInput.Author.Homepage = payload.Author.Homepage
		newRevision, ok := s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Cover Update", expectedRevision)
		if ok {
			ginContext.JSON(http.StatusOK, gin.H{
				"message":  "model updated",
				"revision": newRevision,
			})
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
	aModel, _, revision, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		s.respondRevision(ginContext, revision)
		ginContext.JSON(http.StatusOK, gin.H{
			"title":  aModel.Title,
			"date":   aModel.Date,
			"author": aModel.Author,
		})
	}
}

type payloadOverview struct {
	ManagementSummaryComment string         `yaml:"management_summary_comment" json:"management_summary_comment"`
	BusinessCriticality      string         `yaml:"business_criticality" json:"business_criticality"`
	BusinessOverview         input.Overview `yaml:"business_overview" json:"business_overview"`
	TechnicalOverview        input.Overview `yaml:"technical_overview" json:"technical_overview"`
}

func (s *server) setOverview(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, expectedRevision, ok := s.readModelForUpdate(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadOverview{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
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
		newRevision, ok := s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Overview Update", expectedRevision)
		if ok {
			ginContext.JSON(http.StatusOK, gin.H{
				"message":  "model updated",
				"revision": newRevision,
			})
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
	aModel, _, revision, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		s.respondRevision(ginContext, revision)
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
	modelInput, _, expectedRevision, ok := s.readModelForUpdate(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadAbuseCases{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		modelInput.AbuseCases = payload
		newRevision, ok := s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Abuse Cases Update", expectedRevision)
		if ok {
			ginContext.JSON(http.StatusOK, gin.H{
				"message":  "model updated",
				"revision": newRevision,
			})
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
	aModel, _, revision, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		s.respondRevision(ginContext, revision)
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
	modelInput, _, expectedRevision, ok := s.readModelForUpdate(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadSecurityRequirements{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		modelInput.SecurityRequirements = payload
		newRevision, ok := s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Security Requirements Update", expectedRevision)
		if ok {
			ginContext.JSON(http.StatusOK, gin.H{
				"message":  "model updated",
				"revision": newRevision,
			})
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
	aModel, _, revision, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		s.respondRevision(ginContext, revision)
		ginContext.JSON(http.StatusOK, aModel.SecurityRequirements)
	}
}

type payloadDataAsset struct {
	Title                  string   `yaml:"title" json:"title"`
	Id                     string   `yaml:"id" json:"id"`
	Description            string   `yaml:"description" json:"description"`
	Usage                  string   `yaml:"usage" json:"usage"`
	Tags                   []string `yaml:"tags" json:"tags"`
	Origin                 string   `yaml:"origin" json:"origin"`
	Owner                  string   `yaml:"owner" json:"owner"`
	Quantity               string   `yaml:"quantity" json:"quantity"`
	Confidentiality        string   `yaml:"confidentiality" json:"confidentiality"`
	Integrity              string   `yaml:"integrity" json:"integrity"`
	Availability           string   `yaml:"availability" json:"availability"`
	JustificationCiaRating string   `yaml:"justification_cia_rating" json:"justification_cia_rating"`
}

func (s *server) getDataAssets(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	aModel, _, revision, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		s.respondRevision(ginContext, revision)
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
	modelInput, _, revision, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		s.respondRevision(ginContext, revision)
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, dataAsset := range modelInput.DataAssets {
			if dataAsset.ID == ginContext.Param("data-asset-id") {
				ginContext.JSON(http.StatusOK, gin.H{
					title: dataAsset,
				})
				return
			}
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "data asset not found",
		})
	}
}

func (s *server) deleteDataAsset(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, expectedRevision, ok := s.readModelForUpdate(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		referencesDeleted := false
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, dataAsset := range modelInput.DataAssets {
			if dataAsset.ID == ginContext.Param("data-asset-id") {
				// also remove all usages of this data asset !!
				for _, techAsset := range modelInput.TechnicalAssets {
					if techAsset.DataAssetsProcessed != nil {
						for i, parsedChangeCandidateAsset := range techAsset.DataAssetsProcessed {
							referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
							if referencedAsset == dataAsset.ID { // apply the removal
								referencesDeleted = true
								// Remove the element at index i
								// TODO needs more testing
								copy(techAsset.DataAssetsProcessed[i:], techAsset.DataAssetsProcessed[i+1:])                         // Shift a[i+1:] left one index.
								techAsset.DataAssetsProcessed[len(techAsset.DataAssetsProcessed)-1] = ""                             // Erase last element (write zero value).
								techAsset.DataAssetsProcessed = techAsset.DataAssetsProcessed[:len(techAsset.DataAssetsProcessed)-1] // Truncate slice.
							}
						}
					}
					if techAsset.DataAssetsStored != nil {
						for i, parsedChangeCandidateAsset := range techAsset.DataAssetsStored {
							referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
							if referencedAsset == dataAsset.ID { // apply the removal
								referencesDeleted = true
								// Remove the element at index i
								// TODO needs more testing
								copy(techAsset.DataAssetsStored[i:], techAsset.DataAssetsStored[i+1:])                      // Shift a[i+1:] left one index.
								techAsset.DataAssetsStored[len(techAsset.DataAssetsStored)-1] = ""                          // Erase last element (write zero value).
								techAsset.DataAssetsStored = techAsset.DataAssetsStored[:len(techAsset.DataAssetsStored)-1] // Truncate slice.
							}
						}
					}
					if techAsset.CommunicationLinks != nil {
						for title, commLink := range techAsset.CommunicationLinks {
							for i, dataAssetSent := range commLink.DataAssetsSent {
								referencedAsset := fmt.Sprintf("%v", dataAssetSent)
								if referencedAsset == dataAsset.ID { // apply the removal
									referencesDeleted = true
									// Remove the element at index i
									// TODO needs more testing
									copy(techAsset.CommunicationLinks[title].DataAssetsSent[i:], techAsset.CommunicationLinks[title].DataAssetsSent[i+1:]) // Shift a[i+1:] left one index.
									techAsset.CommunicationLinks[title].DataAssetsSent[len(techAsset.CommunicationLinks[title].DataAssetsSent)-1] = ""     // Erase last element (write zero value).
									x := techAsset.CommunicationLinks[title]
									x.DataAssetsSent = techAsset.CommunicationLinks[title].DataAssetsSent[:len(techAsset.CommunicationLinks[title].DataAssetsSent)-1] // Truncate slice.
									techAsset.CommunicationLinks[title] = x
								}
							}
							for i, dataAssetReceived := range commLink.DataAssetsReceived {
								referencedAsset := fmt.Sprintf("%v", dataAssetReceived)
								if referencedAsset == dataAsset.ID { // apply the removal
									referencesDeleted = true
									// Remove the element at index i
									// TODO needs more testing
									copy(techAsset.CommunicationLinks[title].DataAssetsReceived[i:], techAsset.CommunicationLinks[title].DataAssetsReceived[i+1:]) // Shift a[i+1:] left one index.
									techAsset.CommunicationLinks[title].DataAssetsReceived[len(techAsset.CommunicationLinks[title].DataAssetsReceived)-1] = ""     // Erase last element (write zero value).
									x := techAsset.CommunicationLinks[title]
									x.DataAssetsReceived = techAsset.CommunicationLinks[title].DataAssetsReceived[:len(techAsset.CommunicationLinks[title].DataAssetsReceived)-1] // Truncate slice.
									techAsset.CommunicationLinks[title] = x
								}
							}
						}
					}
				}
				for _, individualRiskCat := range modelInput.CustomRiskCategories {
					if individualRiskCat.RisksIdentified != nil {
						for individualRiskInstanceTitle, individualRiskInstance := range individualRiskCat.RisksIdentified {
							if individualRiskInstance.MostRelevantDataAsset == dataAsset.ID { // apply the removal
								referencesDeleted = true
								x := individualRiskCat.RisksIdentified[individualRiskInstanceTitle]
								x.MostRelevantDataAsset = "" // TODO needs more testing
								individualRiskCat.RisksIdentified[individualRiskInstanceTitle] = x
							}
						}
					}
				}
				// remove it itself
				delete(modelInput.DataAssets, title)
				newRevision, ok := s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Data Asset Deletion", expectedRevision)
				if ok {
					ginContext.JSON(http.StatusOK, gin.H{
						"message":            "data asset deleted",
						"id":                 dataAsset.ID,
						"revision":           newRevision,
						"references_deleted": referencesDeleted, // in order to signal to clients, that other model parts might've been deleted as well
					})
				}
				return
			}
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "data asset not found",
		})
	}
}

func (s *server) setDataAsset(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, expectedRevision, ok := s.readModelForUpdate(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, dataAsset := range modelInput.DataAssets {
			if dataAsset.ID == ginContext.Param("data-asset-id") {
				payload := payloadDataAsset{}
				err := ginContext.BindJSON(&payload)
				if err != nil {
					log.Println(err)
					ginContext.JSON(http.StatusBadRequest, gin.H{
						"error": "unable to parse request payload",
					})
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
					for techAssetTitle, techAsset := range modelInput.TechnicalAssets {
						if techAsset.DataAssetsProcessed != nil {
							for i, parsedChangeCandidateAsset := range techAsset.DataAssetsProcessed {
								referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
								if referencedAsset == dataAsset.ID { // apply the ID change
									modelInput.TechnicalAssets[techAssetTitle].DataAssetsProcessed[i] = dataAssetInput.ID
								}
							}
						}
						if techAsset.DataAssetsStored != nil {
							for i, parsedChangeCandidateAsset := range techAsset.DataAssetsStored {
								referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
								if referencedAsset == dataAsset.ID { // apply the ID change
									modelInput.TechnicalAssets[techAssetTitle].DataAssetsStored[i] = dataAssetInput.ID
								}
							}
						}
						if techAsset.CommunicationLinks != nil {
							for title, commLink := range techAsset.CommunicationLinks {
								for i, dataAssetSent := range commLink.DataAssetsSent {
									referencedAsset := fmt.Sprintf("%v", dataAssetSent)
									if referencedAsset == dataAsset.ID { // apply the ID change
										modelInput.TechnicalAssets[techAssetTitle].CommunicationLinks[title].DataAssetsSent[i] = dataAssetInput.ID
									}
								}
								for i, dataAssetReceived := range commLink.DataAssetsReceived {
									referencedAsset := fmt.Sprintf("%v", dataAssetReceived)
									if referencedAsset == dataAsset.ID { // apply the ID change
										modelInput.TechnicalAssets[techAssetTitle].CommunicationLinks[title].DataAssetsReceived[i] = dataAssetInput.ID
									}
								}
							}
						}
					}
					for _, individualRiskCat := range modelInput.CustomRiskCategories {
						if individualRiskCat.RisksIdentified != nil {
							for individualRiskInstanceTitle, individualRiskInstance := range individualRiskCat.RisksIdentified {
								if individualRiskInstance.MostRelevantDataAsset == dataAsset.ID { // apply the ID change
									x := individualRiskCat.RisksIdentified[individualRiskInstanceTitle]
									x.MostRelevantDataAsset = dataAssetInput.ID // TODO needs more testing
									individualRiskCat.RisksIdentified[individualRiskInstanceTitle] = x
								}
							}
						}
					}
				}
				newRevision, ok := s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Data Asset Update", expectedRevision)
				if ok {
					ginContext.JSON(http.StatusOK, gin.H{
						"message":    "data asset updated",
						"id":         dataAssetInput.ID,
						"revision":   newRevision,
						"id_changed": idChanged, // in order to signal to clients, that other model parts might've received updates as well and should be reloaded
					})
				}
				return
			}
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "data asset not found",
		})
	}
}

func (s *server) createNewDataAsset(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, expectedRevision, ok := s.readModelForUpdate(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadDataAsset{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		if _, exists := modelInput.DataAssets[payload.Title]; exists {
			ginContext.JSON(http.StatusConflict, gin.H{
				"error": "data asset with this title already exists",
			})
			return
		}
		// but later it will in memory keyed by its "id", so do this uniqueness check also
		for _, asset := range modelInput.DataAssets {
			if asset.ID == payload.Id {
				ginContext.JSON(http.StatusConflict, gin.H{
					"error": "data asset with this id already exists",
				})
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
		newRevision, ok := s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Data Asset Creation", expectedRevision)
		if ok {
			ginContext.JSON(http.StatusOK, gin.H{
				"message":  "data asset created",
				"id":       dataAssetInput.ID,
				"revision": newRevision,
			})
		}
	}
}

func (s *server) populateDataAsset(ginContext *gin.Context, payload payloadDataAsset) (dataAssetInput input.DataAsset, ok bool) {
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
	aModel, _, revision, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		s.respondRevision(ginContext, revision)
		ginContext.JSON(http.StatusOK, aModel.TrustBoundaries)
	}
}

type payloadSharedRuntime struct {
	Title                  string   `yaml:"title" json:"title"`
	Id                     string   `yaml:"id" json:"id"`
	Description            string   `yaml:"description" json:"description"`
	Tags                   []string `yaml:"tags" json:"tags"`
	TechnicalAssetsRunning []string `yaml:"technical_assets_running" json:"technical_assets_running"`
}

func (s *server) setSharedRuntime(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, expectedRevision, ok := s.readModelForUpdate(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, sharedRuntime := range modelInput.SharedRuntimes {
			if sharedRuntime.ID == ginContext.Param("shared-runtime-id") {
				payload := payloadSharedRuntime{}
				err := ginContext.BindJSON(&payload)
				if err != nil {
					log.Println(err)
					ginContext.JSON(http.StatusBadRequest, gin.H{
						"error": "unable to parse request payload",
					})
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
					for _, individualRiskCat := range modelInput.CustomRiskCategories {
						if individualRiskCat.RisksIdentified != nil {
							for individualRiskInstanceTitle, individualRiskInstance := range individualRiskCat.RisksIdentified {
								if individualRiskInstance.MostRelevantSharedRuntime == sharedRuntime.ID { // apply the ID change
									x := individualRiskCat.RisksIdentified[individualRiskInstanceTitle]
									x.MostRelevantSharedRuntime = sharedRuntimeInput.ID // TODO needs more testing
									individualRiskCat.RisksIdentified[individualRiskInstanceTitle] = x
								}
							}
						}
					}
				}
				newRevision, ok := s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Shared Runtime Update", expectedRevision)
				if ok {
					ginContext.JSON(http.StatusOK, gin.H{
						"message":    "shared runtime updated",
						"id":         sharedRuntimeInput.ID,
						"revision":   newRevision,
						"id_changed": idChanged, // in order to signal to clients, that other model parts might've received updates as well and should be reloaded
					})
				}
				return
			}
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "shared runtime not found",
		})
	}
}

func (s *server) getSharedRuntime(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, revision, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		s.respondRevision(ginContext, revision)
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, sharedRuntime := range modelInput.SharedRuntimes {
			if sharedRuntime.ID == ginContext.Param("shared-runtime-id") {
				ginContext.JSON(http.StatusOK, gin.H{
					title: sharedRuntime,
				})
				return
			}
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "shared runtime not found",
		})
	}
}

func (s *server) createNewSharedRuntime(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, expectedRevision, ok := s.readModelForUpdate(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadSharedRuntime{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		if _, exists := modelInput.SharedRuntimes[payload.Title]; exists {
			ginContext.JSON(http.StatusConflict, gin.H{
				"error": "shared runtime with this title already exists",
			})
			return
		}
		// but later it will in memory keyed by its "id", so do this uniqueness check also
		for _, sharedRuntime := range modelInput.SharedRuntimes {
			if sharedRuntime.ID == payload.Id {
				ginContext.JSON(http.StatusConflict, gin.H{
					"error": "shared runtime with this id already exists",
				})
				return
			}
		}
		if !checkTechnicalAssetsExisting(modelInput, payload.TechnicalAssetsRunning) {
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "referenced technical asset does not exist",
			})
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
		newRevision, ok := s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Shared Runtime Creation", expectedRevision)
		if ok {
			ginContext.JSON(http.StatusOK, gin.H{
				"message":  "shared runtime created",
				"id":       sharedRuntimeInput.ID,
				"revision": newRevision,
			})
		}
	}
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

func populateSharedRuntime(_ *gin.Context, payload payloadSharedRuntime) (sharedRuntimeInput input.SharedRuntime, ok bool) {
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
	modelInput, _, expectedRevision, ok := s.readModelForUpdate(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		referencesDeleted := false
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, sharedRuntime := range modelInput.SharedRuntimes {
			if sharedRuntime.ID == ginContext.Param("shared-runtime-id") {
				// also remove all usages of this shared runtime !!
				for _, individualRiskCat := range modelInput.CustomRiskCategories {
					if individualRiskCat.RisksIdentified != nil {
						for individualRiskInstanceTitle, individualRiskInstance := range individualRiskCat.RisksIdentified {
							if individualRiskInstance.MostRelevantSharedRuntime == sharedRuntime.ID { // apply the removal
								referencesDeleted = true
								x := individualRiskCat.RisksIdentified[individualRiskInstanceTitle]
								x.MostRelevantSharedRuntime = "" // TODO needs more testing
								individualRiskCat.RisksIdentified[individualRiskInstanceTitle] = x
							}
						}
					}
				}
				// remove it itself
				delete(modelInput.SharedRuntimes, title)
				newRevision, ok := s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Shared Runtime Deletion", expectedRevision)
				if ok {
					ginContext.JSON(http.StatusOK, gin.H{
						"message":            "shared runtime deleted",
						"id":                 sharedRuntime.ID,
						"revision":           newRevision,
						"references_deleted": referencesDeleted, // in order to signal to clients, that other model parts might've been deleted as well
					})
				}
				return
			}
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "shared runtime not found",
		})
	}
}

func (s *server) getSharedRuntimes(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	aModel, _, revision, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		s.respondRevision(ginContext, revision)
		ginContext.JSON(http.StatusOK, aModel.SharedRuntimes)
	}
}

// readModel loads and decrypts the current model. It additionally returns the
// model's revision identifier, which clients must echo on subsequent updates.
// When the model file is damaged (short write, interrupted process, ...), this
// transparently recovers the newest valid history backup.
func (s *server) readModel(ginContext *gin.Context, modelUUID string, key []byte, folderNameOfKey string) (modelInputResult input.Model, yamlText string, revision string, ok bool) {
	modelFolder, ok := s.checkModelFolder(ginContext, modelUUID, folderNameOfKey)
	if !ok {
		return modelInputResult, yamlText, "", false
	}
	loaded, err := s.store.load(modelFolder, key)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, "", false
	}
	return loaded.Model, loaded.YAML, loaded.Revision, true
}

// etagOf wraps a revision as a quoted HTTP ETag value.
func etagOf(revision string) string {
	return "\"" + revision + "\""
}

// respondRevision exposes the current model revision to clients via the
// standard ETag header plus a convenience X-Revision header.
func (s *server) respondRevision(ginContext *gin.Context, revision string) {
	ginContext.Header("ETag", etagOf(revision))
	ginContext.Header("X-Revision", revision)
}

// expectedRevision reads and normalizes the client's optimistic-locking
// precondition. It accepts the standard If-Match header (quoted or unquoted,
// with optional W/ weak prefix) as well as an X-Expected-Revision header.
func (s *server) expectedRevision(ginContext *gin.Context) (expected string, ok bool) {
	value := strings.TrimSpace(ginContext.GetHeader("If-Match"))
	if value == "" {
		value = strings.TrimSpace(ginContext.GetHeader("X-Expected-Revision"))
	}
	if value == "" {
		ginContext.JSON(http.StatusPreconditionRequired, gin.H{
			"error": "missing revision precondition: read the model first and send its revision via the If-Match header",
		})
		return "", false
	}
	if value == "*" {
		ginContext.JSON(http.StatusBadRequest, gin.H{
			"error": "wildcard If-Match precondition is not supported: send the exact revision received on read",
		})
		return "", false
	}
	value = strings.TrimSpace(strings.TrimPrefix(value, "W/"))
	value = strings.Trim(value, "\"")
	value = strings.TrimSpace(value)
	if value == "" {
		ginContext.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid If-Match revision header",
		})
		return "", false
	}
	return value, true
}

func (s *server) conflictResponse(ginContext *gin.Context, currentRevision string) {
	s.respondRevision(ginContext, currentRevision)
	ginContext.JSON(http.StatusConflict, gin.H{
		"error":            "the model was changed in the meantime: your edit is based on an outdated revision, please re-read the current revision and re-apply your changes",
		"current_revision": currentRevision,
	})
}

// readModelForUpdate combines the revision precondition check with the model
// read: requests without an If-Match revision get 428, requests based on a
// stale revision get 409 (including the current revision to re-read).
func (s *server) readModelForUpdate(ginContext *gin.Context, modelUUID string, key []byte, folderNameOfKey string) (modelInputResult input.Model, yamlText string, expectedRevision string, ok bool) {
	expected, ok := s.expectedRevision(ginContext)
	if !ok {
		return modelInputResult, yamlText, "", false
	}
	modelInputResult, yamlText, revision, ok := s.readModel(ginContext, modelUUID, key, folderNameOfKey)
	if !ok {
		return modelInputResult, yamlText, "", false
	}
	if revision != expected {
		s.conflictResponse(ginContext, revision)
		return modelInputResult, yamlText, "", false
	}
	return modelInputResult, yamlText, expected, true
}

func (s *server) writeModel(ginContext *gin.Context, key []byte, folderNameOfKey string, modelInput *input.Model, changeReasonForHistory string, expectedRevision string) (newRevision string, ok bool) {
	modelFolder, ok := s.checkModelFolder(ginContext, ginContext.Param("model-id"), folderNameOfKey)
	if !ok {
		return "", false
	}
	modelInput.ThreagileVersion = s.config.GetThreagileVersion()
	yamlBytes, err := yaml.Marshal(modelInput)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return "", false
	}
	/*
		yamlBytes = model.ReformatYAML(yamlBytes)
	*/
	return s.commitYAML(ginContext, key, modelFolder, string(yamlBytes), changeReasonForHistory, expectedRevision)
}

// commitYAML runs the unified atomic revision commit and maps storage errors
// to HTTP responses. Only ErrStaleRevision can occur here when the folder lock
// did not serialize access (e.g. external modifications).
func (s *server) commitYAML(ginContext *gin.Context, key []byte, modelFolder string, yamlText string, changeReasonForHistory string, expectedRevision string) (newRevision string, ok bool) {
	newRevision, err := s.store.commit(modelFolder, key, yamlText, changeReasonForHistory, expectedRevision)
	if err != nil {
		if errors.Is(err, ErrStaleRevision) {
			// report the revision actually on disk so the client can re-read it
			if loaded, loadErr := s.store.load(modelFolder, key); loadErr == nil {
				s.conflictResponse(ginContext, loaded.Revision)
				return "", false
			}
			s.conflictResponse(ginContext, "")
			return "", false
		}
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return "", false
	}
	s.respondRevision(ginContext, newRevision)
	return newRevision, true
}

func (s *server) checkModelFolder(ginContext *gin.Context, modelUUID string, folderNameOfKey string) (modelFolder string, ok bool) {
	uuidParsed, err := uuid.Parse(modelUUID)
	if err != nil {
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "model not found",
		})
		return modelFolder, false
	}
	modelFolder = folderNameForModel(folderNameOfKey, uuidParsed.String())
	if _, err := os.Stat(modelFolder); os.IsNotExist(err) {
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "model not found",
		})
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
	_, yamlText, revision, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		s.respondRevision(ginContext, revision)
		tmpResultFile, err := os.CreateTemp(s.config.GetTempFolder(), "threagile-*.yaml")
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		err = os.WriteFile(tmpResultFile.Name(), []byte(yamlText), 0400) // #nosec G703
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusInternalServerError, gin.H{
				"error": "unable to stream model file",
			})
			return
		}
		defer func() { _ = os.Remove(tmpResultFile.Name()) }() // #nosec G703
		ginContext.FileAttachment(tmpResultFile.Name(), s.config.GetInputFile())
	}
}

// fully replaces threagile.yaml in sub-folder given by UUID, but only when the
// client still holds the current revision (If-Match)
func (s *server) importModel(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)

	aUuid := ginContext.Param("model-id") // UUID is syntactically validated in readModel+checkModelFolder (next line) via uuid.Parse(modelUUID)
	expectedRevision, ok := s.expectedRevision(ginContext)
	if !ok {
		return
	}
	modelFolder, ok := s.checkModelFolder(ginContext, aUuid, folderNameOfKey)
	if !ok {
		return
	}
	loaded, err := s.store.load(modelFolder, key)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return
	}
	if loaded.Revision != expectedRevision {
		s.conflictResponse(ginContext, loaded.Revision)
		return
	}
	// first analyze it simply by executing the full risk process (just discard the result) to ensure that everything would work
	yamlContent, ok := s.execute(ginContext, true)
	if !ok {
		return
	}
	// if we're here, then no problem was raised, so ok to atomically commit it as a new revision
	newRevision, ok := s.commitYAML(ginContext, key, modelFolder, string(yamlContent), "Model Import", expectedRevision)
	if ok {
		ginContext.JSON(http.StatusCreated, gin.H{
			"message":  "model imported",
			"revision": newRevision,
		})
	}
}

func (s *server) analyzeModelOnServerDirectly(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer func() {
		s.unlockFolder(folderNameOfKey)
		var err error
		if r := recover(); r != nil {
			err = r.(error)
			if s.config.GetVerbose() {
				log.Println(err)
			}
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": strings.TrimSpace(err.Error()),
			})
			ok = false
		}
	}()

	dpi, err := strconv.Atoi(ginContext.DefaultQuery("dpi", strconv.Itoa(s.config.GetGraphvizDPI())))
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}

	_, yamlText, revision, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if !ok {
		return
	}
	s.respondRevision(ginContext, revision)
	tmpModelFile, err := os.CreateTemp(s.config.GetTempFolder(), "threagile-direct-analyze-*")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	defer func() { _ = os.Remove(tmpModelFile.Name()) }() // #nosec G703
	tmpOutputDir, err := os.MkdirTemp(s.config.GetTempFolder(), "threagile-direct-analyze-")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	defer func() { _ = os.RemoveAll(tmpOutputDir) }()
	tmpResultFile, err := os.CreateTemp(s.config.GetTempFolder(), "threagile-result-*.zip")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	defer func() { _ = os.Remove(tmpResultFile.Name()) }() // #nosec G703

	err = os.WriteFile(tmpModelFile.Name(), []byte(yamlText), 0400) // #nosec G703

	s.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, true, true, true, true, true, true, true, true, dpi)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	err = os.WriteFile(filepath.Join(tmpOutputDir, s.config.GetInputFile()), []byte(yamlText), 0400)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}

	files := []string{
		filepath.Join(tmpOutputDir, s.config.GetInputFile()),
		filepath.Join(tmpOutputDir, s.config.GetDataFlowDiagramFilenamePNG()),
		filepath.Join(tmpOutputDir, s.config.GetDataAssetDiagramFilenamePNG()),
		filepath.Join(tmpOutputDir, s.config.GetReportFilename()),
		filepath.Join(tmpOutputDir, s.config.GetExcelRisksFilename()),
		filepath.Join(tmpOutputDir, s.config.GetExcelTagsFilename()),
		filepath.Join(tmpOutputDir, s.config.GetJsonRisksFilename()),
		filepath.Join(tmpOutputDir, s.config.GetJsonTechnicalAssetsFilename()),
		filepath.Join(tmpOutputDir, s.config.GetJsonStatsFilename()),
	}
	if s.config.GetKeepDiagramSourceFiles() {
		files = append(files, filepath.Join(tmpOutputDir, s.config.GetDataFlowDiagramFilenameDOT()))
		files = append(files, filepath.Join(tmpOutputDir, s.config.GetDataAssetDiagramFilenameDOT()))
	}
	err = zipFiles(tmpResultFile.Name(), files)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	if s.config.GetVerbose() {
		fmt.Println("Streaming back result file: " + tmpResultFile.Name())
	}
	ginContext.FileAttachment(tmpResultFile.Name(), "threagile-result.zip")
}

// lockFolder acquires the per-model-folder mutex. The map lookup is protected
// by the global lock, but blocking on the folder mutex happens without holding
// the global lock so different folders cannot serialize each other. The lock
// entry is reference counted and only removed once its last holder released
// it, fixing the previous lifecycle bug where unlocking deleted a mutex
// another goroutine was already waiting on.
func (s *server) lockFolder(folderName string) {
	s.globalLock.Lock()
	lock, exists := s.locksByFolderName[folderName]
	if !exists {
		lock = &folderLock{}
		s.locksByFolderName[folderName] = lock
	}
	lock.holders++
	s.globalLock.Unlock()
	lock.mu.Lock()
}

func (s *server) unlockFolder(folderName string) {
	s.globalLock.Lock()
	defer s.globalLock.Unlock()
	lock, exists := s.locksByFolderName[folderName]
	if !exists {
		log.Printf("warning: unlock of folder without active lock: %q", folderName)
		return
	}
	lock.mu.Unlock()
	lock.holders--
	if lock.holders <= 0 {
		delete(s.locksByFolderName, folderName)
	}
}

func folderNameForModel(folderNameOfKey string, uuid string) string {
	return filepath.Join(folderNameOfKey, uuid)
}

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
		memory:      64 * 1024,
		iterations:  3,
		parallelism: 2,
		saltLength:  16,
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
