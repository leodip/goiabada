package apihandlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/inputsanitizer"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/validators"
)

func HandleAPIGroupsGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		groups, err := database.GetAllGroups(nil)
		if err != nil {
			writeJSONError(w, "Failed to get groups", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		response := api.GetGroupsResponse{
			Groups: api.ToGroupResponses(groups),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		httpHelper.EncodeJson(w, r, response)
	}
}

func HandleAPIGroupCreatePost(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
	identifierValidator *validators.IdentifierValidator,
	inputSanitizer *inputsanitizer.InputSanitizer,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		var createReq api.CreateGroupRequest
		err := json.NewDecoder(r.Body).Decode(&createReq)
		if err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
			return
		}

		// Validate group identifier
		if strings.TrimSpace(createReq.GroupIdentifier) == "" {
			writeJSONError(w, "Group identifier is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Validate description length
		const maxLengthDescription = 100
		if len(createReq.Description) > maxLengthDescription {
			writeJSONError(w, "The description cannot exceed a maximum length of "+strconv.Itoa(maxLengthDescription)+" characters", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Validate identifier format
		err = identifierValidator.ValidateIdentifier(createReq.GroupIdentifier, true)
		if err != nil {
			writeValidationError(w, err)
			return
		}

		// Check if group identifier already exists
		existingGroup, err := database.GetGroupByGroupIdentifier(nil, createReq.GroupIdentifier)
		if err != nil {
			writeJSONError(w, "Failed to check group existence", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if existingGroup != nil {
			writeJSONError(w, "The group identifier is already in use", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Create the group
		group := &models.Group{
			GroupIdentifier:      strings.TrimSpace(inputSanitizer.Sanitize(createReq.GroupIdentifier)),
			Description:          strings.TrimSpace(inputSanitizer.Sanitize(createReq.Description)),
			IncludeInIdToken:     createReq.IncludeInIdToken,
			IncludeInAccessToken: createReq.IncludeInAccessToken,
		}

		err = database.CreateGroup(nil, group)
		if err != nil {
			writeJSONError(w, "Failed to create group", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Audit log
		auditLogger.Log(constants.AuditCreatedGroup, map[string]interface{}{
			"groupId":         group.Id,
			"groupIdentifier": group.GroupIdentifier,
			"loggedInUser":    authHelper.GetLoggedInSubject(r),
		})

		// Return created group
		response := api.CreateGroupResponse{
			Group: *api.ToGroupResponse(group),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		httpHelper.EncodeJson(w, r, response)
	}
}

func HandleAPIGroupGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "id")
		if idStr == "" {
			writeJSONError(w, "Group ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid group ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		group, err := database.GetGroupById(nil, id)
		if err != nil {
			writeJSONError(w, "Failed to get group", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if group == nil {
			writeJSONError(w, "Group not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		response := api.GetGroupResponse{
			Group: *api.ToGroupResponse(group),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		httpHelper.EncodeJson(w, r, response)
	}
}

func HandleAPIGroupUpdatePut(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
	identifierValidator *validators.IdentifierValidator,
	inputSanitizer *inputsanitizer.InputSanitizer,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "id")
		if idStr == "" {
			writeJSONError(w, "Group ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid group ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		group, err := database.GetGroupById(nil, id)
		if err != nil {
			writeJSONError(w, "Failed to get group", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if group == nil {
			writeJSONError(w, "Group not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		var updateReq api.UpdateGroupRequest
		err = json.NewDecoder(r.Body).Decode(&updateReq)
		if err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
			return
		}

		// Validate group identifier
		if strings.TrimSpace(updateReq.GroupIdentifier) == "" {
			writeJSONError(w, "Group identifier is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Validate description length
		const maxLengthDescription = 100
		if len(updateReq.Description) > maxLengthDescription {
			writeJSONError(w, "The description cannot exceed a maximum length of "+strconv.Itoa(maxLengthDescription)+" characters", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Validate identifier format
		err = identifierValidator.ValidateIdentifier(updateReq.GroupIdentifier, true)
		if err != nil {
			writeValidationError(w, err)
			return
		}

		// Check if group identifier already exists (but not for this group)
		existingGroup, err := database.GetGroupByGroupIdentifier(nil, updateReq.GroupIdentifier)
		if err != nil {
			writeJSONError(w, "Failed to check group existence", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if existingGroup != nil && existingGroup.Id != group.Id {
			writeJSONError(w, "The group identifier is already in use", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Update the group
		group.GroupIdentifier = strings.TrimSpace(inputSanitizer.Sanitize(updateReq.GroupIdentifier))
		group.Description = strings.TrimSpace(inputSanitizer.Sanitize(updateReq.Description))
		group.IncludeInIdToken = updateReq.IncludeInIdToken
		group.IncludeInAccessToken = updateReq.IncludeInAccessToken

		err = database.UpdateGroup(nil, group)
		if err != nil {
			writeJSONError(w, "Failed to update group", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Audit log
		auditLogger.Log(constants.AuditUpdatedGroup, map[string]interface{}{
			"groupId":         group.Id,
			"groupIdentifier": group.GroupIdentifier,
			"loggedInUser":    authHelper.GetLoggedInSubject(r),
		})

		// Return updated group
		response := api.UpdateGroupResponse{
			Group: *api.ToGroupResponse(group),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		httpHelper.EncodeJson(w, r, response)
	}
}