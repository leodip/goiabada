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
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/validators"
)

func HandleAPIGroupsGet(
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		groups, err := database.GetAllGroups(nil)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting all groups"))
			return
		}

		// Get member counts for all groups
		memberCounts := make(map[int64]int)
		for _, group := range groups {
			count, err := database.CountGroupMembers(nil, group.Id)
			if err != nil {
				// Log error but continue with 0 count
				count = 0
			}
			memberCounts[group.Id] = count
		}

		groupResponses := api.ToGroupResponses(groups, memberCounts)

		// Ensure we never return a nil slice - always return at least an empty slice
		if groupResponses == nil {
			groupResponses = []api.GroupResponse{}
		}

		response := api.GetGroupsResponse{
			Groups: groupResponses,
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

func HandleAPIGroupCreatePost(
	authHelper handlers.AuthHelper,
	database data.Database,
	identifierValidator *validators.IdentifierValidator,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		var createReq api.CreateGroupRequest
		err := json.NewDecoder(r.Body).Decode(&createReq)
		if err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
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

		if err := validators.ValidateNoAngleBrackets(createReq.Description, i18n.ErrCodeDescriptionAngleBrackets); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Validate identifier format
		err = identifierValidator.ValidateIdentifier(createReq.GroupIdentifier, true)
		if err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Check if group identifier already exists
		existingGroup, err := database.GetGroupByGroupIdentifier(nil, createReq.GroupIdentifier)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error checking group existence by identifier"), "groupIdentifier", createReq.GroupIdentifier)
			return
		}
		if existingGroup != nil {
			writeJSONError(w, "The group identifier is already in use", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Create the group
		group := &models.Group{
			GroupIdentifier:      strings.TrimSpace(createReq.GroupIdentifier),
			Description:          strings.TrimSpace(createReq.Description),
			IncludeInIdToken:     createReq.IncludeInIdToken,
			IncludeInAccessToken: createReq.IncludeInAccessToken,
		}

		err = database.CreateGroup(nil, group)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error creating group"), "groupIdentifier", group.GroupIdentifier)
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
			Group: *api.ToGroupResponse(group, 0), // New group has 0 members
		}

		writeJSON(w, r, http.StatusCreated, response)
	}
}

func HandleAPIGroupGet(
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
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting group by ID"), "groupId", id)
			return
		}
		if group == nil {
			writeJSONError(w, "Group not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Get member count
		memberCount, err := database.CountGroupMembers(nil, group.Id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error counting group members"), "groupId", group.Id)
			return
		}

		response := api.GetGroupResponse{
			Group: *api.ToGroupResponse(group, memberCount),
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

func HandleAPIGroupUpdatePut(
	authHelper handlers.AuthHelper,
	database data.Database,
	identifierValidator *validators.IdentifierValidator,
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
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting group by ID for update"), "groupId", id)
			return
		}
		if group == nil {
			writeJSONError(w, "Group not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		var updateReq api.UpdateGroupRequest
		err = json.NewDecoder(r.Body).Decode(&updateReq)
		if err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
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

		if err := validators.ValidateNoAngleBrackets(updateReq.Description, i18n.ErrCodeDescriptionAngleBrackets); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Validate identifier format
		err = identifierValidator.ValidateIdentifier(updateReq.GroupIdentifier, true)
		if err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Check if group identifier already exists (but not for this group)
		existingGroup, err := database.GetGroupByGroupIdentifier(nil, updateReq.GroupIdentifier)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error checking group existence by identifier for update"), "groupIdentifier", updateReq.GroupIdentifier, "groupId", group.Id)
			return
		}
		if existingGroup != nil && existingGroup.Id != group.Id {
			writeJSONError(w, "The group identifier is already in use", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Update the group
		group.GroupIdentifier = strings.TrimSpace(updateReq.GroupIdentifier)
		group.Description = strings.TrimSpace(updateReq.Description)
		group.IncludeInIdToken = updateReq.IncludeInIdToken
		group.IncludeInAccessToken = updateReq.IncludeInAccessToken

		err = database.UpdateGroup(nil, group)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error updating group"), "groupId", group.Id, "groupIdentifier", group.GroupIdentifier)
			return
		}

		// Audit log
		auditLogger.Log(constants.AuditUpdatedGroup, map[string]interface{}{
			"groupId":         group.Id,
			"groupIdentifier": group.GroupIdentifier,
			"loggedInUser":    authHelper.GetLoggedInSubject(r),
		})

		// Get member count for response
		memberCount, err := database.CountGroupMembers(nil, group.Id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error counting group members for update response"), "groupId", group.Id)
			return
		}

		// Return updated group
		response := api.UpdateGroupResponse{
			Group: *api.ToGroupResponse(group, memberCount),
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

func HandleAPIGroupDelete(
	authHelper handlers.AuthHelper,
	database data.Database,
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

		// Check if group exists
		group, err := database.GetGroupById(nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting group by ID for deletion"), "groupId", id)
			return
		}
		if group == nil {
			writeJSONError(w, "Group not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Delete the group
		err = database.DeleteGroup(nil, group.Id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error deleting group"), "groupId", group.Id, "groupIdentifier", group.GroupIdentifier)
			return
		}

		// Audit log
		auditLogger.Log(constants.AuditDeletedGroup, map[string]interface{}{
			"groupId":         group.Id,
			"groupIdentifier": group.GroupIdentifier,
			"loggedInUser":    authHelper.GetLoggedInSubject(r),
		})

		// Return success response
		response := api.SuccessResponse{
			Success: true,
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}
