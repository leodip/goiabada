package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/validators"
)

// groupsDatabase is what the group endpoints need: the group row and the member count that
// decides whether it can go.
type groupsDatabase interface {
	CountGroupMembers(ctx context.Context, tx *sql.Tx, groupId int64) (int, error)
	CreateGroup(ctx context.Context, tx *sql.Tx, group *models.Group) error
	DeleteGroup(ctx context.Context, tx *sql.Tx, groupId int64) error
	GetAllGroups(ctx context.Context, tx *sql.Tx) ([]models.Group, error)
	GetGroupByGroupIdentifier(ctx context.Context, tx *sql.Tx, groupIdentifier string) (*models.Group, error)
	GetGroupById(ctx context.Context, tx *sql.Tx, groupId int64) (*models.Group, error)
	UpdateGroup(ctx context.Context, tx *sql.Tx, group *models.Group) error
}

func HandleAPIGroupsGet(
	database groupsDatabase,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		groups, err := database.GetAllGroups(r.Context(), nil)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting all groups"))
			return
		}

		// Get member counts for all groups
		memberCounts := make(map[int64]int)
		for _, group := range groups {
			count, err := database.CountGroupMembers(r.Context(), nil, group.Id)
			if err != nil {
				// Log error but continue with 0 count
				count = 0
			}
			memberCounts[group.Id] = count
		}

		groupResponses := apimapping.ToGroupResponses(groups, memberCounts)

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
	database groupsDatabase,
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

		if err := accountvalidation.ValidateNoAngleBrackets(createReq.Description, i18n.ErrCodeDescriptionAngleBrackets); err != nil {
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
		existingGroup, err := database.GetGroupByGroupIdentifier(r.Context(), nil, createReq.GroupIdentifier)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error checking group existence by identifier"), "group_identifier", createReq.GroupIdentifier)
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

		err = database.CreateGroup(r.Context(), nil, group)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error creating group"), "group_identifier", group.GroupIdentifier)
			return
		}

		// Audit log
		auditLogger.Log(r.Context(), audit.AuditCreatedGroup, map[string]interface{}{
			"groupId":         group.Id,
			"groupIdentifier": group.GroupIdentifier,
			"loggedInUser":    callerSubject(r),
		})

		// Return created group
		response := api.CreateGroupResponse{
			Group: *apimapping.ToGroupResponse(group, 0), // New group has 0 members
		}

		writeJSON(w, r, http.StatusCreated, response)
	}
}

func HandleAPIGroupGet(
	database groupsDatabase,
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

		group, err := database.GetGroupById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting group by ID"), "group_id", id)
			return
		}
		if group == nil {
			writeJSONError(w, "Group not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Get member count
		memberCount, err := database.CountGroupMembers(r.Context(), nil, group.Id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error counting group members"), "group_id", group.Id)
			return
		}

		response := api.GetGroupResponse{
			Group: *apimapping.ToGroupResponse(group, memberCount),
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

func HandleAPIGroupUpdatePut(
	database groupsDatabase,
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

		group, err := database.GetGroupById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting group by ID for update"), "group_id", id)
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

		if err := accountvalidation.ValidateNoAngleBrackets(updateReq.Description, i18n.ErrCodeDescriptionAngleBrackets); err != nil {
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
		existingGroup, err := database.GetGroupByGroupIdentifier(r.Context(), nil, updateReq.GroupIdentifier)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error checking group existence by identifier for update"), "group_identifier", updateReq.GroupIdentifier, "group_id", group.Id)
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

		err = database.UpdateGroup(r.Context(), nil, group)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error updating group"), "group_id", group.Id, "group_identifier", group.GroupIdentifier)
			return
		}

		// Audit log
		auditLogger.Log(r.Context(), audit.AuditUpdatedGroup, map[string]interface{}{
			"groupId":         group.Id,
			"groupIdentifier": group.GroupIdentifier,
			"loggedInUser":    callerSubject(r),
		})

		// Get member count for response
		memberCount, err := database.CountGroupMembers(r.Context(), nil, group.Id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error counting group members for update response"), "group_id", group.Id)
			return
		}

		// Return updated group
		response := api.UpdateGroupResponse{
			Group: *apimapping.ToGroupResponse(group, memberCount),
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

func HandleAPIGroupDelete(
	database groupsDatabase,
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
		group, err := database.GetGroupById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting group by ID for deletion"), "group_id", id)
			return
		}
		if group == nil {
			writeJSONError(w, "Group not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Delete the group
		err = database.DeleteGroup(r.Context(), nil, group.Id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error deleting group"), "group_id", group.Id, "group_identifier", group.GroupIdentifier)
			return
		}

		// Audit log
		auditLogger.Log(r.Context(), audit.AuditDeletedGroup, map[string]interface{}{
			"groupId":         group.Id,
			"groupIdentifier": group.GroupIdentifier,
			"loggedInUser":    callerSubject(r),
		})

		// Return success response
		response := api.SuccessResponse{
			Success: true,
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}
