package apihandlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
)

func HandleAPIUserGroupsGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "User ID is required", "INVALID_REQUEST", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "INVALID_REQUEST", http.StatusBadRequest)
			return
		}

		user, err := database.GetUserById(nil, id)
		if err != nil {
			slog.Error("AuthServer API: Database error getting user by ID for groups", "error", err, "userId", id)
			writeJSONError(w, "Failed to get user", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
			return
		}

		err = database.UserLoadGroups(nil, user)
		if err != nil {
			slog.Error("AuthServer API: Database error loading user groups", "error", err, "userId", user.Id)
			writeJSONError(w, "Failed to load user groups", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Get member counts for user's groups
		memberCounts := make(map[int64]int)
		for _, group := range user.Groups {
			count, err := database.CountGroupMembers(nil, group.Id)
			if err != nil {
				// Log error but continue with 0 count
				count = 0
			}
			memberCounts[group.Id] = count
		}

		response := api.GetUserGroupsResponse{
			User:   *api.ToUserResponse(user),
			Groups: api.ToGroupResponses(user.Groups, memberCounts),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		httpHelper.EncodeJson(w, r, response)
	}
}

func HandleAPIUserGroupsPut(
	httpHelper handlers.HttpHelper,
	database data.Database,
	authHelper handlers.AuthHelper,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "User ID is required", "INVALID_REQUEST", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "INVALID_REQUEST", http.StatusBadRequest)
			return
		}

		var request api.UpdateUserGroupsRequest
		err = json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
			return
		}

		user, err := database.GetUserById(nil, id)
		if err != nil {
			slog.Error("AuthServer API: Database error getting user by ID for groups", "error", err, "userId", id)
			writeJSONError(w, "Failed to get user", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Validate all requested groups exist
		if len(request.GroupIds) > 0 {
			groups, err := database.GetGroupsByIds(nil, request.GroupIds)
			if err != nil {
				slog.Error("AuthServer API: Database error getting groups by IDs for validation", "error", err, "groupIds", request.GroupIds, "userId", user.Id)
				writeJSONError(w, "Failed to validate groups", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}
			if len(groups) != len(request.GroupIds) {
				writeValidationError(w, customerrors.NewErrorDetail("", "One or more groups not found"))
				return
			}
		}

		// Load current user groups
		err = database.UserLoadGroups(nil, user)
		if err != nil {
			slog.Error("AuthServer API: Database error loading current user groups for update", "error", err, "userId", user.Id)
			writeJSONError(w, "Failed to load current user groups", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Create map of current group IDs for efficient lookup
		currentGroupIds := make(map[int64]bool)
		for _, grp := range user.Groups {
			currentGroupIds[grp.Id] = true
		}

		// Create map of requested group IDs
		requestedGroupIds := make(map[int64]bool)
		for _, groupId := range request.GroupIds {
			requestedGroupIds[groupId] = true
		}

		loggedInSubject := authHelper.GetLoggedInSubject(r)

		// Add groups that are in requested but not in current
		for _, groupId := range request.GroupIds {
			if !currentGroupIds[groupId] {
				err = database.CreateUserGroup(nil, &models.UserGroup{
					UserId:  user.Id,
					GroupId: groupId,
				})
				if err != nil {
					slog.Error("AuthServer API: Database error creating user group membership", "error", err, "userId", user.Id, "groupId", groupId)
					writeJSONError(w, "Failed to add user to group", "INTERNAL_ERROR", http.StatusInternalServerError)
					return
				}

				auditLogger.Log(constants.AuditUserAddedToGroup, map[string]interface{}{
					"userId":       user.Id,
					"groupId":      groupId,
					"loggedInUser": loggedInSubject,
				})
			}
		}

		// Remove groups that are in current but not in requested
		for _, grp := range user.Groups {
			if !requestedGroupIds[grp.Id] {
				userGroup, err := database.GetUserGroupByUserIdAndGroupId(nil, user.Id, grp.Id)
				if err != nil {
					slog.Error("AuthServer API: Database error getting user group relationship for removal", "error", err, "userId", user.Id, "groupId", grp.Id)
					writeJSONError(w, "Failed to get user group relationship", "INTERNAL_ERROR", http.StatusInternalServerError)
					return
				}
				if userGroup != nil {
					err = database.DeleteUserGroup(nil, userGroup.Id)
					if err != nil {
						slog.Error("AuthServer API: Database error deleting user group membership", "error", err, "userGroupId", userGroup.Id, "userId", user.Id, "groupId", grp.Id)
						writeJSONError(w, "Failed to remove user from group", "INTERNAL_ERROR", http.StatusInternalServerError)
						return
					}

					auditLogger.Log(constants.AuditUserRemovedFromGroup, map[string]interface{}{
						"userId":       user.Id,
						"groupId":      grp.Id,
						"loggedInUser": loggedInSubject,
					})
				}
			}
		}

		// Reload user groups to get updated state
		err = database.UserLoadGroups(nil, user)
		if err != nil {
			slog.Error("AuthServer API: Database error reloading user groups after update", "error", err, "userId", user.Id)
			writeJSONError(w, "Failed to reload user groups", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Get member counts for user's groups
		memberCounts := make(map[int64]int)
		for _, group := range user.Groups {
			count, err := database.CountGroupMembers(nil, group.Id)
			if err != nil {
				// Log error but continue with 0 count
				count = 0
			}
			memberCounts[group.Id] = count
		}

		response := api.GetUserGroupsResponse{
			User:   *api.ToUserResponse(user),
			Groups: api.ToGroupResponses(user.Groups, memberCounts),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		httpHelper.EncodeJson(w, r, response)
	}
}
