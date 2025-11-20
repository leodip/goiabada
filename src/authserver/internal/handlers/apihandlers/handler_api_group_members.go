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
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
)

func HandleAPIGroupMembersGet(
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
			slog.Error("AuthServer API: Database error getting group by ID for members", "error", err, "groupId", id)
			writeJSONError(w, "Failed to get group", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if group == nil {
			writeJSONError(w, "Group not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Parse pagination parameters
		page := 1
		if pageStr := r.URL.Query().Get("page"); pageStr != "" {
			if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
				page = p
			}
		}

		size := 10 // Default page size matching current implementation
		if sizeStr := r.URL.Query().Get("size"); sizeStr != "" {
			if s, err := strconv.Atoi(sizeStr); err == nil && s > 0 && s <= 200 {
				size = s
			}
		}

		// Get group members with pagination
		members, total, err := database.GetGroupMembersPaginated(nil, group.Id, page, size)
		if err != nil {
			slog.Error("AuthServer API: Database error getting group members paginated", "error", err, "groupId", group.Id, "page", page, "size", size)
			writeJSONError(w, "Failed to get group members", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Convert to response format
		memberResponses := api.ToUserResponses(members)

		response := api.GetGroupMembersResponse{
			Members: memberResponses,
			Total:   total,
			Page:    page,
			Size:    size,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		httpHelper.EncodeJson(w, r, response)
	}
}

func HandleAPIGroupMemberAddPost(
	httpHelper handlers.HttpHelper,
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

		groupId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid group ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		var addReq api.AddGroupMemberRequest
		err = json.NewDecoder(r.Body).Decode(&addReq)
		if err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
			return
		}

		// Validate group exists
		group, err := database.GetGroupById(nil, groupId)
		if err != nil {
			slog.Error("AuthServer API: Database error getting group by ID for member add", "error", err, "groupId", groupId)
			writeJSONError(w, "Failed to get group", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if group == nil {
			writeJSONError(w, "Group not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Validate user exists
		user, err := database.GetUserById(nil, addReq.UserId)
		if err != nil {
			slog.Error("AuthServer API: Database error getting user by ID for group member add", "error", err, "userId", addReq.UserId, "groupId", groupId)
			writeJSONError(w, "Failed to get user", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Check if user is already in the group
		existingUserGroup, err := database.GetUserGroupByUserIdAndGroupId(nil, user.Id, group.Id)
		if err != nil {
			slog.Error("AuthServer API: Database error checking existing group membership", "error", err, "userId", user.Id, "groupId", group.Id)
			writeJSONError(w, "Failed to check existing membership", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if existingUserGroup != nil {
			writeJSONError(w, "User is already a member of this group", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Add user to group
		err = database.CreateUserGroup(nil, &models.UserGroup{
			UserId:  user.Id,
			GroupId: group.Id,
		})
		if err != nil {
			slog.Error("AuthServer API: Database error creating user group membership", "error", err, "userId", user.Id, "groupId", group.Id)
			writeJSONError(w, "Failed to add user to group", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Audit log
		auditLogger.Log(constants.AuditUserAddedToGroup, map[string]interface{}{
			"userId":       user.Id,
			"groupId":      group.Id,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		// Return success response
		response := api.SuccessResponse{
			Success: true,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		httpHelper.EncodeJson(w, r, response)
	}
}

func HandleAPIGroupMemberDelete(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		groupIdStr := chi.URLParam(r, "id")
		if groupIdStr == "" {
			writeJSONError(w, "Group ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		groupId, err := strconv.ParseInt(groupIdStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid group ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		userIdStr := chi.URLParam(r, "userId")
		if userIdStr == "" {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Validate group exists
		group, err := database.GetGroupById(nil, groupId)
		if err != nil {
			slog.Error("AuthServer API: Database error getting group by ID for member delete", "error", err, "groupId", groupId)
			writeJSONError(w, "Failed to get group", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if group == nil {
			writeJSONError(w, "Group not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Validate user exists
		user, err := database.GetUserById(nil, userId)
		if err != nil {
			slog.Error("AuthServer API: Database error getting user by ID for group member delete", "error", err, "userId", userId, "groupId", groupId)
			writeJSONError(w, "Failed to get user", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Check if user is in the group
		userGroup, err := database.GetUserGroupByUserIdAndGroupId(nil, user.Id, group.Id)
		if err != nil {
			slog.Error("AuthServer API: Database error checking group membership for delete", "error", err, "userId", user.Id, "groupId", group.Id)
			writeJSONError(w, "Failed to check group membership", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if userGroup == nil {
			writeJSONError(w, "User is not a member of this group", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Remove user from group
		err = database.DeleteUserGroup(nil, userGroup.Id)
		if err != nil {
			slog.Error("AuthServer API: Database error deleting user group membership", "error", err, "userGroupId", userGroup.Id, "userId", user.Id, "groupId", group.Id)
			writeJSONError(w, "Failed to remove user from group", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Audit log
		auditLogger.Log(constants.AuditUserRemovedFromGroup, map[string]interface{}{
			"userId":       user.Id,
			"groupId":      group.Id,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		// Return success response
		response := api.SuccessResponse{
			Success: true,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		httpHelper.EncodeJson(w, r, response)
	}
}