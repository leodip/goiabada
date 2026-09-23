package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// groupMembersDatabase is what the group membership endpoints need: the group, its members, and
// the rows that join them.
type groupMembersDatabase interface {
	CreateUserGroup(ctx context.Context, tx *sql.Tx, userGroup *models.UserGroup) error
	DeleteUserGroup(ctx context.Context, tx *sql.Tx, userGroupId int64) error
	GetGroupById(ctx context.Context, tx *sql.Tx, groupId int64) (*models.Group, error)
	GetGroupMembersPaginated(ctx context.Context, tx *sql.Tx, groupId int64, page int, pageSize int) ([]models.User, int, error)
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*models.User, error)
	GetUserGroupByUserIdAndGroupId(ctx context.Context, tx *sql.Tx, userId, groupId int64) (*models.UserGroup, error)
}

func HandleAPIGroupMembersGet(
	database groupMembersDatabase,
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
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting group by ID for members"), "group_id", id)
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
		members, total, err := database.GetGroupMembersPaginated(r.Context(), nil, group.Id, page, size)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting group members paginated"), "group_id", group.Id, "page", page, "size", size)
			return
		}

		// Convert to response format
		memberResponses := apimapping.ToUserResponses(members)

		response := api.GetGroupMembersResponse{
			Members: memberResponses,
			Total:   total,
			Page:    page,
			Size:    size,
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

func HandleAPIGroupMemberAddPost(
	database groupMembersDatabase,
	auditLogger AuditLogger,
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
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Validate group exists
		group, err := database.GetGroupById(r.Context(), nil, groupId)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting group by ID for member add"), "group_id", groupId)
			return
		}
		if group == nil {
			writeJSONError(w, "Group not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Validate user exists
		user, err := database.GetUserById(r.Context(), nil, addReq.UserId)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting user by ID for group member add"), "user_id", addReq.UserId, "group_id", groupId)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Check if user is already in the group
		existingUserGroup, err := database.GetUserGroupByUserIdAndGroupId(r.Context(), nil, user.Id, group.Id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error checking existing group membership"), "user_id", user.Id, "group_id", group.Id)
			return
		}
		if existingUserGroup != nil {
			writeJSONError(w, "User is already a member of this group", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Add user to group
		err = database.CreateUserGroup(r.Context(), nil, &models.UserGroup{
			UserId:  user.Id,
			GroupId: group.Id,
		})
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error creating user group membership"), "user_id", user.Id, "group_id", group.Id)
			return
		}

		// Audit log
		auditLogger.Log(r.Context(), audit.AuditUserAddedToGroup, map[string]interface{}{
			"userId":       user.Id,
			"groupId":      group.Id,
			"loggedInUser": callerSubject(r),
		})

		// Return success response
		response := api.SuccessResponse{
			Success: true,
		}

		writeJSON(w, r, http.StatusCreated, response)
	}
}

func HandleAPIGroupMemberDelete(
	database groupMembersDatabase,
	auditLogger AuditLogger,
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
		group, err := database.GetGroupById(r.Context(), nil, groupId)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting group by ID for member delete"), "group_id", groupId)
			return
		}
		if group == nil {
			writeJSONError(w, "Group not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Validate user exists
		user, err := database.GetUserById(r.Context(), nil, userId)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting user by ID for group member delete"), "user_id", userId, "group_id", groupId)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Check if user is in the group
		userGroup, err := database.GetUserGroupByUserIdAndGroupId(r.Context(), nil, user.Id, group.Id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error checking group membership for delete"), "user_id", user.Id, "group_id", group.Id)
			return
		}
		if userGroup == nil {
			writeJSONError(w, "User is not a member of this group", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Remove user from group
		err = database.DeleteUserGroup(r.Context(), nil, userGroup.Id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error deleting user group membership"), "user_group_id", userGroup.Id, "user_id", user.Id, "group_id", group.Id)
			return
		}

		// Audit log
		auditLogger.Log(r.Context(), audit.AuditUserRemovedFromGroup, map[string]interface{}{
			"userId":       user.Id,
			"groupId":      group.Id,
			"loggedInUser": callerSubject(r),
		})

		// Return success response
		response := api.SuccessResponse{
			Success: true,
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}
