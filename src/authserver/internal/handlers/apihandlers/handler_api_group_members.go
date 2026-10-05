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
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// groupMembersDatabase is what the group membership endpoints need: the group, its members, and
// the rows that join them, and what the administrative policy reads to judge a change.
type groupMembersDatabase interface {
	userTargetPolicyDatabase
	CreateUserGroup(ctx context.Context, tx *sql.Tx, userGroup *record.UserGroup) error
	DeleteUserGroup(ctx context.Context, tx *sql.Tx, userGroupId int64) error
	GetGroupById(ctx context.Context, tx *sql.Tx, groupId int64) (*record.Group, error)
	GetGroupMembersPaginated(ctx context.Context, tx *sql.Tx, groupId int64, page int, pageSize int) ([]record.User, int, error)
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error)
	GetUserGroupByUserIdAndGroupId(ctx context.Context, tx *sql.Tx, userId, groupId int64) (*record.UserGroup, error)
}

func HandleGroupMembersGet(
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
			if p, parseErr := strconv.Atoi(pageStr); parseErr == nil && p > 0 {
				page = p
			}
		}

		size := 10 // Default page size matching current implementation
		if sizeStr := r.URL.Query().Get("size"); sizeStr != "" {
			if s, parseErr := strconv.Atoi(sizeStr); parseErr == nil && s > 0 && s <= 200 {
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

func HandleGroupMemberAddPost(
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

		// The grant ceiling, after the request's 400 and 404 answers and before the write: only
		// authserver:manage moves a user into a group holding an administrative permission.
		// What it read is what the administrative_permission_changed record is written from (#402).
		administrative, allowed := membershipCeilingAllows(w, r, database, auditLogger, user.Id, []int64{group.Id})
		if !allowed {
			return
		}

		// The grant ceiling judged the group; this judges the user moved (#402 decision 1).
		if !userTargetCeilingAllows(w, r, database, auditLogger, user.Id) {
			return
		}

		// Add user to group
		err = database.CreateUserGroup(r.Context(), nil, &record.UserGroup{
			UserId:  user.Id,
			GroupId: group.Id,
		})
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error creating user group membership"), "user_id", user.Id, "group_id", group.Id)
			return
		}

		// Audit log
		auditLogger.Log(r.Context(), audit.EventUserAddedToGroup, map[string]interface{}{
			"userId":       user.Id,
			"groupId":      group.Id,
			"loggedInUser": callerSubject(r),
		})
		recordMembershipChanges(r, auditLogger, user.Id, changeGranted, administrative)

		// Return success response
		response := api.SuccessResponse{
			Success: true,
		}

		writeJSON(w, r, http.StatusCreated, response)
	}
}

func HandleGroupMemberDelete(
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

		// The grant ceiling, after the request's 400 and 404 answers and before the write: only
		// authserver:manage moves a user out of a group holding an administrative permission.
		// What it read is what the administrative_permission_changed record is written from (#402).
		administrative, allowed := membershipCeilingAllows(w, r, database, auditLogger, user.Id, []int64{group.Id})
		if !allowed {
			return
		}

		// The grant ceiling judged the group; this judges the user moved (#402 decision 1).
		if !userTargetCeilingAllows(w, r, database, auditLogger, user.Id) {
			return
		}

		// Remove user from group
		err = database.DeleteUserGroup(r.Context(), nil, userGroup.Id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error deleting user group membership"), "user_group_id", userGroup.Id, "user_id", user.Id, "group_id", group.Id)
			return
		}

		// Audit log
		auditLogger.Log(r.Context(), audit.EventUserRemovedFromGroup, map[string]interface{}{
			"userId":       user.Id,
			"groupId":      group.Id,
			"loggedInUser": callerSubject(r),
		})
		recordMembershipChanges(r, auditLogger, user.Id, changeRevoked, administrative)

		// Return success response
		response := api.SuccessResponse{
			Success: true,
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}
