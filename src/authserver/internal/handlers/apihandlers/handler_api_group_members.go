package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

// groupMembersDatabase is what the group membership endpoints need: the group, its members, and
// the rows that join them, and what the administrative policy reads to judge a change.
type groupMembersDatabase interface {
	userTargetPolicyDatabase
	lastAdministratorDatabase
	CreateUserGroup(ctx context.Context, tx *sql.Tx, userGroup *record.UserGroup) error
	DeleteUserGroup(ctx context.Context, tx *sql.Tx, userGroupID int64) error
	GetGroupByID(ctx context.Context, tx *sql.Tx, groupID int64) (*record.Group, error)
	GetGroupMembersPaginated(ctx context.Context, tx *sql.Tx, groupID int64, page int, pageSize int) ([]record.User, int, error)
	GetUserByID(ctx context.Context, tx *sql.Tx, userID int64) (*record.User, error)
	GetUserGroupByUserIDAndGroupID(ctx context.Context, tx *sql.Tx, userID, groupID int64) (*record.UserGroup, error)
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
}

func HandleGroupMembersGet(
	database groupMembersDatabase,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := r.PathValue("id")
		if idStr == "" {
			writeJSONError(w, "Group ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid group ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		group, err := database.GetGroupByID(r.Context(), nil, id)
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
		members, total, err := database.GetGroupMembersPaginated(r.Context(), nil, group.ID, page, size)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting group members paginated"), "group_id", group.ID, "page", page, "size", size)
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

		idStr := r.PathValue("id")
		if idStr == "" {
			writeJSONError(w, "Group ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		groupID, err := strconv.ParseInt(idStr, 10, 64)
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
		group, err := database.GetGroupByID(r.Context(), nil, groupID)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting group by ID for member add"), "group_id", groupID)
			return
		}
		if group == nil {
			writeJSONError(w, "Group not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Validate user exists
		user, err := database.GetUserByID(r.Context(), nil, addReq.UserID)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting user by ID for group member add"), "user_id", addReq.UserID, "group_id", groupID)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Check if user is already in the group
		existingUserGroup, err := database.GetUserGroupByUserIDAndGroupID(r.Context(), nil, user.ID, group.ID)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error checking existing group membership"), "user_id", user.ID, "group_id", group.ID)
			return
		}
		if existingUserGroup != nil {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeGroupMemberAlreadyMember, nil))
			return
		}

		// The grant ceiling, after the request's 400 and 404 answers and before the write: only
		// authserver:manage moves a user into a group holding an administrative permission.
		// What it read is what the administrative_permission_changed record is written from (#402).
		administrative, allowed := membershipCeilingAllows(w, r, database, auditLogger, user.ID, []int64{group.ID})
		if !allowed {
			return
		}

		// The grant ceiling judged the group; this judges the user moved (#402 decision 1).
		if !userTargetCeilingAllows(w, r, database, auditLogger, user.ID) {
			return
		}

		// Add user to group
		err = database.CreateUserGroup(r.Context(), nil, &record.UserGroup{
			UserID:  user.ID,
			GroupID: group.ID,
		})
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error creating user group membership"), "user_id", user.ID, "group_id", group.ID)
			return
		}

		// Audit log
		auditLogger.Log(r.Context(), audit.EventUserAddedToGroup, map[string]interface{}{
			"user_id":        user.ID,
			"group_id":       group.ID,
			"logged_in_user": callerSubject(r),
		})
		recordMembershipChanges(r, auditLogger, user.ID, changeGranted, administrative)

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

		groupIDStr := r.PathValue("id")
		if groupIDStr == "" {
			writeJSONError(w, "Group ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		groupID, err := strconv.ParseInt(groupIDStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid group ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		userIDStr := r.PathValue("userId")
		if userIDStr == "" {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		userID, err := strconv.ParseInt(userIDStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Validate group exists
		group, err := database.GetGroupByID(r.Context(), nil, groupID)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting group by ID for member delete"), "group_id", groupID)
			return
		}
		if group == nil {
			writeJSONError(w, "Group not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Validate user exists
		user, err := database.GetUserByID(r.Context(), nil, userID)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting user by ID for group member delete"), "user_id", userID, "group_id", groupID)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Check if user is in the group
		userGroup, err := database.GetUserGroupByUserIDAndGroupID(r.Context(), nil, user.ID, group.ID)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error checking group membership for delete"), "user_id", user.ID, "group_id", group.ID)
			return
		}
		if userGroup == nil {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeGroupMemberNotMember, nil))
			return
		}

		// The grant ceiling, after the request's 400 and 404 answers and before the write: only
		// authserver:manage moves a user out of a group holding an administrative permission.
		// What it read is what the administrative_permission_changed record is written from (#402).
		administrative, allowed := membershipCeilingAllows(w, r, database, auditLogger, user.ID, []int64{group.ID})
		if !allowed {
			return
		}

		// The grant ceiling judged the group; this judges the user moved (#402 decision 1).
		if !userTargetCeilingAllows(w, r, database, auditLogger, user.ID) {
			return
		}

		// Remove user from group. Leaving a group that gives manage can remove the last
		// administrator, so the removal runs in a transaction that takes the administrators' lock
		// first, decides from what the group holds as read under it, and is rolled back when it
		// would leave no enabled user holding manage (#402 decisions 10 and 11).
		err = database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
			administrators, lockErr := lockAdministrators(r.Context(), database, tx)
			if lockErr != nil {
				return lockErr
			}
			givesManage, readErr := administrators.groupsGiveManage(r.Context(), []int64{group.ID})
			if readErr != nil {
				return readErr
			}
			if decideErr := administrators.decide(r.Context(), givesManage); decideErr != nil {
				return decideErr
			}
			if deleteErr := database.DeleteUserGroup(r.Context(), tx, userGroup.ID); deleteErr != nil {
				return errs.Wrap(deleteErr, "database error deleting user group membership")
			}
			return administrators.leavesAnAdministrator(r.Context())
		})
		if errors.Is(err, errLastAdministrator) {
			writeLastAdministrator(w, r)
			return
		}
		if err != nil {
			writeInternalServerError(w, r, err, "user_group_id", userGroup.ID, "user_id", user.ID, "group_id", group.ID)
			return
		}

		// Audit log
		auditLogger.Log(r.Context(), audit.EventUserRemovedFromGroup, map[string]interface{}{
			"user_id":        user.ID,
			"group_id":       group.ID,
			"logged_in_user": callerSubject(r),
		})
		recordMembershipChanges(r, auditLogger, user.ID, changeRevoked, administrative)

		// Return success response
		response := api.SuccessResponse{
			Success: true,
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}
