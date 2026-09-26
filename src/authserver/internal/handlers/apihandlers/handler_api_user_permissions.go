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

// userPermissionsDatabase is what the user permission endpoints need: the user's grants and the
// catalogue they are granted from.
type userPermissionsDatabase interface {
	CreateUserPermission(ctx context.Context, tx *sql.Tx, userPermission *models.UserPermission) error
	DeleteUserPermission(ctx context.Context, tx *sql.Tx, userPermissionId int64) error
	GetPermissionById(ctx context.Context, tx *sql.Tx, permissionId int64) (*models.Permission, error)
	GetResourceById(ctx context.Context, tx *sql.Tx, resourceId int64) (*models.Resource, error)
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*models.User, error)
	GetUserPermissionsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]models.UserPermission, error)
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
	UserLoadPermissions(ctx context.Context, tx *sql.Tx, user *models.User) error
}

func HandleAPIUserPermissionsGet(
	database userPermissionsDatabase,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		user, err := database.GetUserById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "failed to get user by ID"), "user_id", id)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		err = database.UserLoadPermissions(r.Context(), nil, user)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "failed to load user permissions"), "user_id", user.Id)
			return
		}

		// Load resource information for each permission
		for i := range user.Permissions {
			resource, err := database.GetResourceById(r.Context(), nil, user.Permissions[i].ResourceId)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "failed to load resource information"), "user_id", user.Id, "resource_id", user.Permissions[i].ResourceId)
				return
			}
			if resource != nil {
				user.Permissions[i].Resource = *resource
			}
		}

		response := api.GetUserPermissionsResponse{
			User:        *apimapping.ToUserResponse(user),
			Permissions: apimapping.ToPermissionResponses(user.Permissions),
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

func HandleAPIUserPermissionsPut(
	database userPermissionsDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		user, err := database.GetUserById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "failed to get user by ID"), "user_id", id)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		var request api.UpdateUserPermissionsRequest
		if decodeErr := json.NewDecoder(r.Body).Decode(&request); decodeErr != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// The set as the caller loaded it, required as it is on every list save: absent or null
		// decodes to nil and is refused, [] means the caller read no grants (#428).
		if request.ExpectedPermissionIds == nil {
			writeJSONError(w, "expectedPermissionIds is required: send the permission ids as you last read them, or [] if there were none.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Deduplicated as the group and client saves always were. This one was not, and a repeated
		// id stored two grant rows, of which a later revocation deleted one and left the other
		// granting the permission (#406).
		wanted := firstOccurrences(request.PermissionIds)

		// Validate that all requested permissions exist
		for _, permissionId := range wanted {
			permission, getErr := database.GetPermissionById(r.Context(), nil, permissionId)
			if getErr != nil {
				writeInternalServerError(w, r, errs.Wrap(getErr, "failed to get permission by ID during validation"), "user_id", user.Id, "permission_id", permissionId)
				return
			}
			if permission == nil {
				writeJSONError(w, "Permission not found", "NOT_FOUND", http.StatusNotFound)
				return
			}
		}

		grantKey := func(up models.UserPermission) int64 { return up.PermissionId }
		grantId := func(up models.UserPermission) int64 { return up.Id }

		// One transaction, so a failure part way through commits nothing and the 500 is true: an
		// administrator revoking one permission and granting another ends with both changes or
		// neither, where the autocommitted writes this replaced could leave the revocation undone
		// under a 500 (#406). No row lock, as for every list save: two overlapping saves of one
		// user's grants merge item by item, and user_permissions has no unique key, so a grant the
		// two both add is stored twice, which is harmless and collapsed by the next save's
		// replaceSet. Opened through RunInTransaction, so a deadlock victim is rerun whole (#301).
		// The body is safe to rerun: the plan is recomputed from the rows read on the transaction
		// on every attempt, what is audited is assigned only by an attempt that reached its end,
		// and nothing is written to the response inside it (#428).
		//
		// A permission deleted after the validation above read it fails the insert's foreign key,
		// which undoes the whole save as one 500; the second lookup the add loop made to catch it
		// went with the loop (#406).
		var granted, revoked []int64
		err = database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
			stored, loadErr := database.GetUserPermissionsByUserId(r.Context(), tx, user.Id)
			if loadErr != nil {
				return errs.Wrap(loadErr, "database error loading user permissions before update")
			}
			if !sameSet(stored, grantKey, request.ExpectedPermissionIds) {
				return errListChanged
			}

			insert, remove := replaceSet(stored, grantKey, grantId, wanted)
			for _, rowId := range remove {
				if deleteErr := database.DeleteUserPermission(r.Context(), tx, rowId); deleteErr != nil {
					return errs.Wrapf(deleteErr, "database error deleting user permission %d", rowId)
				}
			}
			for _, permissionId := range insert {
				if createErr := database.CreateUserPermission(r.Context(), tx, &models.UserPermission{
					UserId:       user.Id,
					PermissionId: permissionId,
				}); createErr != nil {
					return errs.Wrapf(createErr, "database error granting permission %d", permissionId)
				}
			}
			granted, revoked = insert, revokedKeys(stored, grantKey, wanted)
			return nil
		})
		if err != nil {
			writeListSaveFailure(w, r, err, "user_id", user.Id)
			return
		}

		// Audit, once the save has committed: one event per grant made and per grant withdrawn,
		// from the plan of the attempt that committed (#428).
		for _, permissionId := range granted {
			auditLogger.Log(r.Context(), audit.AuditAddedUserPermission, map[string]interface{}{
				"userId":       user.Id,
				"permissionId": permissionId,
				"loggedInUser": callerSubject(r),
			})
		}
		for _, permissionId := range revoked {
			auditLogger.Log(r.Context(), audit.AuditDeletedUserPermission, map[string]interface{}{
				"userId":       user.Id,
				"permissionId": permissionId,
				"loggedInUser": callerSubject(r),
			})
		}

		// Return success response
		response := api.SuccessResponse{Success: true}
		writeJSON(w, r, http.StatusOK, response)
	}
}
